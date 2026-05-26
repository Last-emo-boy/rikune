/**
 * YARA-X scan tool �?scan a sample with YARA-X rules.
 */

import { createHash } from 'crypto'
import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from '../../docker-shared.js'
import {
  fs,
  ArtifactRefSchema,
  BackendSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  normalizeError,
  runPythonJson,
  persistBackendArtifact,
  buildMetrics,
  buildStaticSetupRequired,
  findBackendPreviewEvidence,
  persistBackendPreviewEvidence,
  buildEvidenceReuseWarnings,
  resolveSampleFile,
  resolveAnalysisBackends,
} from '../../docker-shared.js'

const TOOL_NAME = 'yara_x.scan'
const TOOL_VERSION = '0.1.0'
const YARAX_SCAN_ARTIFACT_TYPE = 'backend_yara_x_scan'

export const yaraXScanInputSchema = z
  .object({
    sample_id: z.string().describe('Target sample identifier.'),
    rules_text: z.string().optional().describe('Inline YARA-X source text.'),
    rules_path: z.string().optional().describe('Absolute path to a YARA or YARA-X rules file.'),
    timeout_sec: z
      .number()
      .int()
      .min(1)
      .max(180)
      .default(30)
      .describe('YARA-X scan timeout in seconds.'),
    max_matches_per_pattern: z
      .number()
      .int()
      .min(1)
      .max(5000)
      .default(250)
      .describe('Maximum matches per pattern for the scanner.'),
    persist_artifact: z
      .boolean()
      .default(true)
      .describe('Persist the JSON scan result as an artifact.'),
    session_tag: z.string().optional().describe('Optional artifact session tag.'),
  })
  .superRefine((data, ctx) => {
    if (!data.rules_text && !data.rules_path) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['rules_text'],
        message: 'Either rules_text or rules_path must be provided',
      })
    }
  })

export type YaraXScanInput = z.infer<typeof yaraXScanInputSchema>
type YaraXBackend = z.infer<typeof BackendSchema>
type YaraXPattern = {
  identifier?: string
  matches?: unknown[]
  [key: string]: unknown
}
type YaraXMatchingRule = {
  identifier?: string
  namespace?: string
  patterns?: YaraXPattern[]
  [key: string]: unknown
}

export const yaraXScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      rules_digest: z.string().nullable().optional(),
      rules_source: z.enum(['inline', 'file', 'unknown']).optional(),
      timeout_sec: z.number().int().optional(),
      max_matches_per_pattern: z.number().int().optional(),
      match_count: z.number().int().nonnegative().optional(),
      matches: z.array(z.any()).optional(),
      matching_rules: z.array(z.any()).optional(),
      module_outputs: z.record(z.any()).optional(),
      pattern_match_count: z.number().int().nonnegative().optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const yaraXScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Scan a sample with YARA-X using inline rules or a rules file. Use this when you explicitly want the newer YARA-X engine instead of the legacy yara.scan path.',
  inputSchema: yaraXScanInputSchema,
  outputSchema: yaraXScanOutputSchema,
  aspects: {
    formats: [
      'pe',
      'elf',
      'macho',
      'apk',
      'dex',
      'jar',
      'dotnet',
      'wasm',
      'firmware',
      'archive',
      'container',
    ],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'signatures',
      'pattern-matching',
      'rule-matching',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: ['signatures', 'strings', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: YARAX_SCAN_ARTIFACT_TYPE,
      description:
        'YARA-X rule match payload with evidence summary, workflow handoff, and quality gates',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'signatures',
      artifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'strings',
      artifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'yara-x.scan-validation-handoff',
      title: 'YARA-X scan to evidence validation and reporting',
      description:
        'Run passive YARA-X rule matching with bounded previews, quality gates, evidence graph routing, legacy YARA comparison, and reporting handoff.',
      startsWith: ['yara_x.scan', 'yara.generate', 'sigma.rule.generate'],
      nextTools: ['artifact.read', 'yara.scan', 'analysis.evidence.graph', 'report.generate'],
      requiredArtifacts: ['sample', 'YARA-X rules'],
      producesArtifacts: [YARAX_SCAN_ARTIFACT_TYPE],
      evidence: ['signatures', 'strings', 'workflow', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

const YARAX_SCAN_SCRIPT = `
import json
import pathlib
import sys
import yara_x

payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
rules_text = payload.get("rules_text")
rules_path = payload.get("rules_path")
max_matches = int(payload.get("max_matches_per_pattern", 250))
timeout_sec = int(payload.get("timeout_sec", 30))

if not rules_text and rules_path:
    rules_text = pathlib.Path(rules_path).read_text(encoding="utf-8")

rules = yara_x.compile(rules_text)
scanner = yara_x.Scanner(rules)
scanner.set_timeout(timeout_sec)
scanner.max_matches_per_pattern(max_matches)

data = pathlib.Path(sample_path).read_bytes()
results = scanner.scan(data)

matching_rules = []
for rule in getattr(results, "matching_rules", []):
    patterns = []
    for pattern in getattr(rule, "patterns", []):
        matches = []
        for match in getattr(pattern, "matches", []):
            matches.append({
                "offset": int(getattr(match, "offset", 0)),
                "length": int(getattr(match, "length", 0)),
            })
        patterns.append({
            "identifier": getattr(pattern, "identifier", ""),
            "matches": matches,
        })
    matching_rules.append({
        "identifier": getattr(rule, "identifier", ""),
        "namespace": getattr(rule, "namespace", ""),
        "patterns": patterns,
    })

print(json.dumps({
    "match_count": len(matching_rules),
    "matching_rules": matching_rules,
    "module_outputs": getattr(results, "module_outputs", {}) or {},
}, ensure_ascii=False))
`.trim()

function rulesSource(input: YaraXScanInput): 'inline' | 'file' | 'unknown' {
  if (input.rules_text) return 'inline'
  if (input.rules_path) return 'file'
  return 'unknown'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function normalizeMatchingRules(value: unknown): YaraXMatchingRule[] {
  if (!Array.isArray(value)) return []
  return value.filter(isRecord).map((rule) => ({
    ...rule,
    patterns: Array.isArray(rule.patterns) ? rule.patterns.filter(isRecord) : [],
  })) as YaraXMatchingRule[]
}

function readNonNegativeInteger(value: unknown, fallback: number): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.trunc(value))
  }
  return fallback
}

function countPatternMatches(matchingRules: YaraXMatchingRule[]): number {
  return matchingRules.reduce(
    (ruleTotal, rule) =>
      ruleTotal +
      (rule.patterns || []).reduce(
        (patternTotal, pattern) =>
          patternTotal + (Array.isArray(pattern.matches) ? pattern.matches.length : 0),
        0
      ),
    0
  )
}

function buildRecommendedNextTools(): string[] {
  return ['artifact.read', 'yara.scan', 'analysis.evidence.graph', 'report.generate']
}

function buildEvidenceSummary(args: {
  input: YaraXScanInput
  sampleId: string
  rulesDigest: string | null
  matchingRules: YaraXMatchingRule[]
  moduleOutputs: Record<string, unknown>
  patternMatchCount: number
}) {
  return {
    schema: 'rikune.yara_x_scan.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: YARAX_SCAN_ARTIFACT_TYPE,
    rules_source: rulesSource(args.input),
    rules_digest: args.rulesDigest,
    timeout_sec: args.input.timeout_sec,
    max_matches_per_pattern: args.input.max_matches_per_pattern,
    match_count: args.matchingRules.length,
    pattern_match_count: args.patternMatchCount,
    matching_rule_identifiers: args.matchingRules
      .map((rule) => rule.identifier || rule.namespace)
      .filter(Boolean)
      .slice(0, 24),
    module_output_keys: Object.keys(args.moduleOutputs).slice(0, 24),
  }
}

function buildQualityGates(args: {
  input: YaraXScanInput
  rulesDigest: string | null
  matchingRules: YaraXMatchingRule[]
  patternMatchCount: number
}) {
  return {
    schema: 'rikune.yara_x_scan.quality_gates.v1',
    passive_scan_only: true,
    backend_started: true,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    live_sample_mutation_performed: false,
    rules_provided: Boolean(args.input.rules_text || args.input.rules_path),
    rules_digest_available: Boolean(args.rulesDigest),
    match_floor_met: args.matchingRules.length > 0,
    pattern_match_floor_met: args.patternMatchCount > 0,
    artifact_review_required: args.input.persist_artifact,
    legacy_yara_comparison_recommended: true,
    bounded_match_preview_returned: true,
  }
}

function buildWorkflowHandoff(args: {
  input: YaraXScanInput
  sampleId: string
  rulesDigest: string | null
  matchingRules: YaraXMatchingRule[]
  patternMatchCount: number
  recommendedNextTools: string[]
}) {
  const matchCount = args.matchingRules.length
  return {
    schema: 'rikune.yara_x_scan.workflow_handoff.v1',
    handoff_mode: 'yara_x_scan_to_rule_validation_and_reporting',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: YARAX_SCAN_ARTIFACT_TYPE,
    rules_source: rulesSource(args.input),
    rules_digest: args.rulesDigest,
    match_count: matchCount,
    pattern_match_count: args.patternMatchCount,
    recommended_next_tools: args.recommendedNextTools,
    dynamic_boundary: {
      passive_scan_only: true,
      backend_started: true,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      live_sample_mutation_performed: false,
    },
    routing: [
      {
        goal: 'artifact-review-and-offset-validation',
        priority: matchCount > 0 ? 'high' : 'normal',
        next_tools: ['artifact.read'],
        required_evidence: [YARAX_SCAN_ARTIFACT_TYPE, 'YARA-X rule match offsets'],
      },
      {
        goal: 'legacy-yara-comparison',
        priority: 'normal',
        next_tools: ['yara.scan'],
        required_evidence: [YARAX_SCAN_ARTIFACT_TYPE, 'legacy YARA compatibility rules'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: matchCount > 0 ? 'high' : 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [YARAX_SCAN_ARTIFACT_TYPE],
      },
    ],
  }
}

function buildNextActions(args: {
  input: YaraXScanInput
  matchingRules: YaraXMatchingRule[]
  patternMatchCount: number
}) {
  const actions = [
    'Use artifact.read for the full YARA-X scan payload when you need all pattern offsets.',
    'Compare with yara.scan to catch legacy engine compatibility gaps before publishing detections.',
    'Route the artifact into analysis.evidence.graph before report.generate for correlated reporting.',
  ]
  if (args.matchingRules.length === 0) {
    actions.unshift(
      'Review rule coverage or broaden candidate strings before treating the sample as unmatched.'
    )
  }
  if (args.patternMatchCount >= args.input.max_matches_per_pattern) {
    actions.unshift(
      'Review bounded pattern output because max_matches_per_pattern may have truncated offsets.'
    )
  }
  return actions
}

function buildStructuredResult(args: {
  input: YaraXScanInput
  backend: YaraXBackend
  sampleId: string
  rulesDigest: string | null
  matchingRules: YaraXMatchingRule[]
  matchCount: number
  moduleOutputs: Record<string, unknown>
}) {
  const patternMatchCount = countPatternMatches(args.matchingRules)
  const recommendedNextTools = buildRecommendedNextTools()
  const evidenceSummary = buildEvidenceSummary({
    input: args.input,
    sampleId: args.sampleId,
    rulesDigest: args.rulesDigest,
    matchingRules: args.matchingRules,
    moduleOutputs: args.moduleOutputs,
    patternMatchCount,
  })
  const workflowHandoff = buildWorkflowHandoff({
    input: args.input,
    sampleId: args.sampleId,
    rulesDigest: args.rulesDigest,
    matchingRules: args.matchingRules,
    patternMatchCount,
    recommendedNextTools,
  })
  const qualityGates = buildQualityGates({
    input: args.input,
    rulesDigest: args.rulesDigest,
    matchingRules: args.matchingRules,
    patternMatchCount,
  })

  return {
    status: 'ready',
    backend: args.backend,
    schema: 'rikune.yara_x_scan.v1',
    tool_version: TOOL_VERSION,
    sample_id: args.sampleId,
    rules_digest: args.rulesDigest,
    rules_source: rulesSource(args.input),
    timeout_sec: args.input.timeout_sec,
    max_matches_per_pattern: args.input.max_matches_per_pattern,
    match_count: args.matchCount,
    matches: args.matchingRules.slice(0, 25),
    matching_rules: args.matchingRules,
    module_outputs: args.moduleOutputs,
    pattern_match_count: patternMatchCount,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
    summary: `YARA-X scanned ${args.sampleId} and produced ${args.matchingRules.length} matching rule(s) with ${patternMatchCount} pattern match(es).`,
    recommended_next_tools: recommendedNextTools,
    next_actions: buildNextActions({
      input: args.input,
      matchingRules: args.matchingRules,
      patternMatchCount,
    }),
  }
}

export function createYaraXScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = yaraXScanInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      let rulesDigest: string | null = null
      if (input.rules_text) {
        rulesDigest = createHash('sha256').update(input.rules_text).digest('hex')
      } else if (input.rules_path) {
        try {
          const rulesContent = await fs.readFile(input.rules_path, 'utf8')
          rulesDigest = createHash('sha256').update(rulesContent).digest('hex')
        } catch {
          rulesDigest = createHash('sha256').update(input.rules_path).digest('hex')
        }
      }
      const evidenceArgs = {
        rules_digest: rulesDigest,
        max_matches_per_pattern: input.max_matches_per_pattern,
      }
      const reused = findBackendPreviewEvidence(database, sample, 'yara_x', 'scan', evidenceArgs)
      if (reused) {
        return {
          ok: true,
          data: reused.result as Record<string, unknown>,
          warnings: buildEvidenceReuseWarnings({
            source: 'analysis_evidence',
            record: reused,
          }),
          artifacts: reused.artifact_refs,
          metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.yara_x
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, yaraXScanToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(
        backend.path,
        YARAX_SCAN_SCRIPT,
        {
          sample_path: samplePath,
          rules_text: input.rules_text,
          rules_path: input.rules_path,
          max_matches_per_pattern: input.max_matches_per_pattern,
          timeout_sec: input.timeout_sec,
        },
        input.timeout_sec * 1000 + 5000
      )

      const matchingRules = normalizeMatchingRules(result.parsed?.matching_rules)
      const moduleOutputs = isRecord(result.parsed?.module_outputs)
        ? result.parsed.module_outputs
        : {}
      const matchCount = readNonNegativeInteger(result.parsed?.match_count, matchingRules.length)
      let outputData: Record<string, unknown> = buildStructuredResult({
        input,
        backend,
        sampleId: input.sample_id,
        rulesDigest,
        matchingRules,
        matchCount,
        moduleOutputs,
      }) satisfies Record<string, unknown>

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'yara_x',
          'scan',
          JSON.stringify(outputData, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
            metadata: {
              schema: 'rikune.yara_x_scan.v1',
              rules_digest: rulesDigest,
            },
          }
        )
        artifacts.push(artifact)
        outputData = { ...outputData, artifact }
      }

      persistBackendPreviewEvidence(
        database,
        sample,
        'yara_x',
        'scan',
        evidenceArgs,
        outputData,
        artifacts,
        {
          backend_version: backend.version,
          rules_path: input.rules_path || null,
        }
      )

      return {
        ok: true,
        data: outputData,
        artifacts,
        metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
      }
    }
  }
}
