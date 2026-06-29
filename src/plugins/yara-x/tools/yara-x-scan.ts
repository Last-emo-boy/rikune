/**
 * YARA-X scan tool - scan a sample with YARA-X rules.
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
const YARAX_BACKEND_NAME = 'YARA-X Python scanner backend'
const YARAX_SEARCH_TERMS = [
  'yara-x',
  'yara',
  'ruleset',
  'provenance',
  'corroboration',
  'rule-validation',
  'engine-comparison',
  'legacy-yara-comparison',
]
const YARAX_SCAN_SAFETY = [
  'passive',
  'external_static_backend',
  'no_live_sample_by_default',
  'no_live_execution',
  'no_network_by_default',
  'no_mutation',
]
const YARAX_SCAN_CAPABILITIES = [
  'signatures',
  'pattern-matching',
  'rule-matching',
  'ruleset-provenance',
  'default-rules-semantics',
  'rule-validation',
  'engine-comparison',
  'legacy-yara-comparison',
  'yara-x-corroboration',
  'workflow-handoff',
  'evidence-correlation',
]
const YARAX_SCAN_EVIDENCE = [
  'signatures',
  'strings',
  'ruleset',
  'rule-validation',
  'engine-comparison',
  'corroboration',
  'workflow',
  'provenance',
]
const YARAX_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  maxRuntimeMs: 185_000,
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'YARA-X scanning is a passive local byte scan through the configured Python yara_x backend.',
    'The tool never downloads default rules, mutates samples, or executes live sample code.',
    'Legacy yara.scan comparison is recommended as a passive corroboration step before publishing detections.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}
const YARAX_WORKER_BACKEND = {
  version: 'backend-worker.v1',
  backendName: YARAX_BACKEND_NAME,
  backendKind: 'external',
  adapter: 'python.yara_x.scan',
  availability: 'optional',
  envVar: 'YARAX_PYTHON',
  commandHint: 'python3',
  versionHint: "python -c \"import yara_x; print(getattr(yara_x, '__version__', 'unknown'))\"",
  supportedModes: ['external-python'],
  defaultMode: 'external-python',
  inputArtifactTypes: ['sample', 'yara_x_rules', 'yara_rules', 'ruleset'],
  outputArtifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
  policy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    maxInputBytes: 256 * 1024 * 1024,
    maxOutputBytes: 16 * 1024 * 1024,
    defaultTimeoutMs: 30_000,
    notes: [
      'The backend reads local sample bytes and caller-provided rules only.',
      'No implicit default ruleset, network rules update, live execution, or mutation is performed.',
      'Use yara.scan separately for legacy engine comparison and corroboration.',
    ],
  },
  readiness: {
    doesNotStartBackend: true,
    setupActions: [
      'Install the Python yara-x package in the configured YARAX_PYTHON environment.',
      'Provide rules_text or rules_path; yara_x.scan does not fetch or apply implicit default rules.',
      'Run yara.scan separately when legacy YARA engine comparison is required.',
    ],
    missingBackendBehavior:
      'Return setup_required with passive setup actions; do not fall back to live execution, network rules retrieval, or sample mutation.',
    defaultRules: 'none; callers must provide inline rules or a local rules file',
    comparisonBackend: 'legacy yara.scan',
  },
  packaging: {
    installRoute: 'profile-gated',
    installProfile: 'optional',
    dockerFeature: 'dynamic-python',
    envVar: 'YARAX_PYTHON',
    dockerDefault: 'python3',
    notes: [
      'The yara-x Python backend is optional and profile-gated.',
      'Default rules are intentionally absent; ruleset provenance comes from rules_text or rules_path.',
    ],
  },
} satisfies NonNullable<ToolDefinition['workerBackend']>

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
      module_outputs: z.record(z.string(), z.any()).optional(),
      pattern_match_count: z.number().int().nonnegative().optional(),
      backend_semantics: z.record(z.string(), z.any()).optional(),
      ruleset_provenance: z.record(z.string(), z.any()).optional(),
      validation_semantics: z.record(z.string(), z.any()).optional(),
      corroboration_plan: z.record(z.string(), z.any()).optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
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
    'Passively scan a sample with the Python YARA-X backend using analyst-provided inline rules or a local rules file. Use this for YARA-X rule validation, ruleset provenance, corroboration, and legacy yara.scan engine comparison handoff.',
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
    safety: YARAX_SCAN_SAFETY,
    capabilities: YARAX_SCAN_CAPABILITIES,
    evidence: YARAX_SCAN_EVIDENCE,
    rulesets: ['yara-x', 'yara', 'ruleset', 'default-rules', 'inline-rules', 'file-rules'],
    provenance: ['ruleset-provenance', 'rules-digest', 'artifact-provenance'],
    comparison: ['yara-x-corroboration', 'legacy-yara-comparison', 'engine-comparison'],
    search: YARAX_SEARCH_TERMS,
  },
  artifacts: [
    {
      type: YARAX_SCAN_ARTIFACT_TYPE,
      description:
        'YARA-X backend rule match payload with ruleset provenance, default-rule semantics, rule validation evidence, engine comparison handoff, corroboration plan, and quality gates',
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
      category: 'ruleset',
      artifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
      description:
        'Inline or local-file YARA-X/YARA ruleset provenance; no implicit default rules are applied',
    },
    {
      category: 'rule-validation',
      artifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
      description: 'YARA-X compile and scan validation semantics for supplied rules',
    },
    {
      category: 'engine-comparison',
      artifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
      description: 'Legacy yara.scan comparison handoff for passive engine corroboration',
    },
    {
      category: 'corroboration',
      artifactTypes: [YARAX_SCAN_ARTIFACT_TYPE],
      description: 'YARA-X primary evidence with recommended legacy YARA corroboration',
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
        'Run passive YARA-X backend rule matching with explicit ruleset provenance, no implicit default rules, bounded previews, quality gates, evidence graph routing, legacy YARA engine comparison, corroboration, and reporting handoff.',
      startsWith: ['yara_x.scan', 'yara.generate', 'yara.scan', 'sigma.rule.generate'],
      nextTools: [
        'artifact.read',
        'yara.scan',
        'yara.generate',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['sample', 'YARA-X compatible rules', 'ruleset provenance'],
      producesArtifacts: [YARAX_SCAN_ARTIFACT_TYPE],
      evidence: YARAX_SCAN_EVIDENCE,
      safety: YARAX_SCAN_SAFETY,
      runtimeBackends: ['python-yara-x', 'yara_x', 'legacy-yara-comparison'],
      backend: {
        engine: 'YARA-X',
        pythonImport: 'yara_x',
        envVar: 'YARAX_PYTHON',
        defaultRules: 'none; rules_text or rules_path must provide the ruleset',
      },
      ruleValidation: {
        compile: 'yara_x.compile',
        scanner: 'yara_x.Scanner',
        boundedPatternOffsets: true,
        provenanceRequired: true,
      },
      engineComparison: {
        primary: TOOL_NAME,
        comparison: 'yara.scan',
        purpose: 'passive legacy YARA corroboration before publishing detection claims',
      },
      searchTags: YARAX_SEARCH_TERMS,
    },
  ],
  runtimePolicy: YARAX_RUNTIME_POLICY,
  workerBackend: YARAX_WORKER_BACKEND,
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
  return [
    'artifact.read',
    'yara.scan',
    'yara.generate',
    'analysis.evidence.graph',
    'report.generate',
  ]
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : []
}

function nullableString(value: unknown): string | null {
  if (typeof value === 'string') return value
  return null
}

function mergeStringArrays(...values: string[][]): string[] {
  return Array.from(new Set(values.flat().filter((value) => value.trim().length > 0)))
}

function buildDefaultRulesSemantics() {
  return {
    applied: false,
    source: 'none',
    policy:
      'No implicit default rules are applied; callers must provide rules_text or a local rules_path.',
    network_rule_fetch_performed: false,
  }
}

function buildRulesetProvenance(input: YaraXScanInput, rulesDigest: string | null) {
  return {
    schema: 'rikune.yara_x_scan.ruleset_provenance.v1',
    rules_source: rulesSource(input),
    rules_digest: rulesDigest,
    digest_algorithm: rulesDigest ? 'sha256' : null,
    inline_rules_present: Boolean(input.rules_text),
    rules_path_present: Boolean(input.rules_path),
    rules_path_recorded: input.rules_path || null,
    default_rules: buildDefaultRulesSemantics(),
    provenance_terms: ['ruleset', 'provenance', 'yara-x', 'yara'],
  }
}

function buildBackendSemantics(backend: YaraXBackend) {
  return {
    schema: 'rikune.yara_x_scan.backend_semantics.v1',
    backend_name: YARAX_BACKEND_NAME,
    backend_engine: 'YARA-X',
    backend_kind: 'external_python',
    adapter: 'python.yara_x.scan',
    python_import: 'yara_x',
    env_var: 'YARAX_PYTHON',
    backend_available: backend.available,
    backend_source: backend.source,
    backend_version: backend.version,
    passive_static_backend: true,
    no_network: true,
    no_mutation: true,
    no_live_execution: true,
    default_rules: buildDefaultRulesSemantics(),
  }
}

function buildValidationSemantics(args: {
  input: YaraXScanInput
  rulesDigest: string | null
  patternMatchCount: number
}) {
  return {
    schema: 'rikune.yara_x_scan.validation_semantics.v1',
    rule_engine: 'YARA-X',
    compile_backend: 'yara_x.compile',
    scan_backend: 'yara_x.Scanner',
    ruleset_source: rulesSource(args.input),
    rules_digest: args.rulesDigest,
    default_rules_applied: false,
    bounded_pattern_offsets: true,
    max_matches_per_pattern: args.input.max_matches_per_pattern,
    timeout_sec: args.input.timeout_sec,
    pattern_match_count: args.patternMatchCount,
    rule_validation_performed_by_backend: true,
    legacy_yara_comparison_recommended: true,
    search_terms: YARAX_SEARCH_TERMS,
  }
}

function buildCorroborationPlan(args: {
  matchingRules: YaraXMatchingRule[]
  patternMatchCount: number
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.yara_x_scan.corroboration_plan.v1',
    primary_tool: TOOL_NAME,
    primary_engine: 'YARA-X',
    comparison_tool: 'yara.scan',
    comparison_engine: 'legacy YARA',
    comparison_status: 'recommended_not_automatically_run',
    yara_x_corroboration_available: args.matchingRules.length > 0 || args.patternMatchCount > 0,
    legacy_yara_comparison_recommended: true,
    recommended_next_tools: args.recommendedNextTools,
    matched_rule_identifiers: args.matchingRules
      .map((rule) => rule.identifier || rule.namespace)
      .filter(Boolean)
      .slice(0, 24),
    purpose:
      'Compare the same ruleset with legacy yara.scan and review artifact offsets before publishing detection claims.',
  }
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
    backend_engine: 'YARA-X',
    backend_import: 'yara_x',
    rules_source: rulesSource(args.input),
    rules_digest: args.rulesDigest,
    ruleset_provenance: buildRulesetProvenance(args.input, args.rulesDigest),
    default_rules: buildDefaultRulesSemantics(),
    timeout_sec: args.input.timeout_sec,
    max_matches_per_pattern: args.input.max_matches_per_pattern,
    match_count: args.matchingRules.length,
    pattern_match_count: args.patternMatchCount,
    rule_validation: {
      engine: 'YARA-X',
      compile_backend: 'yara_x.compile',
      scanner_backend: 'yara_x.Scanner',
      bounded_pattern_offsets: true,
    },
    corroboration: {
      primary_tool: TOOL_NAME,
      primary_engine: 'YARA-X',
      comparison_tool: 'yara.scan',
      comparison_engine: 'legacy YARA',
      legacy_yara_comparison_recommended: true,
    },
    matching_rule_identifiers: args.matchingRules
      .map((rule) => rule.identifier || rule.namespace)
      .filter(Boolean)
      .slice(0, 24),
    module_output_keys: Object.keys(args.moduleOutputs).slice(0, 24),
    evidence_sources: ['local sample bytes', 'caller-provided ruleset', 'YARA-X backend scan'],
    search_terms: YARAX_SEARCH_TERMS,
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
    passive_static_backend: true,
    backend_started: true,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    no_network: true,
    no_mutation: true,
    no_live_execution: true,
    live_sample_mutation_performed: false,
    rules_provided: Boolean(args.input.rules_text || args.input.rules_path),
    rules_digest_available: Boolean(args.rulesDigest),
    ruleset_provenance_recorded: Boolean(args.rulesDigest),
    default_rules_applied: false,
    no_implicit_default_rules: true,
    rule_validation_performed_by_yara_x: true,
    match_floor_met: args.matchingRules.length > 0,
    pattern_match_floor_met: args.patternMatchCount > 0,
    artifact_review_required: args.input.persist_artifact,
    yara_x_corroboration_ready: args.matchingRules.length > 0 || args.patternMatchCount > 0,
    legacy_yara_comparison_recommended: true,
    engine_comparison_required_before_publication: true,
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
    backend_semantics: {
      backend_engine: 'YARA-X',
      backend_adapter: 'python.yara_x.scan',
      backend_import: 'yara_x',
      backend_env_var: 'YARAX_PYTHON',
    },
    rules_source: rulesSource(args.input),
    rules_digest: args.rulesDigest,
    ruleset_provenance: buildRulesetProvenance(args.input, args.rulesDigest),
    default_rules: buildDefaultRulesSemantics(),
    match_count: matchCount,
    pattern_match_count: args.patternMatchCount,
    recommended_next_tools: args.recommendedNextTools,
    validation_semantics: buildValidationSemantics({
      input: args.input,
      rulesDigest: args.rulesDigest,
      patternMatchCount: args.patternMatchCount,
    }),
    corroboration: buildCorroborationPlan({
      matchingRules: args.matchingRules,
      patternMatchCount: args.patternMatchCount,
      recommendedNextTools: args.recommendedNextTools,
    }),
    dynamic_boundary: {
      passive_scan_only: true,
      backend_started: true,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      network_policy: 'disabled',
      no_network: true,
      no_mutation: true,
      no_live_execution: true,
      live_sample_mutation_performed: false,
    },
    routing: [
      {
        goal: 'ruleset-provenance-and-rule-validation',
        priority: 'high',
        next_tools: ['artifact.read', 'yara.scan'],
        required_evidence: [
          YARAX_SCAN_ARTIFACT_TYPE,
          'ruleset provenance',
          'YARA-X rule validation summary',
        ],
      },
      {
        goal: 'artifact-review-and-offset-validation',
        priority: matchCount > 0 ? 'high' : 'normal',
        next_tools: ['artifact.read'],
        required_evidence: [
          YARAX_SCAN_ARTIFACT_TYPE,
          'YARA-X rule match offsets',
          'YARA-X corroboration',
        ],
      },
      {
        goal: 'legacy-yara-comparison',
        priority: 'normal',
        next_tools: ['yara.scan'],
        required_evidence: [
          YARAX_SCAN_ARTIFACT_TYPE,
          'legacy YARA compatibility rules',
          'same ruleset provenance',
        ],
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
    'Compare the same ruleset with yara.scan to catch legacy YARA engine compatibility gaps before publishing detections.',
    'Route the artifact into analysis.evidence.graph before report.generate for correlated reporting.',
  ]
  if (rulesSource(args.input) === 'unknown') {
    actions.unshift(
      'Provide rules_text or rules_path because yara_x.scan has no implicit default rules.'
    )
  }
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
  const backendSemantics = buildBackendSemantics(args.backend)
  const rulesetProvenance = buildRulesetProvenance(args.input, args.rulesDigest)
  const validationSemantics = buildValidationSemantics({
    input: args.input,
    rulesDigest: args.rulesDigest,
    patternMatchCount,
  })
  const corroborationPlan = buildCorroborationPlan({
    matchingRules: args.matchingRules,
    patternMatchCount,
    recommendedNextTools,
  })
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
    backend_semantics: backendSemantics,
    ruleset_provenance: rulesetProvenance,
    validation_semantics: validationSemantics,
    corroboration_plan: corroborationPlan,
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

function backendFromCachedData(data: Record<string, unknown>): YaraXBackend {
  const backend = data.backend
  if (isRecord(backend)) {
    return {
      available: Boolean(backend.available),
      source: nullableString(backend.source),
      path: nullableString(backend.path),
      version: nullableString(backend.version),
      checked_candidates: stringArray(backend.checked_candidates),
      error: nullableString(backend.error),
    }
  }
  return {
    available: true,
    source: 'analysis_evidence_cache',
    path: null,
    version: null,
    checked_candidates: [],
    error: null,
  }
}

function mergeSupplementalValue(base: unknown, existing: unknown): unknown {
  if (existing === undefined) return base
  if (isRecord(base) && isRecord(existing)) {
    const merged: Record<string, unknown> = { ...base }
    for (const [key, value] of Object.entries(existing)) {
      merged[key] = mergeSupplementalValue(base[key], value)
    }
    return merged
  }
  if (Array.isArray(base) && Array.isArray(existing)) {
    const merged: unknown[] = []
    const seen = new Set<string>()
    for (const item of [...base, ...existing]) {
      const key = JSON.stringify(item) ?? String(item)
      if (!seen.has(key)) {
        seen.add(key)
        merged.push(item)
      }
    }
    return merged
  }
  return existing
}

function mergeRecordField(
  target: Record<string, unknown>,
  base: Record<string, unknown>,
  existing: Record<string, unknown>,
  key: string
): void {
  const baseValue = base[key]
  const existingValue = existing[key]
  if (baseValue !== undefined) {
    target[key] = mergeSupplementalValue(baseValue, existingValue)
  }
}

function hydrateStructuredResult(args: {
  data: Record<string, unknown>
  input: YaraXScanInput
  sampleId: string
  rulesDigest: string | null
}): Record<string, unknown> {
  const matchingRules = normalizeMatchingRules(args.data.matching_rules ?? args.data.matches)
  const moduleOutputs = isRecord(args.data.module_outputs) ? args.data.module_outputs : {}
  const patternMatchCount = readNonNegativeInteger(
    args.data.pattern_match_count,
    countPatternMatches(matchingRules)
  )
  const base = buildStructuredResult({
    input: args.input,
    backend: backendFromCachedData(args.data),
    sampleId: args.sampleId,
    rulesDigest: args.rulesDigest,
    matchingRules,
    matchCount: readNonNegativeInteger(args.data.match_count, matchingRules.length),
    moduleOutputs,
  }) as Record<string, unknown>
  const hydrated: Record<string, unknown> = { ...base, ...args.data }

  for (const key of [
    'backend_semantics',
    'ruleset_provenance',
    'validation_semantics',
    'corroboration_plan',
    'evidence_summary',
    'workflow_handoff',
    'quality_gates',
  ]) {
    mergeRecordField(hydrated, base, args.data, key)
  }

  hydrated.recommended_next_tools = mergeStringArrays(
    stringArray(args.data.recommended_next_tools),
    buildRecommendedNextTools()
  )
  hydrated.next_actions = mergeStringArrays(
    stringArray(args.data.next_actions),
    buildNextActions({
      input: args.input,
      matchingRules,
      patternMatchCount,
    })
  )

  return hydrated
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
        const reusedData = isRecord(reused.result)
          ? hydrateStructuredResult({
              data: reused.result,
              input,
              sampleId: input.sample_id,
              rulesDigest,
            })
          : reused.result
        return {
          ok: true,
          data: reusedData as Record<string, unknown>,
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
