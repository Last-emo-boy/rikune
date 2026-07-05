/**
 * yara.scan tool implementation
 * Scans PE files using YARA rules to identify malware families and packers
 * Requirements: 5.1, 5.2, 5.3
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import path from 'path'
import { v4 as uuidv4 } from 'uuid'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { CacheManager } from '../../../cache-manager.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { resolvePackagePath } from '../../../runtime-paths.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import { lookupCachedResult, formatCacheWarning } from '../../../tools/cache-observability.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from '../../../tools/static-worker-client.js'
import { CACHE_TTL_30_DAYS } from '../../../constants/cache-ttl.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'

// ============================================================================
// Constants
// ============================================================================

const TOOL_NAME = 'yara.scan'
const TOOL_VERSION = '1.1.0'
const CACHE_TTL_MS = CACHE_TTL_30_DAYS
const YARA_SCAN_ARTIFACT_TYPE = 'backend_yara_scan'
const MATCH_PREVIEW_LIMIT = 25
const STRING_PREVIEW_LIMIT = 40

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for yara.scan tool
 * Requirements: 5.1, 5.2
 */
export const YaraScanInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  rule_set: z.string().describe('Rule set name (e.g., malware_families, packers)'),
  timeout_ms: z
    .number()
    .int()
    .min(1000)
    .optional()
    .default(30000)
    .describe('Timeout in milliseconds'),
  rule_tier: z
    .enum(['production', 'experimental', 'test', 'all'])
    .optional()
    .default('production')
    .describe('Rule quality tier. Default production excludes weak test rules.'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export type YaraScanInput = z.infer<typeof YaraScanInputSchema>

/**
 * Output schema for yara.scan tool
 * Requirements: 5.2, 5.3
 */
export const YaraScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      matches: z.array(
        z.object({
          rule: z.string(),
          tags: z.array(z.string()),
          meta: z.record(z.any()),
          strings: z.array(
            z.object({
              identifier: z.string(),
              offset: z.number(),
              matched_data: z.string(),
              location: z
                .object({
                  section: z.string().nullable().optional(),
                  offset_in_section: z.number().nullable().optional(),
                  rva: z.number().nullable().optional(),
                  distance_to_entrypoint: z.number().nullable().optional(),
                  function_hint: z
                    .object({
                      name: z.string(),
                      address: z.string(),
                      proximity: z.string(),
                    })
                    .nullable()
                    .optional(),
                })
                .optional(),
            })
          ),
          confidence: z
            .object({
              level: z.enum(['low', 'medium', 'high']),
              score: z.number(),
              reason: z.string(),
            })
            .optional(),
          evidence: z
            .object({
              import_dll_hits: z.array(z.string()),
              import_api_hits: z.array(z.string()),
              section_hits: z.array(z.string()).optional(),
              near_entrypoint_hits: z.number().optional(),
              string_only: z.boolean(),
            })
            .optional(),
          inference: z
            .object({
              classification: z.string(),
              summary: z.string(),
            })
            .optional(),
        })
      ),
      ruleset_version: z.string(),
      timed_out: z.boolean(),
      rule_set: z.string(),
      rule_tier: z.string().optional(),
      rule_files: z.array(z.string()).optional(),
      match_count: z.number().int().nonnegative().optional(),
      string_evidence_count: z.number().int().nonnegative().optional(),
      confidence_summary: z
        .object({
          high: z.number(),
          medium: z.number(),
          low: z.number(),
        })
        .optional(),
      import_evidence: z
        .object({
          dll_count: z.number(),
          api_count: z.number(),
        })
        .optional(),
      offset_mapping: z
        .object({
          parser: z.string().nullable().optional(),
          sections_count: z.number().optional(),
          entry_point: z.record(z.any()).optional(),
        })
        .optional(),
      quality_notes: z.array(z.string()).optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
      artifact: z.any().optional(),
    })
    .passthrough()
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export type YaraScanOutput = z.infer<typeof YaraScanOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for yara.scan
 */
export const yaraScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: '使用 YARA 规则扫描样本，识别已知的恶意软件家族和加壳器',
  inputSchema: YaraScanInputSchema,
  outputSchema: YaraScanOutputSchema,
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
    execution: ['static', 'triage', 'local-worker'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'signatures',
      'malware-family',
      'packer',
      'rule-matching',
      'workflow-handoff',
      'evidence-correlation',
      'readiness',
    ],
    evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: YARA_SCAN_ARTIFACT_TYPE,
      description:
        'Legacy YARA scan result with bounded match previews, rule provenance, evidence summary, workflow handoff, and quality gates',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'signatures',
      artifactTypes: [YARA_SCAN_ARTIFACT_TYPE],
      description: 'YARA rule matches, confidence, and rule provenance',
    },
    {
      category: 'imports',
      artifactTypes: [YARA_SCAN_ARTIFACT_TYPE],
      description: 'Import evidence used to score YARA matches',
    },
    {
      category: 'strings',
      artifactTypes: [YARA_SCAN_ARTIFACT_TYPE],
      description: 'Matched string identifiers, offsets, and bounded data previews',
    },
    {
      category: 'workflow',
      artifactTypes: [YARA_SCAN_ARTIFACT_TYPE],
      description: 'Scan-validation handoff for workflow search, evidence graph, and reporting',
    },
    {
      category: 'provenance',
      artifactTypes: [YARA_SCAN_ARTIFACT_TYPE],
      description: 'Ruleset version, selected rule files, and local worker provenance',
    },
  ],
  workflowRecipes: [
    {
      id: 'yara.scan-validation-handoff',
      title: 'YARA scan validation to evidence graph and reporting',
      description:
        'Run passive local YARA matching, preserve bounded offset evidence, validate rule provenance and confidence, then route results into the evidence graph and reporting workflow.',
      startsWith: ['yara.scan', 'yara.generate', 'yara_x.scan'],
      nextTools: [
        'artifact.read',
        'analysis.evidence.graph',
        'report.generate',
        'malware.intel.loop',
      ],
      requiredArtifacts: ['sample', 'bundled YARA rules'],
      producesArtifacts: [YARA_SCAN_ARTIFACT_TYPE],
      evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      runtimeBackends: ['static_python.preview'],
    },
  ],
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'static_python.preview',
    backendKind: 'builtin',
    adapter: 'runtime-worker-pool/static_worker.py:yara.scan',
    availability: 'builtin',
    supportedModes: ['local-static-scan'],
    defaultMode: 'local-static-scan',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [YARA_SCAN_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 30000,
      notes: [
        'Runs YARA matching against bytes from the local workspace only.',
        'Does not execute the sample and does not require network access by default.',
      ],
    },
    readiness: {
      missingBackendBehavior:
        'Return worker setup or execution errors without falling back to live execution.',
      setupActions: ['Install yara-python in the local static worker environment.'],
    },
    packaging: {
      installRoute: 'installed',
      installProfile: 'default',
      notes: ['Uses bundled workers/yara_rules rule files selected by rule_set and rule_tier.'],
    },
  },
}

// ============================================================================
// Worker Communication
// ============================================================================

/**
 * Worker request structure
 */
interface WorkerRequest {
  job_id: string
  tool: string
  sample: {
    sample_id: string
    path: string
  }
  args: Record<string, unknown>
  context: {
    request_time_utc: string
    policy: {
      allow_dynamic: boolean
      allow_network: boolean
    }
    versions: Record<string, string>
  }
}

/**
 * Worker response structure
 */
interface WorkerResponse {
  job_id: string
  ok: boolean
  warnings: string[]
  errors: string[]
  data: unknown
  artifacts: unknown[]
  metrics: Record<string, unknown>
}

/**
 * Spawn Python Static Worker and communicate via stdin/stdout JSON protocol
 *
 * Requirements: Worker communication
 *
 * @param request - Worker request object
 * @returns Worker response object
 */
async function callStaticWorker(request: WorkerRequest): Promise<WorkerResponse> {
  return new Promise((resolve, reject) => {
    // Get Python worker path
    const workerPath = resolvePackagePath('workers', 'static_worker.py')

    // Spawn Python process
    const pythonCommand = getPythonCommand()
    const pythonProcess = spawn(pythonCommand, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    // Collect stdout
    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    // Collect stderr
    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    // Handle process exit
    pythonProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python worker exited with code ${code}. stderr: ${stderr}`))
        return
      }

      // Parse response from stdout
      try {
        const lines = stdout.trim().split('\n')
        const lastLine = lines[lines.length - 1]
        const response: WorkerResponse = JSON.parse(lastLine)
        resolve(response)
      } catch (error) {
        reject(
          new Error(
            `Failed to parse worker response: ${(error as Error).message}. stdout: ${stdout}`
          )
        )
      }
    })

    // Handle process error
    pythonProcess.on('error', (error) => {
      reject(new Error(`Failed to spawn Python worker: ${error.message}`))
    })

    // Send request to worker via stdin
    try {
      pythonProcess.stdin.write(JSON.stringify(request) + '\n')
      pythonProcess.stdin.end()
    } catch (error) {
      reject(new Error(`Failed to write to worker stdin: ${(error as Error).message}`))
    }
  })
}

type YaraScanRecord = Record<string, unknown>

interface ConfidenceSummary {
  high: number
  medium: number
  low: number
}

function isRecord(value: unknown): value is YaraScanRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function readString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback
}

function readBoolean(value: unknown): boolean {
  return value === true
}

function readNonNegativeInteger(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.trunc(value))
  }
  return fallback
}

function readStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item.length > 0)
    : []
}

function normalizeMatches(data: YaraScanRecord): YaraScanRecord[] {
  return Array.isArray(data.matches) ? data.matches.filter(isRecord) : []
}

function normalizeConfidenceSummary(
  data: YaraScanRecord,
  matches: YaraScanRecord[]
): ConfidenceSummary {
  if (isRecord(data.confidence_summary)) {
    return {
      high: readNonNegativeInteger(data.confidence_summary.high),
      medium: readNonNegativeInteger(data.confidence_summary.medium),
      low: readNonNegativeInteger(data.confidence_summary.low),
    }
  }

  return matches.reduce<ConfidenceSummary>(
    (summary, match) => {
      const confidence = isRecord(match.confidence) ? match.confidence : {}
      const level = confidence.level
      if (level === 'high' || level === 'medium' || level === 'low') {
        summary[level] += 1
      } else {
        summary.low += 1
      }
      return summary
    },
    { high: 0, medium: 0, low: 0 }
  )
}

function countStringEvidence(matches: YaraScanRecord[]): number {
  return matches.reduce(
    (total, match) => total + (Array.isArray(match.strings) ? match.strings.length : 0),
    0
  )
}

function buildStringEvidencePreview(matches: YaraScanRecord[]) {
  const preview: YaraScanRecord[] = []

  for (const match of matches) {
    const strings = Array.isArray(match.strings) ? match.strings.filter(isRecord) : []
    for (const entry of strings) {
      if (preview.length >= STRING_PREVIEW_LIMIT) return preview
      const location = isRecord(entry.location) ? entry.location : {}
      const matchedData = typeof entry.matched_data === 'string' ? entry.matched_data : ''
      preview.push({
        rule: readString(match.rule, 'unknown'),
        identifier: readString(entry.identifier, 'unknown'),
        offset: readNonNegativeInteger(entry.offset),
        matched_data_preview: matchedData.slice(0, 96),
        section: typeof location.section === 'string' ? location.section : null,
        rva: typeof location.rva === 'number' ? location.rva : null,
        distance_to_entrypoint:
          typeof location.distance_to_entrypoint === 'number'
            ? location.distance_to_entrypoint
            : null,
      })
    }
  }

  return preview
}

function countStringsWithLocation(matches: YaraScanRecord[]): number {
  return matches.reduce((total, match) => {
    const strings = Array.isArray(match.strings) ? match.strings.filter(isRecord) : []
    return total + strings.filter((entry) => isRecord(entry.location)).length
  }, 0)
}

function countNearEntrypointHits(matches: YaraScanRecord[]): number {
  return matches.reduce((total, match) => {
    const evidence = isRecord(match.evidence) ? match.evidence : {}
    return total + readNonNegativeInteger(evidence.near_entrypoint_hits)
  }, 0)
}

function buildRuleProvenance(data: YaraScanRecord, input: YaraScanInput) {
  const ruleFiles = readStringArray(data.rule_files)
  return {
    source: 'bundled_static_worker_yara_rules',
    rule_set: readString(data.rule_set, input.rule_set),
    rule_tier: readString(data.rule_tier, input.rule_tier || 'production'),
    ruleset_version: readString(data.ruleset_version, 'unknown'),
    rule_files: ruleFiles,
    selected_rule_file_count: ruleFiles.length,
    local_worker_family: 'static_python.preview',
  }
}

function buildRecommendedNextTools(args: { matchCount: number; timedOut: boolean }): string[] {
  const tools = ['artifact.read', 'analysis.evidence.graph', 'report.generate']
  if (args.matchCount > 0) {
    tools.push('malware.intel.loop', 'ioc.export')
  } else {
    tools.push('yara.generate')
  }
  if (args.timedOut) {
    tools.push('yara.scan')
  }
  return Array.from(new Set(tools))
}

function buildNextActions(args: {
  matchCount: number
  stringEvidenceCount: number
  timedOut: boolean
}): string[] {
  const actions = [
    'Review the persisted backend_yara_scan artifact for the bounded rule, offset, and string evidence preview.',
    'Route the artifact into analysis.evidence.graph before report.generate so provenance and confidence are preserved.',
  ]

  if (args.matchCount > 0) {
    actions.unshift(
      'Validate matched rule provenance, confidence level, and offset context before treating the hit as a family label.'
    )
  } else {
    actions.unshift(
      'Treat the scan as no-hit evidence and consider yara.generate only after richer strings/imports evidence is available.'
    )
  }
  if (args.stringEvidenceCount === 0) {
    actions.push(
      'Confirm the rule match did not omit string offsets before using it as strong evidence.'
    )
  }
  if (args.timedOut) {
    actions.unshift(
      'Repeat yara.scan with a narrower rule_set or longer timeout before final reporting.'
    )
  }

  return actions
}

function buildEvidenceSummary(args: {
  input: YaraScanInput
  sampleId: string
  data: YaraScanRecord
  matches: YaraScanRecord[]
  confidenceSummary: ConfidenceSummary
  stringEvidenceCount: number
}) {
  const stringPreview = buildStringEvidencePreview(args.matches)
  const stringsWithLocation = countStringsWithLocation(args.matches)
  const ruleProvenance = buildRuleProvenance(args.data, args.input)
  const matchedRules = args.matches
    .map((match) => readString(match.rule, ''))
    .filter((rule) => rule.length > 0)

  return {
    schema: 'rikune.yara_scan.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: YARA_SCAN_ARTIFACT_TYPE,
    rule_provenance: ruleProvenance,
    rule_set: ruleProvenance.rule_set,
    rule_tier: ruleProvenance.rule_tier,
    ruleset_version: ruleProvenance.ruleset_version,
    match_count: args.matches.length,
    matched_rule_names: matchedRules.slice(0, MATCH_PREVIEW_LIMIT),
    string_evidence_count: args.stringEvidenceCount,
    offset_evidence: {
      strings_with_offsets: stringPreview.length,
      strings_with_location: stringsWithLocation,
      near_entrypoint_hits: countNearEntrypointHits(args.matches),
      parser: isRecord(args.data.offset_mapping)
        ? readString(args.data.offset_mapping.parser, 'unknown')
        : 'unknown',
      sections_count: isRecord(args.data.offset_mapping)
        ? readNonNegativeInteger(args.data.offset_mapping.sections_count)
        : 0,
      string_preview: stringPreview,
    },
    confidence_summary: args.confidenceSummary,
    import_evidence: isRecord(args.data.import_evidence) ? args.data.import_evidence : {},
    timed_out: readBoolean(args.data.timed_out),
    bounded_match_preview: {
      max_rules: MATCH_PREVIEW_LIMIT,
      returned_rules: Math.min(args.matches.length, MATCH_PREVIEW_LIMIT),
      max_strings: STRING_PREVIEW_LIMIT,
      returned_strings: stringPreview.length,
      truncated:
        args.matches.length > MATCH_PREVIEW_LIMIT ||
        args.stringEvidenceCount > STRING_PREVIEW_LIMIT,
    },
  }
}

function dominantConfidence(summary: ConfidenceSummary): 'high' | 'medium' | 'low' | 'none' {
  if (summary.high > 0) return 'high'
  if (summary.medium > 0) return 'medium'
  if (summary.low > 0) return 'low'
  return 'none'
}

function buildQualityGates(args: {
  input: YaraScanInput
  data: YaraScanRecord
  matches: YaraScanRecord[]
  confidenceSummary: ConfidenceSummary
  stringEvidenceCount: number
  backendStarted: boolean
}) {
  const ruleProvenance = buildRuleProvenance(args.data, args.input)
  const timedOut = readBoolean(args.data.timed_out)
  return {
    schema: 'rikune.yara_scan.quality_gates.v1',
    passive_local_scan_only: true,
    backend_started: args.backendStarted,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    live_sample_mutation_performed: false,
    rule_provenance_available:
      ruleProvenance.ruleset_version !== 'unknown' || ruleProvenance.rule_files.length > 0,
    match_floor_met: args.matches.length > 0,
    string_offset_evidence_available: args.stringEvidenceCount > 0,
    confidence_summary_available:
      args.confidenceSummary.high + args.confidenceSummary.medium + args.confidenceSummary.low > 0,
    dominant_confidence: dominantConfidence(args.confidenceSummary),
    bounded_match_preview_returned: true,
    timed_out: timedOut,
    timeout_ms: args.input.timeout_ms,
    artifact_review_required: true,
    false_positive_review_required: args.matches.length > 0,
  }
}

function buildWorkflowHandoff(args: {
  input: YaraScanInput
  sampleId: string
  data: YaraScanRecord
  matches: YaraScanRecord[]
  stringEvidenceCount: number
  recommendedNextTools: string[]
  backendStarted: boolean
}) {
  const matchCount = args.matches.length
  const ruleProvenance = buildRuleProvenance(args.data, args.input)
  return {
    schema: 'rikune.yara_scan.workflow_handoff.v1',
    handoff_mode: 'yara_scan_to_validation_evidence_graph_and_reporting',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: YARA_SCAN_ARTIFACT_TYPE,
    rule_provenance: ruleProvenance,
    match_count: matchCount,
    string_evidence_count: args.stringEvidenceCount,
    recommended_next_tools: args.recommendedNextTools,
    dynamic_boundary: {
      passive_local_scan_only: true,
      backend_started: args.backendStarted,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      live_sample_mutation_performed: false,
    },
    routing: [
      {
        goal: 'artifact-review-and-offset-validation',
        priority: matchCount > 0 ? 'high' : 'normal',
        next_tools: ['artifact.read'],
        required_evidence: [YARA_SCAN_ARTIFACT_TYPE, 'YARA string offsets'],
      },
      {
        goal: 'rule-provenance-and-confidence-review',
        priority: matchCount > 0 ? 'high' : 'normal',
        next_tools: ['artifact.read', 'analysis.evidence.graph'],
        required_evidence: ['ruleset_version', 'rule_files', 'confidence_summary'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: matchCount > 0 ? 'high' : 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [YARA_SCAN_ARTIFACT_TYPE],
      },
      {
        goal: 'workflow-search-reuse',
        priority: 'normal',
        next_tools: ['workflow.search'],
        required_evidence: ['yara.scan-validation-handoff'],
      },
    ],
  }
}

function buildStructuredYaraScanResult(args: {
  input: YaraScanInput
  sampleId: string
  data: YaraScanRecord
  backendStarted: boolean
}): YaraScanRecord {
  const matches = normalizeMatches(args.data)
  const confidenceSummary = normalizeConfidenceSummary(args.data, matches)
  const stringEvidenceCount = countStringEvidence(matches)
  const timedOut = readBoolean(args.data.timed_out)
  const recommendedNextTools = buildRecommendedNextTools({
    matchCount: matches.length,
    timedOut,
  })
  const evidenceSummary = buildEvidenceSummary({
    input: args.input,
    sampleId: args.sampleId,
    data: args.data,
    matches,
    confidenceSummary,
    stringEvidenceCount,
  })
  const qualityGates = buildQualityGates({
    input: args.input,
    data: args.data,
    matches,
    confidenceSummary,
    stringEvidenceCount,
    backendStarted: args.backendStarted,
  })
  const workflowHandoff = buildWorkflowHandoff({
    input: args.input,
    sampleId: args.sampleId,
    data: args.data,
    matches,
    stringEvidenceCount,
    recommendedNextTools,
    backendStarted: args.backendStarted,
  })

  return {
    ...args.data,
    schema: 'rikune.yara_scan.v1',
    tool_version: TOOL_VERSION,
    sample_id: args.sampleId,
    rule_set: readString(args.data.rule_set, args.input.rule_set),
    rule_tier: readString(args.data.rule_tier, args.input.rule_tier || 'production'),
    ruleset_version: readString(args.data.ruleset_version, 'unknown'),
    match_count: matches.length,
    string_evidence_count: stringEvidenceCount,
    confidence_summary: confidenceSummary,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
    recommended_next_tools: recommendedNextTools,
    next_actions: buildNextActions({
      matchCount: matches.length,
      stringEvidenceCount,
      timedOut,
    }),
  }
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create yara.scan tool handler
 * Requirements: 5.1, 5.2, 5.3, 5.5
 */
export function createYaraScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = YaraScanInputSchema.parse(args)

      // 1. Validate sample exists
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      // 2. Generate cache key
      // Requirement: 5.5 - Cache key includes ruleset version
      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          rule_set: input.rule_set,
          timeout_ms: input.timeout_ms,
          rule_tier: input.rule_tier,
        },
      })

      // 3. Check cache
      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          const cachedData = isRecord(cachedLookup.data)
            ? buildStructuredYaraScanResult({
                input,
                sampleId: input.sample_id,
                data: cachedLookup.data,
                backendStarted: false,
              })
            : cachedLookup.data

          return {
            ok: true,
            data: cachedData,
            warnings: ['Result from cache', formatCacheWarning(cachedLookup.metadata)],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
              cache_key: cachedLookup.metadata.key,
              cache_tier: cachedLookup.metadata.tier,
              cache_created_at: cachedLookup.metadata.createdAt,
              cache_expires_at: cachedLookup.metadata.expiresAt,
              cache_hit_at: cachedLookup.metadata.fetchedAt,
            },
          }
        }
      }

      const warnings = input.force_refresh ? ['force_refresh=true; bypassed cache lookup'] : []

      // 4. Get sample path from workspace
      const workspace = await workspaceManager.getWorkspace(input.sample_id)

      // Find the sample file in the original directory
      const fs = await import('fs/promises')
      const files = await fs.readdir(workspace.original)
      if (files.length === 0) {
        return {
          ok: false,
          errors: ['Sample file not found in workspace'],
        }
      }

      const samplePath = path.join(workspace.original, files[0])

      // 5. Prepare worker request
      const workerRequest: WorkerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          rule_set: input.rule_set,
          timeout_ms: input.timeout_ms,
          rule_tier: input.rule_tier,
        },
        toolVersion: TOOL_VERSION,
      })

      // 6. Call Static Worker
      // Requirements: 5.1, 5.2, 5.3
      const workerResponse = await callPooledStaticWorker(workerRequest, {
        database,
        family: 'static_python.preview',
      })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
        }
      }

      warnings.push(...(workerResponse.warnings || []))

      let outputData: unknown = workerResponse.data
      const artifacts: ArtifactRef[] = Array.isArray(workerResponse.artifacts)
        ? [...(workerResponse.artifacts as ArtifactRef[])]
        : []

      if (isRecord(workerResponse.data)) {
        outputData = buildStructuredYaraScanResult({
          input,
          sampleId: input.sample_id,
          data: {
            ...workerResponse.data,
            worker_pool: workerResponse.metrics?.worker_pool,
          },
          backendStarted: true,
        })

        try {
          const artifactRef = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            YARA_SCAN_ARTIFACT_TYPE,
            'yara_scan',
            outputData
          )
          artifacts.push(artifactRef)
          outputData = { ...(outputData as YaraScanRecord), artifact: artifactRef }
        } catch {
          warnings.push('Failed to persist YARA scan artifact')
        }
      }

      // 7. Cache result
      // Requirement: 5.5 - Cache with ruleset version for invalidation
      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS)

      // 8. Return result
      return {
        ok: true,
        data: outputData,
        warnings: warnings.length > 0 ? warnings : undefined,
        errors: workerResponse.errors,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: {
          ...workerResponse.metrics,
          elapsed_ms: Date.now() - startTime,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
