/**
 * strings.extract tool implementation
 * Extracts readable strings (ASCII and Unicode) from PE files
 * Requirements: 4.1, 4.2, 4.3
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import { randomUUID } from 'crypto'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { CacheManager } from '../../../cache-manager.js'
import type { JobQueue } from '../../../job-queue.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { resolvePackagePath } from '../../../runtime-paths.js'
import { formatCacheWarning } from '../../../tools/cache-observability.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from '../../../tools/static-worker-client.js'
import { buildEnrichedStringBundle, EnrichedStringBundleSchema } from '../string-xref-analysis.js'
import {
  ENRICHED_STRING_ANALYSIS_ARTIFACT_TYPE,
  persistStringXrefJsonArtifact,
} from '../string-xref-artifacts.js'
import {
  buildDeferredToolResponse,
  shouldDeferLargeSample,
} from '../../../analysis/nonblocking-analysis.js'
import { classifySampleSizeTier } from '../../../analysis/analysis-coverage.js'
import { persistChunkedArrayArtifacts } from '../../../analysis/chunked-analysis-evidence.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'
import {
  AnalysisEvidenceStateSchema,
  buildDeferredEvidenceState,
  buildFreshEvidenceState,
  buildResolvedEvidenceState,
  buildEvidenceReuseWarnings,
  persistCanonicalEvidence,
  resolveCanonicalEvidenceOrCache,
} from '../../../analysis/analysis-evidence.js'
import { CACHE_TTL_30_DAYS } from '../../../constants/cache-ttl.js'

// ============================================================================
// Constants
// ============================================================================

const TOOL_NAME = 'strings.extract'
const TOOL_VERSION = '1.1.0'
const CACHE_TTL_MS = CACHE_TTL_30_DAYS
const LARGE_SAMPLE_INLINE_STRINGS = 120
const MEDIUM_SAMPLE_INLINE_STRINGS = 180
const DEFAULT_FULL_INLINE_STRINGS = 240
const STRING_CHUNK_SIZE = 200

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for strings.extract tool
 * Requirements: 4.1, 4.2, 4.3
 */
export const StringsExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  mode: z
    .enum(['preview', 'full'])
    .optional()
    .default('preview')
    .describe(
      'preview is bounded and safe for synchronous MCP use. Start with preview on medium or larger samples. full scans the complete sample and may be deferred to the background queue.'
    ),
  min_len: z.number().int().min(1).optional().default(4).describe('Minimum string length'),
  encoding: z
    .enum(['ascii', 'unicode', 'all'])
    .optional()
    .default('all')
    .describe('Encoding type to extract'),
  max_strings: z
    .number()
    .int()
    .min(1)
    .optional()
    .default(500)
    .describe('Maximum number of strings to return (default: 500)'),
  max_string_length: z
    .number()
    .int()
    .min(16)
    .optional()
    .default(512)
    .describe('Maximum length for each returned string'),
  max_scan_bytes: z
    .number()
    .int()
    .min(65536)
    .optional()
    .describe(
      'Optional bounded scan budget used in preview mode. The worker samples the file instead of scanning every byte.'
    ),
  context_window_bytes: z
    .number()
    .int()
    .min(32)
    .max(65536)
    .optional()
    .default(1024)
    .describe('Maximum byte gap used to regroup nearby strings into context windows'),
  max_context_windows: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .default(12)
    .describe('Maximum number of context windows returned in the summary'),
  category_filter: z
    .enum([
      'all',
      'ioc',
      'url',
      'network',
      'ipc',
      'command',
      'registry',
      'file_path',
      'suspicious_api',
    ])
    .optional()
    .default('all')
    .describe('Optional category filter; use `ioc` to prioritize IOC-related strings'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
  defer_if_slow: z
    .boolean()
    .optional()
    .default(true)
    .describe(
      'When true, mode=full may return a queued job instead of blocking the MCP request on medium or larger samples.'
    ),
  enrich_result: z
    .boolean()
    .optional()
    .default(true)
    .describe('Attach analyst-oriented enriched string classification and bounded summaries'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist enriched string intelligence as a JSON artifact for later reuse'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting enriched string artifacts'),
})

export type StringsExtractInput = z.infer<typeof StringsExtractInputSchema>

/**
 * Output schema for strings.extract tool
 * Requirements: 4.1, 4.2, 4.3, 4.6
 */
export const StringsExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'queued', 'partial']).optional(),
      sample_id: z.string().optional(),
      result_mode: z.enum(['preview', 'full']).optional(),
      execution_state: z.enum(['inline', 'queued', 'partial', 'completed']).optional(),
      job_id: z.string().optional(),
      polling_guidance: z.any().optional(),
      evidence_state: z.array(AnalysisEvidenceStateSchema).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
      strings: z
        .array(
          z.object({
            offset: z.number(),
            string: z.string(),
            encoding: z.string(),
          })
        )
        .optional(),
      count: z.number().optional(),
      total_count: z.number().optional(),
      pre_filter_count: z.number().optional(),
      truncated: z.boolean().optional(),
      max_strings: z.number().optional(),
      max_string_length: z.number().optional(),
      max_scan_bytes: z.number().optional(),
      scan_mode: z.string().optional(),
      scan_bytes: z.number().optional(),
      sampled: z.boolean().optional(),
      min_len: z.number().optional(),
      encoding_filter: z.string().optional(),
      category_filter: z.string().optional(),
      summary: z
        .object({
          cluster_counts: z.record(z.string(), z.number()),
          clusters: z.record(z.string(), z.array(z.string())),
          top_high_value: z.array(
            z.object({
              offset: z.number(),
              string: z.string(),
              encoding: z.string(),
              categories: z.array(z.string()),
            })
          ),
          context_windows: z
            .array(
              z.object({
                start_offset: z.number(),
                end_offset: z.number(),
                score: z.number(),
                categories: z.array(z.string()),
                strings: z.array(
                  z.object({
                    offset: z.number(),
                    string: z.string(),
                    encoding: z.string(),
                    categories: z.array(z.string()),
                  })
                ),
              })
            )
            .optional(),
        })
        .optional(),
      enriched: EnrichedStringBundleSchema.optional(),
    })
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

export type StringsExtractOutput = z.infer<typeof StringsExtractOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for strings.extract
 */
export const stringsExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract readable strings from a sample and return compact IOC-aware grouping plus enriched analyst labels. ' +
    'Use this for fast string triage; use analysis.context.link when you need merged FLOSS output and function-aware attribution before full reconstruction. ' +
    'On medium/large samples, prefer mode=preview first and only escalate to mode=full when the workflow explicitly needs complete extraction.',
  inputSchema: StringsExtractInputSchema,
  outputSchema: StringsExtractOutputSchema,
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
      'pyc',
      'lua-bytecode',
      'v8-cache',
    ],
    platforms: [
      'windows',
      'linux',
      'macos',
      'android',
      'jvm',
      'dotnet',
      'wasm',
      'embedded',
      'cross-platform',
    ],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: ['strings', 'ioc', 'context-windows', 'workflow-handoff', 'evidence-correlation'],
    evidence: [
      'strings',
      'network',
      'filesystem',
      'registry',
      'encoded-config',
      'workflow',
      'provenance',
    ],
  },
  artifacts: [
    {
      type: 'enriched_string_analysis',
      description: 'Enriched string extraction output with IOC categories and bounded chunks',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'strings',
      artifactTypes: ['enriched_string_analysis'],
    },
    {
      category: 'network',
      artifactTypes: ['enriched_string_analysis'],
    },
    {
      category: 'filesystem',
      artifactTypes: ['enriched_string_analysis'],
    },
    {
      category: 'registry',
      artifactTypes: ['enriched_string_analysis'],
    },
    {
      category: 'encoded-config',
      artifactTypes: ['enriched_string_analysis'],
    },
    {
      category: 'workflow',
      artifactTypes: ['enriched_string_analysis'],
    },
    {
      category: 'provenance',
      artifactTypes: ['enriched_string_analysis'],
    },
  ],
  workflowRecipes: [
    {
      id: 'strings.raw-extraction-evidence',
      title: 'Raw string evidence to context, IOC, and reporting handoff',
      startsWith: ['strings.extract', 'analysis.context.link'],
      nextTools: [
        'analysis.context.link',
        'strings.floss.decode',
        'static.config.carver',
        'malware.intel.loop',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['sample bytes'],
      producesArtifacts: ['enriched_string_analysis'],
      evidence: [
        'strings',
        'network',
        'filesystem',
        'registry',
        'encoded-config',
        'workflow',
        'provenance',
      ],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'Static string extraction reads sample bytes through a bounded worker and does not execute the sample.',
    ],
  } as ToolDefinition['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'Static Python strings extractor',
    backendKind: 'external',
    adapter: 'static_python.strings.extract',
    availability: 'optional',
    envVar: 'STATIC_WORKER_PYTHON',
    commandHint: 'python3',
    supportedModes: ['external'],
    defaultMode: 'external',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: ['enriched_string_analysis'],
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
        'Worker performs read-only printable string extraction and IOC categorization.',
        'Missing worker readiness must be reported as setup metadata, not replaced with live execution.',
      ],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Configure the static Python worker used for strings.extract.',
        'Retry strings.extract after static worker readiness is restored.',
      ],
      missingBackendBehavior:
        'Return setup_required or partial static evidence with setup actions; do not execute the sample.',
    },
    packaging: {
      installRoute: 'installed',
      installProfile: 'default',
      dockerFeature: 'static-python',
      envVar: 'STATIC_WORKER_PYTHON',
      dockerDefault: 'python3',
      notes: ['Uses the shared static Python worker path packaged with the MCP server.'],
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

function normalizeStringsExtractData(
  payload: unknown,
  input: StringsExtractInput
): Record<string, unknown> {
  const data =
    payload && typeof payload === 'object' ? { ...(payload as Record<string, unknown>) } : {}
  const extracted = Array.isArray(data.strings)
    ? data.strings
        .map((item) => {
          const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
          if (typeof entry.string !== 'string') {
            return null
          }
          return {
            offset: Number(entry.offset || 0),
            string: entry.string,
            encoding: typeof entry.encoding === 'string' ? entry.encoding : null,
          }
        })
        .filter(
          (
            item
          ): item is {
            offset: number
            string: string
            encoding: string | null
          } => Boolean(item)
        )
    : []

  if (input.enrich_result !== false) {
    const summary =
      data.summary && typeof data.summary === 'object'
        ? (data.summary as Record<string, unknown>)
        : {}
    data.enriched = buildEnrichedStringBundle(extracted, [], {
      maxRecords: Math.max(20, Math.min(input.max_strings || 500, 120)),
      maxHighlights: 12,
      contextWindows: Array.isArray(summary.context_windows)
        ? (summary.context_windows as unknown[])
        : [],
    })
  }

  return data
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function readString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function readNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function uniqueStrings(values: unknown[], limit = 16): string[] {
  return Array.from(new Set(values.map(readString).filter(Boolean))).slice(0, limit)
}

function enrichedBundle(data: Record<string, unknown>): Record<string, unknown> | null {
  return asRecord(data.enriched)
}

function highlightValues(
  enriched: Record<string, unknown> | null,
  key: string,
  limit = 8
): string[] {
  return asArray(enriched?.[key])
    .map((value) => asRecord(value))
    .filter((value): value is Record<string, unknown> => Boolean(value))
    .map((value) => readString(value.value))
    .filter(Boolean)
    .slice(0, limit)
}

function extractedStringCount(data: Record<string, unknown>): number {
  return asArray(data.strings).length || readNumber(data.count, 0)
}

function buildRecommendedNextTools(data: Record<string, unknown>): string[] {
  const enriched = enrichedBundle(data)
  const hasIocs = highlightValues(enriched, 'top_iocs', 1).length > 0
  const encodedCandidateCount = readNumber(enriched?.encoded_candidate_count, 0)
  const tools = [
    'analysis.context.link',
    'strings.floss.decode',
    'static.config.carver',
    'malware.intel.loop',
    'analysis.evidence.graph',
    'report.generate',
  ]
  if (hasIocs) {
    tools.push('ioc.export')
  }
  if (encodedCandidateCount > 0) {
    tools.push('crypto.identify', 'unpack.workflow.plan')
  }
  return uniqueStrings(tools, 12)
}

function buildEvidenceSummary(args: {
  sampleId: string
  data: Record<string, unknown>
  input: StringsExtractInput
  warningCount: number
}) {
  const enriched = enrichedBundle(args.data)
  return {
    schema: 'rikune.strings_extract.evidence_summary.v1',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    result_mode: args.input.mode,
    category_filter: args.input.category_filter,
    string_count: extractedStringCount(args.data),
    total_count: readNumber(args.data.total_count, readNumber(args.data.count, 0)),
    pre_filter_count: readNumber(args.data.pre_filter_count, 0),
    truncated: Boolean(args.data.truncated),
    sampled: Boolean(args.data.sampled),
    scan_mode: readString(args.data.scan_mode) || args.input.mode,
    enriched_bundle_present: Boolean(enriched),
    analyst_relevant_count: readNumber(enriched?.analyst_relevant_count, 0),
    runtime_noise_count: readNumber(enriched?.runtime_noise_count, 0),
    encoded_candidate_count: readNumber(enriched?.encoded_candidate_count, 0),
    top_iocs: highlightValues(enriched, 'top_iocs'),
    top_suspicious: highlightValues(enriched, 'top_suspicious'),
    context_window_count: asArray(asRecord(args.data.summary)?.context_windows).length,
    warning_count: args.warningCount,
  }
}

function buildWorkflowHandoff(args: {
  sampleId: string
  data: Record<string, unknown>
  input: StringsExtractInput
  recommendedNextTools: string[]
  backendStarted: boolean
}) {
  const enriched = enrichedBundle(args.data)
  const stringCount = extractedStringCount(args.data)
  const hasIocs = highlightValues(enriched, 'top_iocs', 1).length > 0
  const encodedCandidateCount = readNumber(enriched?.encoded_candidate_count, 0)
  return {
    schema: 'rikune.strings_extract.workflow_handoff.v1',
    handoff_mode: 'raw_strings_to_context_ioc_and_reporting',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    recommended_next_tools: args.recommendedNextTools,
    string_context: {
      result_mode: args.input.mode,
      string_count: stringCount,
      analyst_relevant_count: readNumber(enriched?.analyst_relevant_count, 0),
      encoded_candidate_count: encodedCandidateCount,
      top_iocs: highlightValues(enriched, 'top_iocs'),
      top_suspicious: highlightValues(enriched, 'top_suspicious'),
    },
    routing: [
      {
        goal: 'raw-string-context-linking',
        priority: stringCount > 0 ? 'high' : 'optional',
        next_tools: ['analysis.context.link', 'code.xrefs.analyze'],
        required_evidence: ['raw strings', 'enriched_string_analysis'],
      },
      {
        goal: 'decoded-string-followup',
        priority: encodedCandidateCount > 0 ? 'high' : 'normal',
        next_tools: ['strings.floss.decode', 'crypto.identify', 'unpack.workflow.plan'],
        required_evidence: ['raw strings', 'encoded string candidates'],
      },
      {
        goal: 'ioc-and-config-carving',
        priority: hasIocs ? 'high' : 'normal',
        next_tools: ['static.config.carver', 'ioc.export', 'malware.intel.loop'],
        required_evidence: ['raw strings', 'enriched_string_analysis'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: ['enriched_string_analysis'],
      },
    ],
    artifact_contract: {
      consumes: ['sample bytes'],
      produces: ['enriched_string_analysis'],
      expected_consumers: [
        'analysis.context.link',
        'strings.floss.decode',
        'static.config.carver',
        'malware.intel.loop',
        'analysis.evidence.graph',
        'report.generate',
      ],
    },
    dynamic_boundary: {
      static_backend_started: args.backendStarted,
      runtime_started_by_tool: false,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
      runtime_followup_requires_opt_in: true,
    },
  }
}

function buildQualityGates(args: {
  data: Record<string, unknown>
  input: StringsExtractInput
  backendStarted: boolean
}) {
  const enriched = enrichedBundle(args.data)
  const stringCount = extractedStringCount(args.data)
  const iocCount = highlightValues(enriched, 'top_iocs', 12).length
  const encodedCandidateCount = readNumber(enriched?.encoded_candidate_count, 0)
  return {
    passive_static_extraction: true,
    preview_mode_used: args.input.mode === 'preview',
    static_backend_started: args.backendStarted,
    runtime_started_by_tool: false,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    strings_present: stringCount > 0,
    enriched_bundle_present: Boolean(enriched),
    ioc_handoff_ready: iocCount > 0,
    config_handoff_ready: iocCount > 0 || encodedCandidateCount > 0,
    evidence_graph_handoff_ready: true,
    truncated: Boolean(args.data.truncated),
    sampled: Boolean(args.data.sampled),
    runtime_followup_requires_opt_in: true,
    analyst_review_required:
      stringCount > 0 || iocCount > 0 || encodedCandidateCount > 0 || Boolean(args.data.truncated),
  }
}

function buildNextActions(args: {
  data: Record<string, unknown>
  recommendedNextTools: string[]
}): string[] {
  const actions = [
    'Run analysis.context.link to merge raw strings with decoded strings and function context.',
    'Run analysis.evidence.graph to correlate enriched string evidence with other plugin artifacts.',
  ]
  if (args.recommendedNextTools.includes('strings.floss.decode')) {
    actions.push('Run strings.floss.decode when raw strings suggest obfuscation or encoded config.')
  }
  if (args.recommendedNextTools.includes('ioc.export')) {
    actions.push('Export high-confidence string IOCs with ioc.export.')
  }
  if (args.recommendedNextTools.includes('crypto.identify')) {
    actions.push(
      'Use crypto.identify or unpack.workflow.plan for encoded or packed string follow-up.'
    )
  }
  if (extractedStringCount(args.data) === 0) {
    actions.push(
      'If no strings were found, retry with a smaller min_len or inspect packed payloads.'
    )
  }
  return actions
}

function buildStructuredHandoff(args: {
  sampleId: string
  data: Record<string, unknown>
  input: StringsExtractInput
  warningCount: number
  backendStarted: boolean
}) {
  const recommendedNextTools = buildRecommendedNextTools(args.data)
  return {
    evidenceSummary: buildEvidenceSummary({
      sampleId: args.sampleId,
      data: args.data,
      input: args.input,
      warningCount: args.warningCount,
    }),
    workflowHandoff: buildWorkflowHandoff({
      sampleId: args.sampleId,
      data: args.data,
      input: args.input,
      recommendedNextTools,
      backendStarted: args.backendStarted,
    }),
    qualityGates: buildQualityGates({
      data: args.data,
      input: args.input,
      backendStarted: args.backendStarted,
    }),
    recommendedNextTools,
    nextActions: buildNextActions({
      data: args.data,
      recommendedNextTools,
    }),
  }
}

function chooseInlineStringsLimit(
  sampleSizeTier: ReturnType<typeof classifySampleSizeTier>
): number {
  if (sampleSizeTier === 'large' || sampleSizeTier === 'oversized') {
    return LARGE_SAMPLE_INLINE_STRINGS
  }
  if (sampleSizeTier === 'medium') {
    return MEDIUM_SAMPLE_INLINE_STRINGS
  }
  return DEFAULT_FULL_INLINE_STRINGS
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create strings.extract tool handler
 * Requirements: 4.1, 4.2, 4.3
 */
export function createStringsExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  jobQueue?: JobQueue,
  options: { allowDeferred?: boolean } = {}
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = StringsExtractInputSchema.parse(args)
    const startTime = Date.now()

    try {
      // 1. Generate cache key
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }
      const sampleSizeTier = classifySampleSizeTier(sample.size)

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          mode: input.mode,
          min_len: input.min_len,
          encoding: input.encoding,
          max_strings: input.max_strings,
          max_string_length: input.max_string_length,
          max_scan_bytes: input.max_scan_bytes,
          context_window_bytes: input.context_window_bytes,
          max_context_windows: input.max_context_windows,
          category_filter: input.category_filter,
          enrich_result: input.enrich_result,
        },
      })

      // 2. Check cache
      if (!input.force_refresh) {
        const resolved = await resolveCanonicalEvidenceOrCache(database, cacheManager, cacheKey, {
          sample,
          evidenceFamily: 'strings',
          backend: TOOL_NAME,
          mode: input.mode,
          args: {
            min_len: input.min_len,
            encoding: input.encoding,
            max_strings: input.max_strings,
            max_string_length: input.max_string_length,
            max_scan_bytes: input.max_scan_bytes,
            context_window_bytes: input.context_window_bytes,
            max_context_windows: input.max_context_windows,
            category_filter: input.category_filter,
            enrich_result: input.enrich_result,
          },
        })
        if (resolved) {
          const normalizedCachedData = normalizeStringsExtractData(resolved.record.result, input)
          const warnings =
            resolved.source === 'cache' && resolved.cache
              ? [
                  ...buildEvidenceReuseWarnings(resolved),
                  formatCacheWarning(resolved.cache.metadata),
                ]
              : buildEvidenceReuseWarnings(resolved)
          const structured = buildStructuredHandoff({
            sampleId: input.sample_id,
            data: normalizedCachedData,
            input,
            warningCount: warnings.length,
            backendStarted: false,
          })
          return {
            ok: true,
            data: {
              status: 'ready',
              sample_id: input.sample_id,
              result_mode: input.mode,
              execution_state: 'completed',
              evidence_state: [buildResolvedEvidenceState(resolved)],
              ...normalizedCachedData,
              evidence_summary: structured.evidenceSummary,
              workflow_handoff: structured.workflowHandoff,
              quality_gates: structured.qualityGates,
              recommended_next_tools: structured.recommendedNextTools,
              next_actions: structured.nextActions,
            },
            warnings,
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: resolved.source === 'cache',
              cache_key: resolved.cache?.metadata.key,
              cache_tier: resolved.cache?.metadata.tier,
              cache_created_at: resolved.cache?.metadata.createdAt,
              cache_expires_at: resolved.cache?.metadata.expiresAt,
              cache_hit_at: resolved.cache?.metadata.fetchedAt,
            },
          }
        }
      }

      if (
        input.mode === 'full' &&
        input.defer_if_slow !== false &&
        jobQueue &&
        options.allowDeferred !== false &&
        shouldDeferLargeSample(sample, input.mode)
      ) {
        return buildDeferredToolResponse({
          jobQueue,
          tool: TOOL_NAME,
          sampleId: input.sample_id,
          args: {
            ...input,
            defer_if_slow: false,
          },
          timeoutMs: 5 * 60 * 1000,
          summary:
            'Full string extraction was deferred because complete scans on medium or larger samples are too expensive for synchronous MCP requests.',
          nextTools: ['task.status', 'analysis.context.link', 'binary.role.profile'],
          nextActions: [
            'Poll task.status with the returned job_id before requesting the same full string extraction again.',
            'Use mode=preview when you only need a bounded first-pass IOC and noise-filtered string view.',
          ],
          metadata: {
            evidence_state: [
              buildDeferredEvidenceState({
                evidenceFamily: 'strings',
                backend: TOOL_NAME,
                mode: input.mode,
                reason:
                  'Full string extraction was deferred because the requested sample size exceeds the synchronous preview budget.',
              }),
            ],
          },
        })
      }

      // 3. Get sample path from workspace
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)

      // 4. Prepare worker request
      const workerRequest: WorkerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          scan_mode: input.mode,
          max_scan_bytes:
            input.mode === 'preview' ? input.max_scan_bytes || 1024 * 1024 : undefined,
          min_len: input.min_len,
          encoding: input.encoding,
          max_strings: input.max_strings,
          max_string_length: input.max_string_length,
          context_window_bytes: input.context_window_bytes,
          max_context_windows: input.max_context_windows,
          category_filter: input.category_filter,
        },
        toolVersion: TOOL_VERSION,
      })

      // 5. Call Static Worker
      // Requirements: 4.1, 4.2, 4.3
      const workerResponse = await callPooledStaticWorker(workerRequest, {
        database,
        family: input.mode === 'full' ? 'static_python.full' : 'static_python.preview',
      })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
        }
      }

      let normalizedData = normalizeStringsExtractData(workerResponse.data, input)
      const artifacts = [...((workerResponse.artifacts as ArtifactRef[] | undefined) || [])]
      const chunkWarnings: string[] = []

      const extractedStrings = Array.isArray(normalizedData.strings)
        ? (normalizedData.strings as Array<Record<string, unknown>>)
        : []
      if (
        input.mode === 'full' &&
        extractedStrings.length > chooseInlineStringsLimit(sampleSizeTier)
      ) {
        const chunked = await persistChunkedArrayArtifacts(extractedStrings, {
          family: 'strings',
          inlineLimit: chooseInlineStringsLimit(sampleSizeTier),
          chunkSize: STRING_CHUNK_SIZE,
          notes: [
            'Large-sample full strings were bounded inline and persisted as chunk artifacts.',
          ],
          buildLabel: (index, itemCount) => `strings chunk ${index + 1} (${itemCount} strings)`,
          persistChunk: async ({ index, itemCount, items }) =>
            persistStringXrefJsonArtifact(
              workspaceManager,
              database,
              input.sample_id,
              ENRICHED_STRING_ANALYSIS_ARTIFACT_TYPE,
              `enriched_strings_chunk_${String(index + 1).padStart(3, '0')}`,
              {
                sample_id: input.sample_id,
                session_tag: input.session_tag || null,
                tool: TOOL_NAME,
                created_at: new Date().toISOString(),
                chunk_index: index,
                chunk_item_count: itemCount,
                total_items: extractedStrings.length,
                data: {
                  strings: items,
                },
              },
              input.session_tag
            ),
        })
        if (chunked.manifest) {
          normalizedData = {
            ...normalizedData,
            strings: chunked.inline_items,
            chunk_manifest: chunked.manifest,
          }
          artifacts.push(...chunked.chunk_artifacts)
          chunkWarnings.push(
            `Bounded full strings inline payload to ${chunked.inline_items.length} strings and persisted ${chunked.chunk_artifacts.length} chunk artifact(s).`
          )
        }
      }

      const resultWarnings = input.force_refresh
        ? [
            'force_refresh=true; bypassed cache lookup',
            ...(workerResponse.warnings || []),
            ...chunkWarnings,
          ]
        : [...(workerResponse.warnings || []), ...chunkWarnings]
      const structured = buildStructuredHandoff({
        sampleId: input.sample_id,
        data: normalizedData,
        input,
        warningCount: resultWarnings.length,
        backendStarted: true,
      })
      const resultData = {
        ...normalizedData,
        evidence_summary: structured.evidenceSummary,
        workflow_handoff: structured.workflowHandoff,
        quality_gates: structured.qualityGates,
        recommended_next_tools: structured.recommendedNextTools,
        next_actions: structured.nextActions,
      }

      if (input.persist_artifact !== false) {
        const artifact = await persistStringXrefJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          ENRICHED_STRING_ANALYSIS_ARTIFACT_TYPE,
          'enriched_strings',
          {
            sample_id: input.sample_id,
            session_tag: input.session_tag || null,
            tool: TOOL_NAME,
            created_at: new Date().toISOString(),
            input: {
              min_len: input.min_len,
              encoding: input.encoding,
              max_strings: input.max_strings,
              category_filter: input.category_filter,
            },
            data: resultData,
          },
          input.session_tag
        )
        artifacts.push(artifact)
      }

      // 6. Cache result
      await cacheManager.setCachedResult(cacheKey, resultData, CACHE_TTL_MS, sample.sha256)
      persistCanonicalEvidence(database, {
        sample,
        evidenceFamily: 'strings',
        backend: TOOL_NAME,
        mode: input.mode,
        args: {
          min_len: input.min_len,
          encoding: input.encoding,
          max_strings: input.max_strings,
          max_string_length: input.max_string_length,
          max_scan_bytes: input.max_scan_bytes,
          context_window_bytes: input.context_window_bytes,
          max_context_windows: input.max_context_windows,
          category_filter: input.category_filter,
          enrich_result: input.enrich_result,
        },
        result: resultData,
        artifactRefs: artifacts,
        metadata: {
          session_tag: input.session_tag || null,
          cache_key: cacheKey,
          sample_size_tier: sampleSizeTier,
          ...(normalizedData.chunk_manifest
            ? { chunk_manifest: normalizedData.chunk_manifest }
            : {}),
        },
        provenance: {
          tool: TOOL_NAME,
          tool_version: TOOL_VERSION,
          precedence: ['analysis_run_stage', 'analysis_evidence', 'artifact', 'cache'],
        },
      })

      // 7. Return result
      return {
        ok: true,
        data: {
          status: 'ready',
          sample_id: input.sample_id,
          result_mode: input.mode,
          execution_state: 'completed',
          worker_pool: workerResponse.metrics?.worker_pool,
          evidence_state: [
            buildFreshEvidenceState({
              evidenceFamily: 'strings',
              backend: TOOL_NAME,
              mode: input.mode,
            }),
          ],
          ...resultData,
        },
        warnings: resultWarnings,
        errors: workerResponse.errors,
        artifacts,
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
