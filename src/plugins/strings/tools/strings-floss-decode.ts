/**
 * strings.floss.decode tool implementation
 * Uses FLOSS tool to decode obfuscated strings from PE files
 * Requirements: 4.4, 4.5
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import path from 'path'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { CacheManager } from '../../../cache-manager.js'
import type { JobQueue } from '../../../job-queue.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { resolvePackagePath } from '../../../runtime-paths.js'
import { lookupCachedResult, formatCacheWarning } from '../../../tools/cache-observability.js'
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
import { CACHE_TTL_30_DAYS } from '../../../constants/cache-ttl.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'

// ============================================================================
// Constants
// ============================================================================

const TOOL_NAME = 'strings.floss.decode'
const TOOL_VERSION = '1.0.0'
const CACHE_TTL_MS = CACHE_TTL_30_DAYS
const DEFAULT_TIMEOUT = 60 // seconds

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for strings.floss.decode tool
 * Requirements: 4.4, 4.5
 */
export const StringsFlossDecodeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout: z
    .number()
    .int()
    .min(1)
    .optional()
    .default(DEFAULT_TIMEOUT)
    .describe('Timeout in seconds (default: 60)'),
  modes: z
    .array(z.enum(['static', 'stack', 'tight', 'decoded']))
    .optional()
    .default(['decoded'])
    .describe('Decoding modes to use'),
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
      'When true, FLOSS decoding may be deferred to the background queue instead of blocking the MCP request.'
    ),
  enrich_result: z
    .boolean()
    .optional()
    .default(true)
    .describe('Attach analyst-oriented enriched string classification to decoded strings'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist decoded string intelligence as a JSON artifact for later reuse'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag used when persisting decoded string artifacts'),
})

export type StringsFlossDecodeInput = z.infer<typeof StringsFlossDecodeInputSchema>

/**
 * Output schema for strings.floss.decode tool
 * Requirements: 4.4, 4.5
 */
export const StringsFlossDecodeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'queued', 'partial']).optional(),
      sample_id: z.string().optional(),
      result_mode: z.enum(['full']).optional(),
      execution_state: z.enum(['inline', 'queued', 'partial', 'completed']).optional(),
      job_id: z.string().optional(),
      polling_guidance: z.any().optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      decoded_strings: z
        .array(
          z.object({
            string: z.string(),
            offset: z.number(),
            type: z.string(),
            decoding_method: z.string().nullable(),
          })
        )
        .optional(),
      count: z.number().optional(),
      timeout_occurred: z.boolean().optional(),
      partial_results: z.boolean().optional(),
      enriched: EnrichedStringBundleSchema.optional(),
      tooling: z.any().optional(),
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

export type StringsFlossDecodeOutput = z.infer<typeof StringsFlossDecodeOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for strings.floss.decode
 */
export const stringsFlossDecodeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decode obfuscated strings with FLOSS and return compact enriched analyst labels for decoded output. ' +
    'Use this when you suspect stack/tight/decoded strings; use analysis.context.link to merge FLOSS output with raw strings and function attribution.',
  inputSchema: StringsFlossDecodeInputSchema,
  outputSchema: StringsFlossDecodeOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'dotnet', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'external_static_backend',
      'no_live_sample_by_default',
      'no_network_by_default',
    ],
    capabilities: [
      'strings',
      'floss-decode',
      'obfuscation',
      'workflow-handoff',
      'evidence-correlation',
    ],
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
      description: 'Decoded and enriched FLOSS string output',
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
      id: 'strings.floss-decoded-evidence',
      title: 'Decoded string evidence to config and reporting handoff',
      startsWith: ['strings.floss.decode', 'strings.extract', 'analysis.context.link'],
      nextTools: [
        'analysis.context.link',
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
      safety: [
        'passive',
        'external_static_backend',
        'no_live_sample_by_default',
        'no_network_by_default',
      ],
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
      'FLOSS decoding is a static backend workflow and must not execute the sample.',
      'Missing FLARE-FLOSS readiness is surfaced through setup metadata only.',
    ],
  } as ToolDefinition['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'FLARE-FLOSS static decoder',
    backendKind: 'external',
    adapter: 'static_python.strings.floss.decode',
    availability: 'optional',
    envVar: 'FLOSS_PATH',
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
      defaultTimeoutMs: 60_000,
      notes: [
        'FLARE-FLOSS is used only as a read-only static decoder.',
        'Readiness probes must not spawn FLOSS or fall back to dynamic sample execution.',
      ],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Install FLARE-FLOSS in the static analysis environment.',
        'Set FLOSS_PATH to the floss command when using an external backend.',
        'Use strings.extract for raw string triage when FLOSS is unavailable.',
      ],
      missingBackendBehavior:
        'Report backend_missing/setup guidance through readiness metadata; do not start FLOSS from discovery/readiness and do not execute the sample.',
    },
    packaging: {
      installRoute: 'profile-gated',
      installProfile: 'optional',
      dockerFeature: 'static-python',
      envVar: 'FLOSS_PATH',
      dockerDefault: 'floss',
      notes: ['Enable the optional static-python profile to include FLARE-FLOSS.'],
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

function normalizeStringsFlossDecodeData(
  payload: unknown,
  input: StringsFlossDecodeInput
): Record<string, unknown> {
  const data =
    payload && typeof payload === 'object' ? { ...(payload as Record<string, unknown>) } : {}
  const decoded = Array.isArray(data.decoded_strings)
    ? data.decoded_strings
        .map((item) => {
          const entry = item && typeof item === 'object' ? (item as Record<string, unknown>) : {}
          if (typeof entry.string !== 'string') {
            return null
          }
          return {
            offset: Number(entry.offset || 0),
            string: entry.string,
            type: typeof entry.type === 'string' ? entry.type : null,
            decoding_method:
              typeof entry.decoding_method === 'string' ? entry.decoding_method : null,
          }
        })
        .filter(
          (
            item
          ): item is {
            offset: number
            string: string
            type: string | null
            decoding_method: string | null
          } => Boolean(item)
        )
    : []

  if (input.enrich_result !== false) {
    data.enriched = buildEnrichedStringBundle([], decoded, {
      maxRecords: 80,
      maxHighlights: 12,
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

function readNumber(value: unknown, fallback = 0): number {
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

function decodedStringCount(data: Record<string, unknown>): number {
  return asArray(data.decoded_strings).length || readNumber(data.count, 0)
}

function buildRecommendedNextTools(data: Record<string, unknown>): string[] {
  const enriched = enrichedBundle(data)
  const hasIocs = highlightValues(enriched, 'top_iocs', 1).length > 0
  const encodedCandidateCount = readNumber(enriched?.encoded_candidate_count, 0)
  const tools: string[] = [
    'analysis.context.link',
    'static.config.carver',
    'malware.intel.loop',
    'analysis.evidence.graph',
    'report.generate',
  ]
  if (hasIocs) {
    tools.push('ioc.export')
  }
  if (encodedCandidateCount > 0 || decodedStringCount(data) === 0) {
    tools.push('crypto.identify', 'unpack.workflow.plan')
  }
  return uniqueStrings(tools, 12)
}

function buildEvidenceSummary(args: {
  sampleId: string
  data: Record<string, unknown>
  warningCount: number
}) {
  const enriched = enrichedBundle(args.data)
  return {
    schema: 'rikune.strings_floss_decode.evidence_summary.v1',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    decoded_string_count: decodedStringCount(args.data),
    timeout_occurred: Boolean(args.data.timeout_occurred),
    partial_results: Boolean(args.data.partial_results),
    enriched_bundle_present: Boolean(enriched),
    analyst_relevant_count: readNumber(enriched?.analyst_relevant_count, 0),
    runtime_noise_count: readNumber(enriched?.runtime_noise_count, 0),
    encoded_candidate_count: readNumber(enriched?.encoded_candidate_count, 0),
    top_iocs: highlightValues(enriched, 'top_iocs'),
    top_suspicious: highlightValues(enriched, 'top_suspicious'),
    top_decoded: highlightValues(enriched, 'top_decoded'),
    warning_count: args.warningCount,
  }
}

function buildWorkflowHandoff(args: {
  sampleId: string
  data: Record<string, unknown>
  recommendedNextTools: string[]
  backendStarted: boolean
}) {
  const enriched = enrichedBundle(args.data)
  const hasIocs = highlightValues(enriched, 'top_iocs', 1).length > 0
  const encodedCandidateCount = readNumber(enriched?.encoded_candidate_count, 0)
  return {
    schema: 'rikune.strings_floss_decode.workflow_handoff.v1',
    handoff_mode: 'decoded_strings_to_config_ioc_and_reporting',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    recommended_next_tools: args.recommendedNextTools,
    decoded_string_context: {
      decoded_string_count: decodedStringCount(args.data),
      analyst_relevant_count: readNumber(enriched?.analyst_relevant_count, 0),
      encoded_candidate_count: encodedCandidateCount,
      top_iocs: highlightValues(enriched, 'top_iocs'),
      top_decoded: highlightValues(enriched, 'top_decoded'),
    },
    routing: [
      {
        goal: 'decoded-string-context-linking',
        priority: decodedStringCount(args.data) > 0 ? 'high' : 'optional',
        next_tools: ['analysis.context.link', 'code.xrefs.analyze'],
        required_evidence: ['enriched_string_analysis'],
      },
      {
        goal: 'ioc-and-config-carving',
        priority: hasIocs ? 'high' : 'normal',
        next_tools: ['static.config.carver', 'ioc.export', 'malware.intel.loop'],
        required_evidence: ['decoded strings', 'enriched_string_analysis'],
      },
      {
        goal: 'encoded-string-followup',
        priority: encodedCandidateCount > 0 ? 'normal' : 'optional',
        next_tools: ['crypto.identify', 'unpack.workflow.plan', 'strings.extract'],
        required_evidence: ['encoded string candidates', 'enriched_string_analysis'],
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

function buildQualityGates(args: { data: Record<string, unknown>; backendStarted: boolean }) {
  const enriched = enrichedBundle(args.data)
  const decodedCount = decodedStringCount(args.data)
  const iocCount = highlightValues(enriched, 'top_iocs', 12).length
  const encodedCandidateCount = readNumber(enriched?.encoded_candidate_count, 0)
  return {
    passive_static_decode: true,
    static_backend_started: args.backendStarted,
    runtime_started_by_tool: false,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    decoded_strings_present: decodedCount > 0,
    enriched_bundle_present: Boolean(enriched),
    ioc_handoff_ready: iocCount > 0,
    config_handoff_ready: iocCount > 0 || encodedCandidateCount > 0,
    evidence_graph_handoff_ready: true,
    timeout_occurred: Boolean(args.data.timeout_occurred),
    partial_results: Boolean(args.data.partial_results),
    runtime_followup_requires_opt_in: true,
    analyst_review_required:
      decodedCount > 0 ||
      iocCount > 0 ||
      encodedCandidateCount > 0 ||
      Boolean(args.data.partial_results),
  }
}

function buildNextActions(args: {
  data: Record<string, unknown>
  recommendedNextTools: string[]
}): string[] {
  const actions = [
    'Run analysis.context.link to merge decoded FLOSS strings with raw strings and function context.',
    'Run analysis.evidence.graph to correlate decoded string evidence with other plugin artifacts.',
  ]
  if (args.recommendedNextTools.includes('ioc.export')) {
    actions.push('Export high-confidence decoded-string IOCs with ioc.export.')
  }
  if (args.recommendedNextTools.includes('crypto.identify')) {
    actions.push(
      'Use crypto.identify or unpack.workflow.plan for encoded or packed string follow-up.'
    )
  }
  if (decodedStringCount(args.data) === 0) {
    actions.push(
      'If decoded strings are empty, collect runtime memory or unpacked payload evidence before rerunning FLOSS.'
    )
  }
  return actions
}

function buildStructuredHandoff(args: {
  sampleId: string
  data: Record<string, unknown>
  warningCount: number
  backendStarted: boolean
}) {
  const recommendedNextTools = buildRecommendedNextTools(args.data)
  return {
    evidenceSummary: buildEvidenceSummary({
      sampleId: args.sampleId,
      data: args.data,
      warningCount: args.warningCount,
    }),
    workflowHandoff: buildWorkflowHandoff({
      sampleId: args.sampleId,
      data: args.data,
      recommendedNextTools,
      backendStarted: args.backendStarted,
    }),
    qualityGates: buildQualityGates({
      data: args.data,
      backendStarted: args.backendStarted,
    }),
    recommendedNextTools,
    nextActions: buildNextActions({
      data: args.data,
      recommendedNextTools,
    }),
  }
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create strings.floss.decode tool handler
 * Requirements: 4.4, 4.5
 */
export function createStringsFlossDecodeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  jobQueue?: JobQueue,
  options: { allowDeferred?: boolean } = {}
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = StringsFlossDecodeInputSchema.parse(args)
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

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          timeout: input.timeout,
          modes: input.modes,
          enrich_result: input.enrich_result,
        },
      })

      // 2. Check cache
      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          const normalizedCachedData = normalizeStringsFlossDecodeData(cachedLookup.data, input)
          const warnings = ['Result from cache', formatCacheWarning(cachedLookup.metadata)]
          const structured = buildStructuredHandoff({
            sampleId: input.sample_id,
            data: normalizedCachedData,
            warningCount: warnings.length,
            backendStarted: false,
          })
          return {
            ok: true,
            data: {
              status: 'ready',
              sample_id: input.sample_id,
              result_mode: 'full',
              execution_state: 'completed',
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

      if (
        input.defer_if_slow !== false &&
        jobQueue &&
        options.allowDeferred !== false &&
        shouldDeferLargeSample(sample, 'full')
      ) {
        return buildDeferredToolResponse({
          jobQueue,
          tool: TOOL_NAME,
          sampleId: input.sample_id,
          args: {
            ...input,
            defer_if_slow: false,
          },
          timeoutMs: Math.max(input.timeout * 1000, 5 * 60 * 1000),
          summary:
            'FLOSS decoding was deferred because full decode passes are expensive on medium or larger samples.',
          nextTools: ['task.status', 'analysis.context.link'],
          nextActions: [
            'Poll task.status with the returned job_id instead of rerunning FLOSS immediately.',
            'If you only need a first-pass string view, use strings.extract(mode=preview) before decoding.',
          ],
        })
      }

      // 3. Get sample path from workspace
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

      // 4. Prepare worker request
      const workerRequest: WorkerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          timeout: input.timeout,
          modes: input.modes,
        },
        toolVersion: TOOL_VERSION,
      })

      // 5. Call Static Worker
      // Requirements: 4.4, 4.5
      const workerResponse = await callPooledStaticWorker(workerRequest, {
        database,
        family: 'static_python.full',
      })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
        }
      }

      const normalizedData = normalizeStringsFlossDecodeData(workerResponse.data, input)
      const artifacts = [...((workerResponse.artifacts as ArtifactRef[] | undefined) || [])]
      const warnings: string[] = []
      if (input.force_refresh) {
        warnings.push('force_refresh=true; bypassed cache lookup')
      }
      if (workerResponse.warnings) {
        warnings.push(...workerResponse.warnings)
      }
      const decodedStrings = normalizedData.decoded_strings
      if (Array.isArray(decodedStrings) && decodedStrings.length === 0) {
        warnings.push(
          'FLOSS decoded 0 strings. This is expected for samples protected by strong obfuscators ' +
            '(e.g. .NET Reactor, Themida, VMProtect) where string decoding requires runtime execution. ' +
            'Consider using a debugger or memory dump approach instead.'
        )
      }
      const structured = buildStructuredHandoff({
        sampleId: input.sample_id,
        data: normalizedData,
        warningCount: warnings.length,
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
          'decoded_strings',
          {
            sample_id: input.sample_id,
            session_tag: input.session_tag || null,
            tool: TOOL_NAME,
            created_at: new Date().toISOString(),
            input: {
              timeout: input.timeout,
              modes: input.modes,
            },
            data: resultData,
          },
          input.session_tag
        )
        artifacts.push(artifact)
      }

      // 6. Cache result (only if not timeout or partial)
      const responseData = normalizedData as {
        timeout_occurred?: boolean
        partial_results?: boolean
      }
      if (!responseData.timeout_occurred && !responseData.partial_results) {
        await cacheManager.setCachedResult(cacheKey, normalizedData, CACHE_TTL_MS, sample.sha256)
      }

      // 8. Return result
      return {
        ok: true,
        data: {
          status: 'ready',
          sample_id: input.sample_id,
          result_mode: 'full',
          execution_state: 'completed',
          ...resultData,
          worker_pool: workerResponse.metrics?.worker_pool,
        },
        warnings: warnings.length > 0 ? warnings : undefined,
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
