/**
 * Rizin analyze tool �?bounded Rizin inspection on a sample.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from '../../docker-shared.js'
import {
  randomUUID,
  ArtifactRefSchema,
  BackendSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  executeCommand,
  truncateText,
  normalizeError,
  safeJsonParse,
  persistBackendArtifact,
  buildMetrics,
  buildStaticSetupRequired,
  findBackendPreviewEvidence,
  persistBackendPreviewEvidence,
  buildEvidenceReuseWarnings,
  resolveSampleFile,
  resolveAnalysisBackends,
  getRuntimeWorkerPool,
  buildRizinPreviewCompatibilityKey,
  resolvePackagePath,
} from '../../docker-shared.js'

const TOOL_NAME = 'rizin.analyze'
const TOOL_VERSION = '0.2.0'
const RIZIN_OPERATIONS = [
  'info',
  'sections',
  'imports',
  'exports',
  'entrypoints',
  'functions',
  'strings',
] as const
const RIZIN_ARTIFACT_TYPES = RIZIN_OPERATIONS.map((operation) => `backend_rizin_${operation}`)
const RIZIN_RECOMMENDED_NEXT_TOOLS = ['artifact.read', 'workflow.search']
const RIZIN_PROFILE_NEXT_TOOLS = [
  'code.cross_decompiler.consensus',
  'analysis.evidence.graph',
  'report.generate',
]
const RIZIN_SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]

export const rizinAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  operation: z.enum(RIZIN_OPERATIONS).default('info').describe('Bounded Rizin inspection mode.'),
  max_items: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(25)
    .describe('Maximum preview items to return.'),
  timeout_sec: z
    .number()
    .int()
    .min(1)
    .max(180)
    .default(45)
    .describe('Rizin execution timeout in seconds.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist the raw JSON result as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const rizinAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      operation: z.string().optional(),
      item_count: z.number().int().nonnegative().optional(),
      preview: z.any().optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
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

export const rizinAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run bounded Rizin inspection on a sample for info, sections, imports, exports, entrypoints, functions, or strings. Use this when you explicitly want Rizin-backed inspection instead of the default workflow backends.',
  inputSchema: rizinAnalyzeInputSchema,
  outputSchema: rizinAnalyzeOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'ios', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc', 'riscv', 'wasm'],
    execution: ['static', 'triage'],
    runtimes: ['rizin'],
    safety: RIZIN_SAFETY,
    capabilities: [
      'info',
      'sections',
      'imports',
      'exports',
      'entrypoints',
      'functions',
      'strings',
      'cross-backend-corroboration',
      'workflow-handoff',
    ],
    evidence: ['structure', 'symbols', 'imports', 'exports', 'strings', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'backend_rizin_info',
      description: 'Bounded Rizin binary info JSON preview',
    },
    {
      type: 'backend_rizin_sections',
      description: 'Bounded Rizin sections JSON preview',
    },
    {
      type: 'backend_rizin_imports',
      description: 'Bounded Rizin imports JSON preview',
    },
    {
      type: 'backend_rizin_exports',
      description: 'Bounded Rizin exports JSON preview',
    },
    {
      type: 'backend_rizin_entrypoints',
      description: 'Bounded Rizin entrypoints JSON preview',
    },
    {
      type: 'backend_rizin_functions',
      description: 'Bounded Rizin functions JSON preview',
    },
    {
      type: 'backend_rizin_strings',
      description: 'Bounded Rizin strings JSON preview',
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: ['backend_rizin_info', 'backend_rizin_sections', 'backend_rizin_entrypoints'],
    },
    {
      category: 'symbols',
      artifactTypes: ['backend_rizin_functions'],
    },
    {
      category: 'imports',
      artifactTypes: ['backend_rizin_imports'],
    },
    {
      category: 'exports',
      artifactTypes: ['backend_rizin_exports'],
    },
    {
      category: 'strings',
      artifactTypes: ['backend_rizin_strings'],
    },
  ],
  workflowRecipes: [
    {
      id: 'rizin.readonly-preview',
      title: 'Rizin read-only backend preview',
      description:
        'Run a bounded Rizin read-only inspection, then hand off preview artifacts to artifact review, cross-decompiler consensus, evidence graph, and reporting.',
      startsWith: [TOOL_NAME],
      nextTools: [...RIZIN_RECOMMENDED_NEXT_TOOLS, ...RIZIN_PROFILE_NEXT_TOOLS],
      requiredArtifacts: ['sample'],
      producesArtifacts: RIZIN_ARTIFACT_TYPES,
      evidence: ['structure', 'symbols', 'imports', 'exports', 'strings', 'workflow', 'provenance'],
      safety: RIZIN_SAFETY,
      runtimeBackends: ['rizin'],
      operations: RIZIN_OPERATIONS,
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: false,
    allowedBackends: ['local'],
    maxRuntimeMs: 180000,
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'Rizin is used as a bounded read-only static backend and must not execute the sample.',
      'workflow.search should activate only rizin.analyze for this profile before any broader cross-backend workflow.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'rizin',
    backendKind: 'external',
    adapter: 'rizin.readonly.preview',
    availability: 'optional',
    envVar: 'RIZIN_PATH',
    commandHint: 'rizin -A -q0 -c "<command>;q" <sample>',
    versionHint: 'rizin -v',
    supportedModes: [...RIZIN_OPERATIONS],
    defaultMode: 'info',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: RIZIN_ARTIFACT_TYPES,
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 45000,
      maxOutputBytes: 16 * 1024 * 1024,
      notes: ['Only bounded JSON preview commands are used by this tool.'],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: ['Set RIZIN_PATH to a pinned Rizin binary or install rizin on PATH.'],
      missingBackendBehavior: 'Return setup_required without running any backend command.',
    },
    packaging: {
      installRoute: 'profile-gated',
      installProfile: 'optional',
      dockerFeature: 'rizin',
      envVar: 'RIZIN_PATH',
      dockerDefault: '/opt/rizin/bin/rizin',
    },
  },
}

function getRizinCommand(operation: z.infer<typeof rizinAnalyzeInputSchema>['operation']): string {
  switch (operation) {
    case 'sections':
      return 'iSj'
    case 'imports':
      return 'iij'
    case 'exports':
      return 'iEj'
    case 'entrypoints':
      return 'iej'
    case 'functions':
      return 'aaa;aflj'
    case 'strings':
      return 'izj'
    case 'info':
    default:
      return 'ij'
  }
}

function rizinArtifactType(operation: z.infer<typeof rizinAnalyzeInputSchema>['operation']) {
  return `backend_rizin_${operation}`
}

function buildRizinEvidenceSummary(args: {
  sampleId: string
  operation: z.infer<typeof rizinAnalyzeInputSchema>['operation']
  itemCount: number
  preview: unknown
  artifact?: ArtifactRef
}) {
  return {
    schema: 'rikune.rizin_preview.evidence_summary.v1',
    source_tool: TOOL_NAME,
    tool_version: TOOL_VERSION,
    artifact_type: rizinArtifactType(args.operation),
    sample_id: args.sampleId,
    operation: args.operation,
    item_count: args.itemCount,
    preview_kind: Array.isArray(args.preview) ? 'array' : typeof args.preview,
    artifact_id: args.artifact?.id ?? null,
  }
}

function buildRizinQualityGates(args: {
  operation: z.infer<typeof rizinAnalyzeInputSchema>['operation']
  itemCount: number
  artifactPersisted: boolean
}) {
  return {
    schema: 'rikune.rizin_preview.quality_gates.v1',
    passive_static_analysis: true,
    read_only_backend: true,
    sample_executed_by_tool: false,
    backend_started_with_bounded_command: true,
    network_accessed_by_tool: false,
    mutation_performed: false,
    output_bounded_inline: true,
    artifact_persisted: args.artifactPersisted,
    analyst_review_required: true,
    operation: args.operation,
    item_count: args.itemCount,
  }
}

function buildRizinWorkflowHandoff(args: {
  sampleId: string
  operation: z.infer<typeof rizinAnalyzeInputSchema>['operation']
  itemCount: number
  artifact?: ArtifactRef
}) {
  return {
    schema: 'rikune.rizin_preview.workflow_handoff.v1',
    handoff_mode: 'rizin_preview_to_cross_backend_review',
    artifact_type: rizinArtifactType(args.operation),
    sample_id: args.sampleId,
    operation: args.operation,
    recommended_next_tools: RIZIN_RECOMMENDED_NEXT_TOOLS,
    artifact_contract: {
      type: rizinArtifactType(args.operation),
      suggested_read_mode: 'profile',
      artifact_id: args.artifact?.id ?? null,
      item_count: args.itemCount,
    },
    routing: [
      {
        goal: 'review-rizin-preview',
        priority: 'high',
        next_tools: ['artifact.read'],
        required_evidence: [rizinArtifactType(args.operation)],
      },
      {
        goal: 'cross-backend-corroboration',
        priority:
          args.operation === 'functions' || args.operation === 'imports' ? 'high' : 'normal',
        next_tools: ['code.cross_decompiler.consensus', 'analysis.evidence.graph'],
        required_evidence: [rizinArtifactType(args.operation), 'paired backend artifacts'],
      },
      {
        goal: 'report-rizin-findings',
        priority: 'normal',
        next_tools: ['report.generate'],
        required_evidence: [rizinArtifactType(args.operation)],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: true,
      backend_kind: 'external-static',
      live_execution_started: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildRizinNextActions(args: {
  operation: z.infer<typeof rizinAnalyzeInputSchema>['operation']
  artifact?: ArtifactRef
}) {
  return [
    args.artifact
      ? 'Use artifact.read in profile mode to inspect the persisted Rizin preview envelope.'
      : 'Persist a Rizin preview artifact before relying on this result for cross-backend review.',
    'Use workflow.search to select a result-scoped cross-backend or evidence graph follow-up instead of exposing broad reverse-engineering tools.',
    args.operation === 'functions'
      ? 'Corroborate Rizin function boundaries with Ghidra, radare2, or another backend before reconstruction.'
      : 'Corroborate this Rizin preview with a format-specific static analyzer before reporting.',
  ]
}

export function createRizinAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = rizinAnalyzeInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      const evidenceArgs = {
        operation: input.operation,
        max_items: input.max_items,
      }
      const reused = findBackendPreviewEvidence(
        database,
        sample,
        'rizin',
        input.operation,
        evidenceArgs
      )
      if (reused) {
        return {
          ok: true,
          data: reused.result as Record<string, unknown>,
          warnings: buildEvidenceReuseWarnings({
            source: 'analysis_evidence',
            record: reused,
          }),
          artifacts: reused.artifact_refs,
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.rizin
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, rizinAnalyzeToolDefinition.name)
      }

      const command = getRizinCommand(input.operation)
      const pooledResult = !dependencies?.executeCommand
        ? await getRuntimeWorkerPool().executeHelperWorker(
            {
              job_id: randomUUID(),
              backend_path: backend.path,
              sample_path: samplePath,
              command,
              timeout_ms: input.timeout_sec * 1000,
            },
            {
              database,
              family: 'rizin.preview',
              compatibilityKey: buildRizinPreviewCompatibilityKey({
                backendPath: backend.path,
                backendVersion: backend.version,
                operation: input.operation,
                helperPath: resolvePackagePath('workers', 'rizin_preview_worker.py'),
              }),
              timeoutMs: input.timeout_sec * 1000,
              spawnConfig: {
                command: process.platform === 'win32' ? 'python' : 'python3',
                args: [resolvePackagePath('workers', 'rizin_preview_worker.py')],
              },
            }
          )
        : null
      const commandResult = dependencies?.executeCommand
        ? await dependencies.executeCommand(
            backend.path,
            ['-A', '-q0', '-c', `${command};q`, samplePath],
            input.timeout_sec * 1000
          )
        : null

      const effectiveResult = pooledResult
        ? {
            stdout:
              typeof pooledResult.response.data === 'object' &&
              pooledResult.response.data &&
              typeof (pooledResult.response.data as Record<string, unknown>).stdout === 'string'
                ? String((pooledResult.response.data as Record<string, unknown>).stdout)
                : '',
            stderr:
              typeof pooledResult.response.data === 'object' &&
              pooledResult.response.data &&
              typeof (pooledResult.response.data as Record<string, unknown>).stderr === 'string'
                ? String((pooledResult.response.data as Record<string, unknown>).stderr)
                : '',
            exitCode:
              typeof pooledResult.response.data === 'object' &&
              pooledResult.response.data &&
              typeof (pooledResult.response.data as Record<string, unknown>).exit_code === 'number'
                ? Number((pooledResult.response.data as Record<string, unknown>).exit_code)
                : pooledResult.response.ok
                  ? 0
                  : 1,
            timedOut:
              typeof pooledResult.response.data === 'object' &&
              pooledResult.response.data &&
              typeof (pooledResult.response.data as Record<string, unknown>).timed_out === 'boolean'
                ? Boolean((pooledResult.response.data as Record<string, unknown>).timed_out)
                : false,
          }
        : {
            stdout: commandResult?.stdout || '',
            stderr: commandResult?.stderr || '',
            exitCode: commandResult?.exitCode ?? 1,
            timedOut: commandResult?.timedOut ?? false,
          }

      if (pooledResult && !pooledResult.response.ok) {
        return {
          ok: false,
          errors:
            pooledResult.response.errors && pooledResult.response.errors.length > 0
              ? pooledResult.response.errors
              : ['Rizin pooled helper failed without returning a concrete error.'],
          warnings: pooledResult.response.warnings,
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      if (effectiveResult.exitCode !== 0) {
        return {
          ok: false,
          errors: [
            `Rizin exited with code ${effectiveResult.exitCode}`,
            effectiveResult.stderr || effectiveResult.stdout || 'No backend output was returned.',
          ],
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      const parsed = safeJsonParse<any>(effectiveResult.stdout.trim())
      let preview: unknown = parsed
      let itemCount = 0
      if (Array.isArray(parsed)) {
        itemCount = parsed.length
        preview = parsed.slice(0, input.max_items)
      } else if (parsed && typeof parsed === 'object') {
        const entries = Object.entries(parsed)
        itemCount = entries.length
        preview = Object.fromEntries(entries.slice(0, input.max_items))
      } else {
        const previewText = truncateText(effectiveResult.stdout.trim(), 3000)
        preview = {
          inline_text: previewText.text,
          truncated: previewText.truncated,
        }
      }

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      const baseOutputData = {
        schema: 'rikune.rizin_preview.v1',
        tool_version: TOOL_VERSION,
        status: 'ready',
        backend,
        sample_id: input.sample_id,
        operation: input.operation,
        item_count: itemCount,
        preview,
        worker_pool: pooledResult
          ? {
              family: pooledResult.lease.family,
              compatibility_key: pooledResult.lease.compatibility_key,
              deployment_key: pooledResult.lease.deployment_key,
              worker_id: pooledResult.lease.worker_id,
              pool_kind: pooledResult.lease.pool_kind,
              warm_reuse: pooledResult.lease.warm_reuse,
              cold_start: pooledResult.lease.cold_start,
            }
          : undefined,
        summary: `Rizin completed ${input.operation} inspection for ${input.sample_id}.`,
      } satisfies Record<string, unknown>

      if (input.persist_artifact) {
        const artifactPayload = {
          ...baseOutputData,
          evidence_summary: buildRizinEvidenceSummary({
            sampleId: input.sample_id,
            operation: input.operation,
            itemCount,
            preview,
          }),
          workflow_handoff: buildRizinWorkflowHandoff({
            sampleId: input.sample_id,
            operation: input.operation,
            itemCount,
          }),
          quality_gates: buildRizinQualityGates({
            operation: input.operation,
            itemCount,
            artifactPersisted: true,
          }),
          recommended_next_tools: RIZIN_RECOMMENDED_NEXT_TOOLS,
          next_actions: buildRizinNextActions({ operation: input.operation }),
          raw_rizin_result: parsed ?? { stdout: effectiveResult.stdout },
        }
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'rizin',
          input.operation,
          JSON.stringify(artifactPayload, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      const outputData = {
        ...baseOutputData,
        artifact,
        evidence_summary: buildRizinEvidenceSummary({
          sampleId: input.sample_id,
          operation: input.operation,
          itemCount,
          preview,
          artifact,
        }),
        workflow_handoff: buildRizinWorkflowHandoff({
          sampleId: input.sample_id,
          operation: input.operation,
          itemCount,
          artifact,
        }),
        quality_gates: buildRizinQualityGates({
          operation: input.operation,
          itemCount,
          artifactPersisted: Boolean(artifact),
        }),
        recommended_next_tools: RIZIN_RECOMMENDED_NEXT_TOOLS,
        next_actions: buildRizinNextActions({ operation: input.operation, artifact }),
      } satisfies Record<string, unknown>

      persistBackendPreviewEvidence(
        database,
        sample,
        'rizin',
        input.operation,
        evidenceArgs,
        outputData,
        artifacts,
        {
          backend_version: backend.version,
        }
      )

      return {
        ok: true,
        data: outputData,
        artifacts,
        metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
      }
    }
  }
}
