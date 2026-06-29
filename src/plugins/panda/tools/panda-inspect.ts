/**
 * PANDA inspect tool - inspect PANDA/pandare runtime readiness.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from '../../docker-shared.js'
import {
  BackendSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  normalizeError,
  runPythonJson,
  buildMetrics,
  buildDynamicSetupRequired,
  resolveAnalysisBackends,
} from '../../docker-shared.js'

export const pandaInspectInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe(
      'Optional sample identifier for context; PANDA inspect itself does not execute the sample.'
    ),
  timeout_sec: z
    .number()
    .int()
    .min(1)
    .max(30)
    .default(15)
    .describe('Backend probe timeout in seconds.'),
})

export const pandaInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      result_mode: z.literal('panda_readiness_profile').optional(),
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().nullable().optional(),
      readiness: z.record(z.string(), z.any()).optional(),
      policy: z.record(z.string(), z.any()).optional(),
      execution_semantics: z.record(z.string(), z.any()).optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
      details: z.record(z.string(), z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const PANDA_INSPECT_ARTIFACT_TYPE = 'panda_readiness_profile'

export const PANDA_INSPECT_FORMATS = [
  'pe',
  'elf',
  'macho',
  'firmware',
  'memory-image',
  'recording',
  'replay',
]

export const PANDA_INSPECT_PLATFORMS = ['windows', 'linux', 'macos', 'embedded']
export const PANDA_INSPECT_ARCHITECTURES = ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel']

export const PANDA_INSPECT_SAFETY = [
  'passive',
  'opt_in_dynamic',
  'requires_isolation',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_sample_execution_by_default',
  'backend_readiness_probe_only',
]

export const PANDA_INSPECT_CAPABILITIES = [
  'readiness',
  'readiness-profile',
  'record-replay-plan',
  'taint-analysis-plan',
  'dynamic-tracing-plan',
  'backend-profile',
  'runtime-plan',
  'workflow-plan',
  'workflow-handoff',
]

export const PANDA_INSPECT_EVIDENCE = [
  'runtime-readiness',
  'backend',
  'record-replay',
  'trace',
  'timeline',
  'workflow',
  'provenance',
]

export const PANDA_INSPECT_RECOMMENDED_NEXT_TOOLS = [
  'dynamic.dependencies',
  'dynamic.runtime.status',
  'dynamic.toolkit.status',
  'tool.readiness',
  'analysis.evidence.graph',
]

export const PANDA_INSPECT_RUNTIME_POLICY: ToolDefinition['runtimePolicy'] = {
  passiveByDefault: true,
  requiresUserOptIn: true,
  requiresIsolation: true,
  allowedBackends: ['docker'],
  maxRuntimeMs: 120_000,
  networkPolicy: 'disabled',
  notes: [
    'panda.inspect is a readiness/profile planner; it probes PANDA Python bindings only.',
    'PANDA and pandare are analysis engine profiles, while allowedBackends names the isolation carrier used to run Python tooling.',
    'It must not start a guest, replay trace assets, instrument memory, or execute sample code by default.',
    'Full PANDA record/replay analysis requires a separate opt-in runtime plan, guest image, replay assets, and isolation boundary.',
  ],
}

export const PANDA_INSPECT_WORKFLOW_RECIPES = [
  {
    id: 'panda.runtime-readiness-profile',
    title: 'PANDA runtime readiness profile',
    description:
      'Build a passive PANDA/pandare readiness profile and hand off record/replay prerequisites without starting a guest, replay, instrumentation, network, or sample execution.',
    startsWith: ['panda.inspect'],
    nextTools: PANDA_INSPECT_RECOMMENDED_NEXT_TOOLS,
    requiredArtifacts: [],
    evidence: PANDA_INSPECT_EVIDENCE,
    safety: PANDA_INSPECT_SAFETY,
    runtimeBackends: ['panda', 'pandare', 'qemu'],
  },
]

export const pandaInspectToolDefinition: ToolDefinition = {
  name: 'panda.inspect',
  description:
    'Inspect PANDA/pandare runtime readiness and record/replay caveats. Use this when you explicitly request PANDA-oriented dynamic analysis support from the MCP server.',
  inputSchema: pandaInspectInputSchema,
  outputSchema: pandaInspectOutputSchema,
  aspects: {
    formats: PANDA_INSPECT_FORMATS,
    platforms: PANDA_INSPECT_PLATFORMS,
    architectures: PANDA_INSPECT_ARCHITECTURES,
    execution: ['dynamic', 'triage'],
    runtimes: ['panda', 'pandare', 'qemu'],
    safety: PANDA_INSPECT_SAFETY,
    capabilities: PANDA_INSPECT_CAPABILITIES,
    evidence: PANDA_INSPECT_EVIDENCE,
    search: [
      'panda',
      'pandare',
      'qemu record replay',
      'record replay readiness',
      'dynamic trace readiness',
      'taint analysis plan',
      'guest image prerequisite',
    ],
    profile: [
      'panda-readiness-profile',
      'record-replay-profile',
      'backend-readiness-probe',
      'passive-runtime-profile',
      'guest-image-handoff',
    ],
    route_terms: [
      'panda_readiness_profile',
      'record_replay_handoff',
      'taint_analysis_plan',
      'guest_image_prerequisite',
      'backend_readiness_probe_only',
    ],
  },
  evidence: [
    { category: 'runtime-readiness' },
    { category: 'backend' },
    { category: 'record-replay' },
    { category: 'workflow' },
    { category: 'provenance' },
  ],
  workflowRecipes: PANDA_INSPECT_WORKFLOW_RECIPES,
  runtimePolicy: PANDA_INSPECT_RUNTIME_POLICY,
  runtime: { type: 'inline', handler: 'executePandaInspect' },
}

const PANDA_INSPECT_SCRIPT = `
import json
import sys
import pandare

print(json.dumps({
    "pandare_version": getattr(pandare, "__version__", None),
    "module": "pandare",
    "note": "PANDA support is installed, but full record/replay workflows still require guest images and trace assets.",
}, ensure_ascii=False))
`.trim()

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : []
}

function buildPandaReadiness(params: { backendAvailable: boolean; details?: unknown }) {
  const details = asRecord(params.details)
  return {
    backend_available: params.backendAvailable,
    pandare_available: params.backendAvailable,
    pandare_version: typeof details.pandare_version === 'string' ? details.pandare_version : null,
    guest_image_configured: false,
    replay_assets_configured: false,
    trace_plugins_configured: false,
  }
}

function enrichPandaInspectResult(
  result: WorkerResult,
  context: {
    sampleId?: string | null
    backendProbeAttempted?: boolean
    backendProbeSucceeded?: boolean
    details?: unknown
  } = {}
): WorkerResult {
  const data = asRecord(result.data)
  const backend = asRecord(data.backend)
  const backendAvailable =
    typeof backend.available === 'boolean'
      ? backend.available
      : Boolean(context.backendProbeSucceeded)
  const backendProbeAttempted = Boolean(context.backendProbeAttempted)
  const backendProbeSucceeded = Boolean(context.backendProbeSucceeded)
  const details = context.details ?? data.details
  const readiness = buildPandaReadiness({ backendAvailable, details })
  const recommendedNextTools = PANDA_INSPECT_RECOMMENDED_NEXT_TOOLS
  const nextActions = backendAvailable
    ? [
        'Use dynamic.runtime.status or dynamic.toolkit.status to verify the isolated runtime carrier before any PANDA replay work.',
        'Prepare guest images, replay assets, and PANDA plugins outside this readiness probe before opting into record/replay analysis.',
      ]
    : [
        'Install or configure the PANDA/pandare Python backend, then re-run panda.inspect as a passive readiness probe.',
        'Use dynamic.dependencies and runtime setup guidance before any record/replay workflow.',
      ]

  return {
    ...result,
    data: {
      ...data,
      result_mode: PANDA_INSPECT_ARTIFACT_TYPE,
      status: backendAvailable ? 'ready' : 'setup_required',
      sample_id: context.sampleId ?? data.sample_id ?? null,
      readiness,
      policy: {
        passive: true,
        readiness_probe_only: true,
        probe_requires_user_opt_in: false,
        probe_requires_isolation: false,
        record_replay_requires_user_opt_in: true,
        record_replay_requires_isolation: true,
        no_execute: true,
        no_sample_execution: true,
        no_guest_started: true,
        no_replay_started: true,
        no_instrumentation_started: true,
        no_network: true,
        network_policy: 'disabled',
      },
      execution_semantics: {
        readiness_probe: 'passive',
        requested_mode: 'panda_readiness_probe',
        actual_mode: 'plan_only',
        backend: 'panda',
        live_execution: false,
        sample_executed_by_tool: false,
        guest_started_by_tool: false,
        replay_started_by_tool: false,
        instrumentation_started_by_tool: false,
        runtime_started_by_tool: false,
        backend_probe_started: backendProbeSucceeded,
        backend_probe_attempted: backendProbeAttempted,
        backend_probe_succeeded: backendProbeSucceeded,
        network_accessed_by_tool: false,
      },
      evidence_summary: {
        schema: 'rikune.panda_inspect.evidence_summary.v1',
        source_tool: 'panda.inspect',
        profile_type: PANDA_INSPECT_ARTIFACT_TYPE,
        artifact_type: PANDA_INSPECT_ARTIFACT_TYPE,
        artifact_persisted: false,
        sample_id: context.sampleId ?? data.sample_id ?? null,
        backend_available: readiness.backend_available,
        pandare_available: readiness.pandare_available,
        pandare_version: readiness.pandare_version,
        readiness_probe_only: true,
        route_terms: [
          'panda_readiness_profile',
          'record_replay_handoff',
          'backend_readiness_probe_only',
        ],
        sample_executed_by_tool: false,
        guest_started_by_tool: false,
        replay_started_by_tool: false,
        instrumentation_started_by_tool: false,
      },
      workflow_handoff: {
        schema: 'rikune.panda_inspect.workflow_handoff.v1',
        handoff_mode: 'panda_readiness_to_record_replay_planning',
        profile_type: PANDA_INSPECT_ARTIFACT_TYPE,
        artifact_type: PANDA_INSPECT_ARTIFACT_TYPE,
        artifact_persisted: false,
        recommended_next_tools: recommendedNextTools,
        artifact_contract: {
          consumes: ['sample', 'PANDA Python backend configuration'],
          produces: [],
          expected_consumers: [
            'workflow.search',
            'dynamic.runtime.status',
            'dynamic.toolkit.status',
          ],
        },
        routing: [
          {
            goal: 'panda-backend-readiness',
            priority: backendAvailable ? 'high' : 'blocked',
            route_terms: ['panda_readiness_profile', 'backend_readiness_probe_only'],
            consumes: [PANDA_INSPECT_ARTIFACT_TYPE],
            produces: ['runtime_readiness_profile'],
            next_tools: ['dynamic.dependencies', 'dynamic.runtime.status', 'tool.readiness'],
          },
          {
            goal: 'opt-in-record-replay-planning',
            priority: backendAvailable ? 'medium' : 'blocked',
            route_terms: ['record_replay_handoff', 'guest_image_prerequisite'],
            consumes: [PANDA_INSPECT_ARTIFACT_TYPE],
            produces: ['runtime_session_plan'],
            next_tools: ['dynamic.toolkit.status', 'analysis.evidence.graph'],
            blocking_conditions: [
              'Guest images, replay assets, and PANDA plugins are external prerequisites and are not started by panda.inspect.',
            ],
          },
        ],
        dynamic_boundary: {
          sample_executed_by_tool: false,
          guest_started_by_tool: false,
          replay_started_by_tool: false,
          instrumentation_started_by_tool: false,
          runtime_started_by_tool: false,
          network_accessed_by_tool: false,
          mutation_performed: false,
        },
      },
      quality_gates: {
        schema: 'rikune.panda_inspect.quality_gates.v1',
        readiness_probe_only: true,
        backend_available: readiness.backend_available,
        backend_probe_started: backendProbeSucceeded,
        backend_probe_attempted: backendProbeAttempted,
        backend_probe_succeeded: backendProbeSucceeded,
        artifact_persisted: false,
        guest_image_configured: false,
        replay_assets_configured: false,
        trace_plugins_configured: false,
        network_disabled_by_default: true,
        sample_executed_by_tool: false,
        guest_started_by_tool: false,
        replay_started_by_tool: false,
        instrumentation_started_by_tool: false,
        runtime_started_by_tool: false,
        recommended_live_execution_tools: [],
      },
      recommended_next_tools: recommendedNextTools,
      next_actions: nextActions,
    },
    warnings: stringArray(result.warnings).length > 0 ? result.warnings : undefined,
  }
}

export function createPandaInspectHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    let backendProbeAttempted = false
    try {
      const input = pandaInspectInputSchema.parse(args)
      if (input.sample_id) {
        ensureSampleExists(database, input.sample_id)
      }
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.panda
      if (!backend.available || !backend.path) {
        return enrichPandaInspectResult(
          buildDynamicSetupRequired(backend, startTime, pandaInspectToolDefinition.name),
          {
            sampleId: input.sample_id ?? null,
            backendProbeAttempted: false,
            backendProbeSucceeded: false,
          }
        )
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      backendProbeAttempted = true
      const result = await runPythonImpl(
        backend.path,
        PANDA_INSPECT_SCRIPT,
        {},
        input.timeout_sec * 1000
      )

      return enrichPandaInspectResult(
        {
          ok: true,
          data: {
            status: 'ready',
            backend,
            sample_id: input.sample_id || null,
            details: result.parsed,
            summary:
              'PANDA bindings are available. Guest images and replay assets are still external prerequisites.',
            recommended_next_tools: PANDA_INSPECT_RECOMMENDED_NEXT_TOOLS,
            next_actions: [],
          },
          metrics: buildMetrics(startTime, pandaInspectToolDefinition.name),
        },
        {
          sampleId: input.sample_id ?? null,
          backendProbeAttempted,
          backendProbeSucceeded: true,
          details: result.parsed,
        }
      )
    } catch (error) {
      const parsedInput = pandaInspectInputSchema.safeParse(args)
      const message = normalizeError(error)
      return enrichPandaInspectResult(
        {
          ok: false,
          data: {
            status: 'setup_required',
            backend: {
              available: false,
              source: null,
              path: null,
              version: null,
              checked_candidates: [],
              error: message,
            },
            sample_id: parsedInput.success ? parsedInput.data.sample_id || null : null,
            summary: 'PANDA readiness probe failed before any sample execution or replay.',
            recommended_next_tools: PANDA_INSPECT_RECOMMENDED_NEXT_TOOLS,
            next_actions: [],
          },
          errors: [message],
          metrics: buildMetrics(startTime, pandaInspectToolDefinition.name),
        },
        {
          sampleId: parsedInput.success ? (parsedInput.data.sample_id ?? null) : null,
          backendProbeAttempted,
          backendProbeSucceeded: false,
        }
      )
    }
  }
}
