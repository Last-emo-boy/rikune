import type { ToolDefinition, WorkerResult } from '../../types.js'

export const QILING_INSPECT_ARTIFACT_TYPE = 'qiling_readiness_profile'

export const QILING_INSPECT_FORMATS = [
  'elf',
  'elf-executable',
  'so',
  'pe',
  'macho',
  'shellcode',
  'firmware',
]

export const QILING_INSPECT_PLATFORMS = ['linux', 'windows', 'macos', 'embedded']

export const QILING_INSPECT_ARCHITECTURES = ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel']

export const QILING_INSPECT_SAFETY = [
  'passive',
  'opt_in_dynamic',
  'requires_isolation',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_sample_execution_by_default',
  'backend_readiness_probe_only',
]

export const QILING_INSPECT_CAPABILITIES = [
  'readiness',
  'readiness-profile',
  'emulation-plan',
  'rootfs-profile',
  'qiling-rootfs-readiness',
  'backend-profile',
  'runtime-plan',
  'workflow-plan',
  'workflow-handoff',
]

export const QILING_INSPECT_EVIDENCE = [
  'runtime-readiness',
  'rootfs',
  'backend',
  'workflow',
  'provenance',
]

export const QILING_INSPECT_RECOMMENDED_NEXT_TOOLS = [
  'linux.runtime.plan',
  'windows.runtime.plan',
  'dynamic.dependencies',
  'dynamic.runtime.status',
  'dynamic.toolkit.status',
  'tool.readiness',
]

export const QILING_INSPECT_RUNTIME_POLICY: ToolDefinition['runtimePolicy'] = {
  passiveByDefault: true,
  requiresUserOptIn: true,
  requiresIsolation: true,
  allowedBackends: ['docker'],
  maxRuntimeMs: 120_000,
  networkPolicy: 'disabled',
  notes: [
    'qiling.inspect is a readiness/profile planner; it probes backend and rootfs state only.',
    'Qiling and Unicorn are emulation engine profiles, while allowedBackends names the isolation carrier used to run Python tooling.',
    'It must not execute, emulate, or instrument sample code by default.',
    'Live Qiling emulation requires a separate opt-in runtime plan and isolation boundary.',
  ],
}

export const QILING_INSPECT_WORKFLOW_RECIPES = [
  {
    id: 'qiling.rootfs-readiness-profile',
    title: 'Qiling rootfs and backend readiness profile',
    description:
      'Build a passive Qiling backend/rootfs readiness profile and hand it off to runtime planning without executing or emulating the sample.',
    startsWith: ['qiling.inspect'],
    nextTools: QILING_INSPECT_RECOMMENDED_NEXT_TOOLS,
    requiredArtifacts: ['sample'],
    evidence: QILING_INSPECT_EVIDENCE,
    safety: QILING_INSPECT_SAFETY,
    runtimeBackends: ['qiling', 'unicorn'],
  },
]

export function buildQilingReadiness(params: {
  backendAvailable: boolean
  rootfsConfigured?: boolean
  rootfsExists?: boolean
  windowsKernel32Present?: boolean
}) {
  return {
    backend_available: params.backendAvailable,
    rootfs_configured: Boolean(params.rootfsConfigured),
    rootfs_exists: Boolean(params.rootfsExists),
    windows_rootfs_kernel32_present: Boolean(params.windowsKernel32Present),
  }
}

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

export function enrichQilingInspectResult(
  result: WorkerResult,
  context: {
    sampleId?: string
    operation?: string
    rootfsConfigured?: boolean
    rootfsExists?: boolean
    rootfsPath?: string | null
    windowsKernel32Present?: boolean
    backendProbeStarted?: boolean
  } = {}
): WorkerResult {
  const data = asRecord(result.data)
  const backend = asRecord(data.backend)
  const backendAvailable =
    typeof backend.available === 'boolean'
      ? backend.available
      : Boolean(context.backendProbeStarted)
  const readiness = buildQilingReadiness({
    backendAvailable,
    rootfsConfigured:
      context.rootfsConfigured ??
      (typeof data.rootfs_configured === 'boolean' ? data.rootfs_configured : false),
    rootfsExists:
      context.rootfsExists ??
      (typeof data.rootfs_exists === 'boolean' ? data.rootfs_exists : false),
    windowsKernel32Present:
      context.windowsKernel32Present ??
      Boolean(asRecord(data.details).kernel32_present ?? data.windows_rootfs_kernel32_present),
  })
  const rootfsPath =
    context.rootfsPath ?? (typeof data.rootfs_path === 'string' ? data.rootfs_path : null)
  const rootfsReadinessSufficient =
    readiness.rootfs_configured &&
    readiness.rootfs_exists &&
    readiness.windows_rootfs_kernel32_present
  const recommendedNextTools = QILING_INSPECT_RECOMMENDED_NEXT_TOOLS
  const nextActions =
    readiness.backend_available && readiness.rootfs_configured && readiness.rootfs_exists
      ? [
          'Use linux.runtime.plan or windows.runtime.plan to choose an explicit isolated runtime session before emulation.',
          'Use tool.readiness for qiling.inspect to verify runtime control-plane compatibility before delegated execution.',
        ]
      : readiness.backend_available
        ? [
            'Configure QILING_ROOTFS as a read-only rootfs before attempting Qiling-backed emulation.',
            'Use dynamic.dependencies and dynamic.toolkit.status to inspect runtime setup without executing the sample.',
          ]
        : [
            'Install or configure the Qiling Python backend, then re-run qiling.inspect as a passive readiness probe.',
            'Use dynamic.dependencies and system setup guidance before any emulation workflow.',
          ]

  return {
    ...result,
    data: {
      ...data,
      result_mode: QILING_INSPECT_ARTIFACT_TYPE,
      status: rootfsReadinessSufficient && readiness.backend_available ? 'ready' : 'setup_required',
      sample_id: context.sampleId ?? data.sample_id,
      operation: context.operation ?? data.operation ?? 'preflight',
      rootfs_configured: readiness.rootfs_configured,
      rootfs_exists: readiness.rootfs_exists,
      rootfs_path: rootfsPath,
      windows_rootfs_kernel32_present: readiness.windows_rootfs_kernel32_present,
      readiness,
      policy: {
        passive: true,
        readiness_probe_only: true,
        probe_requires_user_opt_in: false,
        probe_requires_isolation: false,
        emulation_requires_user_opt_in: true,
        emulation_requires_isolation: true,
        no_execute: true,
        no_sample_execution: true,
        no_live_execution: true,
        no_emulation_started: true,
        no_network: true,
        network_policy: 'disabled',
      },
      execution_semantics: {
        readiness_probe: 'passive',
        requested_mode: 'qiling_readiness_probe',
        actual_mode: 'plan_only',
        backend: 'qiling',
        live_execution: false,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
        runtime_started_by_tool: false,
        backend_probe_started: Boolean(context.backendProbeStarted),
        network_accessed_by_tool: false,
      },
      evidence_summary: {
        schema: 'rikune.qiling_inspect.evidence_summary.v1',
        source_tool: 'qiling.inspect',
        artifact_type: QILING_INSPECT_ARTIFACT_TYPE,
        sample_id: context.sampleId ?? data.sample_id ?? null,
        operation: context.operation ?? data.operation ?? 'preflight',
        backend_available: readiness.backend_available,
        rootfs_configured: readiness.rootfs_configured,
        rootfs_exists: readiness.rootfs_exists,
        rootfs_path: rootfsPath,
        windows_rootfs_kernel32_present: readiness.windows_rootfs_kernel32_present,
        readiness_probe_only: true,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
      },
      workflow_handoff: {
        schema: 'rikune.qiling_inspect.workflow_handoff.v1',
        handoff_mode: 'qiling_readiness_to_runtime_planning',
        artifact_type: QILING_INSPECT_ARTIFACT_TYPE,
        recommended_next_tools: recommendedNextTools,
        artifact_contract: {
          consumes: ['sample', 'qiling backend configuration', 'QILING_ROOTFS environment'],
          produces: [],
          expected_consumers: ['workflow.search', 'linux.runtime.plan', 'windows.runtime.plan'],
        },
        routing: [
          {
            goal: 'qiling-rootfs-readiness',
            priority: readiness.backend_available ? 'high' : 'blocked',
            consumes: [QILING_INSPECT_ARTIFACT_TYPE],
            produces: ['runtime_readiness_profile'],
            next_tools: ['dynamic.dependencies', 'dynamic.toolkit.status', 'tool.readiness'],
          },
          {
            goal: 'opt-in-emulation-planning',
            priority: rootfsReadinessSufficient ? 'medium' : 'blocked',
            consumes: [QILING_INSPECT_ARTIFACT_TYPE],
            produces: ['runtime_session_plan'],
            next_tools: ['linux.runtime.plan', 'windows.runtime.plan'],
          },
        ],
        dynamic_boundary: {
          sample_executed_by_tool: false,
          emulation_started_by_tool: false,
          runtime_started_by_tool: false,
          network_accessed_by_tool: false,
          mutation_performed: false,
        },
      },
      quality_gates: {
        schema: 'rikune.qiling_inspect.quality_gates.v1',
        readiness_probe_only: true,
        backend_available: readiness.backend_available,
        backend_probe_started: Boolean(context.backendProbeStarted),
        rootfs_configured: readiness.rootfs_configured,
        rootfs_exists: readiness.rootfs_exists,
        windows_rootfs_kernel32_present: readiness.windows_rootfs_kernel32_present,
        rootfs_readiness_sufficient: rootfsReadinessSufficient,
        network_disabled_by_default: true,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
        runtime_started_by_tool: false,
        recommended_live_execution_tools: [],
      },
      recommended_next_tools: recommendedNextTools,
      next_actions: nextActions,
    },
    warnings: stringArray(result.warnings).length > 0 ? result.warnings : undefined,
  }
}
