import type { ToolDefinition } from '../../types.js'

export const WINE_FORMATS = ['pe', 'dll', 'dotnet', 'pe-clr', 'msi', 'installer']
export const WINE_PLATFORMS = ['windows', 'linux']
export const WINE_ARCHITECTURES = ['x86', 'x64', 'arm64']

export const WINE_SAFETY = [
  'passive',
  'opt_in_dynamic',
  'requires_isolation',
  'no_live_sample_by_default',
  'no_network_by_default',
  'approval_required_for_live_execution',
]

export const WINE_CAPABILITIES = [
  'wine-prefix',
  'wine-preflight',
  'dll-overrides',
  'registry-profile',
  'execution-plan',
  'debug-plan',
  'behavior-hints',
  'workflow-plan',
  'workflow-handoff',
]

export const WINE_EVIDENCE = [
  'runtime-readiness',
  'configuration',
  'filesystem',
  'registry',
  'process',
  'timeline',
  'workflow',
  'provenance',
]

export const WINE_SEARCH_TERMS = [
  'wine',
  'wine preflight',
  'wine readiness',
  'windows compatibility',
  'windows runtime on linux',
  'linux-hosted windows sample',
  'dll override',
  'winedlloverrides',
  'wine registry',
  'wine prefix',
  'winedbg',
  'compatibility runtime',
]

export const WINE_ROUTE_TERMS = [
  'wine_compatibility_profile',
  'runtime_intent_router',
  'windows_runtime_plan',
  'profile_gated_execution',
  'approval_gated_execution',
  'prefix_profile',
  'registry_profile',
  'dll_override_profile',
]

export const WINE_QUALITY_GATES_SCHEMA = 'rikune.wine_compatibility.quality_gates.v1'

export const WINE_RUNTIME_POLICY: ToolDefinition['runtimePolicy'] = {
  passiveByDefault: true,
  requiresUserOptIn: true,
  requiresIsolation: true,
  allowedBackends: ['wine'],
  maxRuntimeMs: 120_000,
  networkPolicy: 'disabled',
  notes: [
    'Wine preflight and profile paths must not launch PE payloads.',
    'wine.run mode=run/debug requires approved=true and an isolated runtime boundary.',
    'Wine behavior is a compatibility signal and must not be treated as native Windows ground truth.',
  ],
}

export const WINE_PROFILE_NEXT_TOOLS = [
  'windows.runtime.plan',
  'pe.structure.analyze',
  'dll.dependency.tree',
  'dynamic.dependencies',
  'dynamic.runtime.status',
  'tool.readiness',
]

export const WINE_RUN_ARTIFACT_TYPES = ['backend_wine_run', 'backend_winedbg_run']
export const WINE_REG_ARTIFACT_TYPE = 'backend_wine-reg_export'

export type WineRunEnvelopeInput = {
  status: 'ready' | 'denied' | 'setup_required'
  mode?: string
  approved?: boolean
  sampleId?: string
  backendAvailable?: boolean
  executionAttempted?: boolean
  artifactPersisted?: boolean
  timedOut?: boolean
  recommendedNextTools?: string[]
}

export function buildWineRunEnvelope(input: WineRunEnvelopeInput) {
  const executionAttempted = input.executionAttempted === true
  const recommendedNextTools = input.recommendedNextTools ?? WINE_PROFILE_NEXT_TOOLS
  const mode = input.mode ?? 'preflight'

  return {
    evidence_summary: {
      schema: 'rikune.wine_compatibility.evidence_summary.v1',
      profile: 'wine.compatibility',
      status: input.status,
      mode,
      sample_id: input.sampleId ?? null,
      evidence_categories: executionAttempted
        ? ['runtime-readiness', 'process', 'filesystem', 'timeline', 'workflow', 'provenance']
        : ['runtime-readiness', 'workflow', 'provenance'],
      route_terms: WINE_ROUTE_TERMS,
      confidence: executionAttempted ? 'compatibility-signal' : 'readiness-only',
      notes: [
        'Wine output is a compatibility signal and is not native Windows ground truth.',
        'Live run/debug modes require explicit approval and isolation.',
      ],
      recommended_next_tools: recommendedNextTools,
    },
    workflow_handoff: {
      schema: 'rikune.wine_compatibility.workflow_handoff.v1',
      routing: {
        profile: 'wine.compatibility',
        route_terms: WINE_ROUTE_TERMS,
        activation_boundary: 'result-scoped',
        preferred_next_tools: recommendedNextTools,
        live_execution_requires: [
          'approved=true',
          'isolated runtime',
          'network disabled by default',
        ],
      },
      recommended_next_tools: recommendedNextTools,
      quality_gates_schema: WINE_QUALITY_GATES_SCHEMA,
    },
    quality_gates: {
      schema: WINE_QUALITY_GATES_SCHEMA,
      passive_preflight_only: mode === 'preflight' && !executionAttempted,
      sample_executed_by_tool: executionAttempted,
      approval_required_for_live_execution: true,
      current_mode_requires_approval: mode === 'run' || mode === 'debug',
      approved_execution: executionAttempted && input.approved === true,
      network_disabled_by_default: true,
      requires_isolation: true,
      wine_not_windows_ground_truth: true,
      runtime_backend_available: input.backendAvailable ?? null,
      artifact_persisted: input.artifactPersisted === true,
      timed_out: input.timedOut === true,
    },
  }
}

export const WINE_RUN_WORKFLOW_RECIPES = [
  {
    id: 'wine.pe-preflight',
    title: 'Wine PE preflight and opt-in execution gate',
    description:
      'Check Wine and winedbg readiness for PE/.NET samples, then hand off to explicit runtime planning before any Wine execution.',
    startsWith: ['wine.run'],
    nextTools: WINE_PROFILE_NEXT_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: WINE_RUN_ARTIFACT_TYPES,
    evidence: ['runtime-readiness', 'process', 'filesystem', 'timeline', 'workflow', 'provenance'],
    safety: WINE_SAFETY,
    runtimeBackends: ['wine'],
    defaultMode: 'preflight',
    liveExecutionRequires: ['approved=true', 'isolated runtime', 'network disabled by default'],
  },
]

export const WINE_ENV_WORKFLOW_RECIPES = [
  {
    id: 'wine.prefix-profile',
    title: 'Wine prefix profile and readiness',
    description:
      'List or inspect Wine prefixes as bounded runtime state before configuring DLL overrides, registry keys, or explicit execution.',
    startsWith: ['wine.env'],
    nextTools: ['wine.dll_overrides', 'wine.reg', 'wine.run', ...WINE_PROFILE_NEXT_TOOLS],
    requiredArtifacts: [],
    evidence: ['runtime-readiness', 'configuration', 'filesystem', 'workflow', 'provenance'],
    safety: WINE_SAFETY,
    runtimeBackends: ['wine'],
    preferredActions: ['list', 'inspect'],
    mutatingActions: ['create', 'remove'],
  },
]

export const WINE_DLL_OVERRIDE_WORKFLOW_RECIPES = [
  {
    id: 'wine.dll-override-plan',
    title: 'Wine DLL override profile',
    description:
      'Inspect or configure DLL override state in a Wine prefix before an explicitly approved Wine run/debug workflow.',
    startsWith: ['wine.dll_overrides'],
    nextTools: ['wine.env', 'wine.run', ...WINE_PROFILE_NEXT_TOOLS],
    requiredArtifacts: ['wine_prefix'],
    evidence: ['configuration', 'filesystem', 'workflow', 'provenance'],
    safety: WINE_SAFETY,
    runtimeBackends: ['wine'],
    preferredActions: ['get', 'list'],
    mutatingActions: ['set'],
  },
]

export const WINE_REG_WORKFLOW_RECIPES = [
  {
    id: 'wine.registry-profile',
    title: 'Wine registry profile and export',
    description:
      'Query or export Wine registry state for environment profiling, with registry writes kept explicit and separate from sample execution.',
    startsWith: ['wine.reg'],
    nextTools: ['wine.env', 'wine.run', 'artifact.read', ...WINE_PROFILE_NEXT_TOOLS],
    requiredArtifacts: ['wine_prefix'],
    producesArtifacts: [WINE_REG_ARTIFACT_TYPE],
    evidence: ['registry', 'configuration', 'workflow', 'provenance'],
    safety: WINE_SAFETY,
    runtimeBackends: ['wine'],
    preferredActions: ['query', 'export'],
    mutatingActions: ['add'],
  },
]

export function wineToolAspects(
  options: {
    capabilities?: string[]
    evidence?: string[]
    execution?: string[]
  } = {}
) {
  return {
    formats: WINE_FORMATS,
    platforms: WINE_PLATFORMS,
    architectures: WINE_ARCHITECTURES,
    execution: options.execution ?? ['dynamic', 'triage'],
    runtimes: ['wine'],
    safety: WINE_SAFETY,
    capabilities: options.capabilities ?? WINE_CAPABILITIES,
    evidence: options.evidence ?? WINE_EVIDENCE,
    search: WINE_SEARCH_TERMS,
    route_terms: WINE_ROUTE_TERMS,
  }
}
