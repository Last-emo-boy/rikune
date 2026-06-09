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
  }
}
