import type { ToolDefinition } from '../../types.js'

export const MANAGED_IL_XREFS_FORMATS = ['dotnet', 'pe-clr', 'mono', 'winmd']
export const MANAGED_IL_XREFS_PLATFORMS = ['dotnet', 'windows', 'linux', 'macos']
export const MANAGED_IL_XREFS_ARCHITECTURES = ['x86', 'x64', 'arm', 'arm64']

export const MANAGED_IL_XREFS_SAFETY = [
  'passive',
  'bounded-worker',
  'no_runtime_start',
  'no_clr_start',
  'no_decompiler_launch',
  'no_network',
  'no_mutation',
  'no_live_sample_by_default',
]

export const MANAGED_IL_XREFS_CAPABILITIES = [
  'il-xrefs',
  'managed-xrefs',
  'token-graph',
  'dependency-graph',
  'artifact-handoff',
  'workflow-handoff',
  'quality-gates',
  'search-profile',
  'routing',
]

export const MANAGED_IL_XREFS_EVIDENCE = [
  'managed-metadata',
  'il-references',
  'callgraph',
  'symbols',
  'workflow',
  'provenance',
]

export const MANAGED_IL_XREFS_SEARCH_TERMS = [
  'managed-xref',
  'managed il xrefs',
  'il cross reference',
  'metadata token',
  'token graph',
  'methoddef token',
  'field token',
  'clr metadata',
  'dnfile',
  'generic instantiation',
  'where is this token used',
]

export const MANAGED_IL_XREFS_PROFILE_TERMS = [
  'managed-il-xrefs',
  'managed-xref',
  'token-graph',
  'clr-metadata',
  'workflow-handoff',
  'quality-gates',
]

export const MANAGED_IL_XREFS_ROUTE_TERMS = [
  'managed_xref_profile',
  'dotnet_token_graph',
  'clr_metadata_handoff',
  'il_reference_graph',
  'bounded_worker_static_analysis',
  'no_clr_start',
  'no_decompiler_launch',
]

export const MANAGED_IL_XREFS_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'dotnet.metadata.extract',
  'dotnet.types.list',
  'analysis.evidence.graph',
  'report.generate',
]

export const MANAGED_IL_XREFS_ARTIFACT_TYPES = {
  il: 'il_xrefs',
  token: 'token_xrefs',
} as const

export const MANAGED_IL_XREFS_TOOL_VERSION = '1.1.0'
export const MANAGED_IL_XREFS_RUNTIME_BACKEND = 'python-dnfile'
export const MANAGED_IL_XREFS_WORKER_ADAPTER = 'python.dnfile.managed-il-xrefs'
export const MANAGED_IL_XREFS_WORKER_MODE = 'local-python'
export const MANAGED_IL_XREFS_WORKER_TIMEOUT_MS = 30_000
export const MANAGED_IL_XREFS_EVIDENCE_SUMMARY_SCHEMA =
  'rikune.managed_il_xrefs.evidence_summary.v1'
export const MANAGED_IL_XREFS_WORKFLOW_HANDOFF_SCHEMA =
  'rikune.managed_il_xrefs.workflow_handoff.v1'
export const MANAGED_IL_XREFS_QUALITY_GATES_SCHEMA = 'rikune.managed_il_xrefs.quality_gates.v1'

export const MANAGED_IL_XREFS_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  maxRuntimeMs: MANAGED_IL_XREFS_WORKER_TIMEOUT_MS,
  networkPolicy: 'disabled',
  workerBackends: [MANAGED_IL_XREFS_RUNTIME_BACKEND],
  workerMode: MANAGED_IL_XREFS_WORKER_MODE,
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noClrStart: true,
  noDecompilerLaunch: true,
  noPackageRestore: true,
  notes: [
    'Managed IL xref tools read .NET metadata and IL method bodies through a bounded local Python worker.',
    'They do not start the CLR, execute managed code, restore packages, launch decompilers, mutate samples, or use network access.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noClrStart: true
  noDecompilerLaunch: true
  noPackageRestore: true
}

export function managedIlXrefsAspects(capabilities: string[] = MANAGED_IL_XREFS_CAPABILITIES) {
  return {
    formats: MANAGED_IL_XREFS_FORMATS,
    platforms: MANAGED_IL_XREFS_PLATFORMS,
    architectures: MANAGED_IL_XREFS_ARCHITECTURES,
    execution: ['static', 'triage', 'workflow-handoff'],
    safety: MANAGED_IL_XREFS_SAFETY,
    capabilities,
    evidence: MANAGED_IL_XREFS_EVIDENCE,
    search: MANAGED_IL_XREFS_SEARCH_TERMS,
    profile: MANAGED_IL_XREFS_PROFILE_TERMS,
    route_terms: MANAGED_IL_XREFS_ROUTE_TERMS,
  }
}

export function managedIlXrefsWorkerBackend(
  outputArtifactType: string
): NonNullable<ToolDefinition['workerBackend']> {
  return {
    version: 'backend-worker.v1',
    backendName: 'dnfile managed IL xrefs worker',
    backendKind: 'external',
    adapter: MANAGED_IL_XREFS_WORKER_ADAPTER,
    availability: 'required',
    supportedModes: [MANAGED_IL_XREFS_WORKER_MODE],
    defaultMode: MANAGED_IL_XREFS_WORKER_MODE,
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [outputArtifactType],
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: false,
      requiresIsolation: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      noClrStart: true,
      noDecompilerLaunch: true,
      noPackageRestore: true,
      defaultTimeoutMs: MANAGED_IL_XREFS_WORKER_TIMEOUT_MS,
      notes: [
        'Readiness metadata must not spawn Python or parse the sample.',
        'Worker execution is scoped to explicit managed xref tool calls after .NET metadata has been identified.',
      ],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Install Python 3 and the dnfile package when managed IL xref tools are used.',
      ],
      missingBackendBehavior:
        'Discovery and readiness remain metadata-only; explicit managed xref calls fail with a setup error if Python or dnfile is missing.',
    },
    packaging: {
      installRoute: 'profile-gated',
      installProfile: 'optional',
      envVar: 'PYTHON',
      notes: ['Python/dnfile is only required for explicit managed IL xref analysis.'],
    },
  }
}

export function managedIlXrefsRecipe(args: {
  id: string
  title: string
  startsWith: string
  artifactType: string
  focus: string
}) {
  return {
    id: args.id,
    title: args.title,
    description:
      'Build a bounded managed IL xref handoff without CLR startup, managed code execution, package restore, or decompiler launch.',
    startsWith: [args.startsWith],
    nextTools: MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample', 'dotnet_assembly_inventory'],
    producesArtifacts: [args.artifactType],
    evidence: MANAGED_IL_XREFS_EVIDENCE,
    safety: MANAGED_IL_XREFS_SAFETY,
    runtimeBackends: [MANAGED_IL_XREFS_RUNTIME_BACKEND],
    focus: args.focus,
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function arrayLengthOrNull(value: unknown): number | null {
  return Array.isArray(value) ? value.length : null
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null
}

function managedIlXrefsResultSummary(result: Record<string, unknown>) {
  const data = isRecord(result.data) ? result.data : result

  return {
    xref_count: numberOrNull(data.xref_count) ?? arrayLengthOrNull(data.xrefs),
    node_count: numberOrNull(data.node_count) ?? arrayLengthOrNull(data.nodes),
    edge_count: numberOrNull(data.edge_count) ?? arrayLengthOrNull(data.edges),
    truncated: data.truncated === true,
    target_token: stringOrNull(data.target_token),
    root_token: stringOrNull(data.root_token),
  }
}

export function buildManagedIlXrefsEnvelope(args: {
  toolName: string
  artifactType: string
  sampleId: string
  focus: 'il-token-reference' | 'token-graph'
  query: Record<string, unknown>
  result: Record<string, unknown>
}) {
  const bounded = {
    max_results: args.query.max_results ?? null,
    max_nodes: args.query.max_nodes ?? null,
    depth: args.query.depth ?? null,
  }
  const resultSummary = managedIlXrefsResultSummary(args.result)

  return {
    evidence_summary: {
      schema: MANAGED_IL_XREFS_EVIDENCE_SUMMARY_SCHEMA,
      profile: 'managed.il_xrefs',
      source_tool: args.toolName,
      artifact_type: args.artifactType,
      sample_id: args.sampleId,
      evidence_kind: args.focus,
      route_terms: MANAGED_IL_XREFS_ROUTE_TERMS,
      result_ok: args.result.ok === true,
      result_summary: resultSummary,
      bounded,
      recommended_next_tools: MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
    },
    workflow_handoff: {
      schema: MANAGED_IL_XREFS_WORKFLOW_HANDOFF_SCHEMA,
      artifact_contract: {
        consumes: ['sample', 'dotnet_assembly_inventory'],
        produces: [args.artifactType],
        mime: 'application/json',
      },
      dynamic_boundary: {
        activation_boundary: 'result-scoped',
        sample_execution_allowed: false,
        clr_start_allowed: false,
        decompiler_launch_allowed: false,
        package_restore_allowed: false,
        network_allowed: false,
      },
      routing: [
        {
          goal: args.focus,
          profile: 'managed.il_xrefs',
          route_terms: MANAGED_IL_XREFS_ROUTE_TERMS,
          activation_boundary: 'result-scoped',
          next_tools: MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
          required_evidence: [args.artifactType],
        },
      ],
      recommended_next_tools: MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
      quality_gates_schema: MANAGED_IL_XREFS_QUALITY_GATES_SCHEMA,
    },
    quality_gates: {
      schema: MANAGED_IL_XREFS_QUALITY_GATES_SCHEMA,
      passive_static_analysis: true,
      worker_backend_started: true,
      sample_executed_by_tool: false,
      clr_started_by_tool: false,
      decompiler_launched_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
      bounded,
    },
    recommended_next_tools: MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
  }
}
