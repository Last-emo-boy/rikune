import {
  definePlugin,
  defineTool,
  type DynamicRuntimePolicy,
  type PluginAspects,
  type WorkerResult,
} from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'
import {
  createFrontierWorkerHandler,
  createFrontierWorkerToolDefinition,
  type FrontierWorkerToolSpec,
} from '../frontier-worker-tools.js'

const GTIRB_SEARCH_TERMS = [
  'gtirb',
  'binary ir',
  'intermediate representation',
  'basic blocks',
  'cfg edges',
  'cfg recovery',
  'symbol correlation',
  'aux data',
  'byte intervals',
  'relocations',
  'symbol table',
  'rewrite boundary',
  'cross backend ir',
]

const GTIRB_PROFILE_TERMS = [
  'gtirb-ir-profile',
  'cfg-symbol-profile',
  'byte-interval-profile',
  'aux-data-profile',
  'relocation-profile',
  'rewrite-boundary-profile',
  'cross-backend-ir-profile',
]

const GTIRB_ROUTE_TERMS = [
  'gtirb_ir_handoff',
  'binary_ir_handoff',
  'gtirb_schema_profile',
  'byte_interval_inventory',
  'cfg_symbol_handoff',
  'cfg_edge_summary',
  'symbol_table_handoff',
  'aux_data_summary',
  'relocation_summary',
  'rewrite_boundary_handoff',
  'cross_backend_ir_comparison',
  'bounded_readonly_ir',
]

const GTIRB_PLAN_FOLLOW_UP_TOOLS = [
  'remill.lift.plan',
  'revng.pipeline.plan',
  'rizin.analyze',
  'analysis.evidence.graph',
  'artifact.read',
  'workflow.search',
]

const GTIRB_WORKER_FOLLOW_UP_TOOLS = [
  'remill.lift.run',
  'manifold.fact.extract',
  'analysis.evidence.graph',
  'artifact.read',
  'workflow.search',
]

const GTIRB_RUNTIME_POLICY: DynamicRuntimePolicy = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'GTIRB planning and builtin worker mode are passive, local-artifact-only paths.',
    'Read-only IR generation stays separate from any binary rewrite or patch workflow.',
    'External GTIRB toolchains must be profile-gated and pinned before persisted IR is trusted.',
  ],
}

const spec: BackendPlanSpec = {
  pluginId: 'gtirb',
  toolName: 'gtirb.ir.plan',
  title: 'GTIRB binary IR plan',
  description:
    'Build a passive GTIRB integration plan for binary IR, rewriting, and cross-backend comparison without invoking GTIRB tooling or mutating binaries.',
  backendName: 'GTIRB',
  formats: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib'],
  platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
  capabilities: [
    'binary-ir',
    'binary-rewriting-plan',
    'cfg-recovery',
    'symbol-correlation',
    'cross-backend-comparison',
    'search-profile',
    'workflow-handoff',
    'metadata-only-handoff',
    'binary-ir-handoff',
    'cfg-symbol-handoff',
    'rewrite-boundary-handoff',
    'cross-backend-ir-comparison',
    'workflow-routing',
  ],
  evidence: [
    'structure',
    'symbols',
    'imports',
    'exports',
    'artifact',
    'cfg',
    'function-boundaries',
    'relocations',
    'byte-intervals',
    'ir-schema',
    'aux-data',
  ],
  artifactType: 'gtirb_ir_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'gtirb.binary.ir-plan',
    title: 'GTIRB binary IR planning',
    description:
      'Plan GTIRB IR generation, CFG/symbol correlation, and optional rewriting workflows from existing static evidence without invoking GTIRB.',
    startsWith: ['gtirb.ir.plan', 'pe.structure.analyze', 'elf.structure.analyze'],
    nextTools: [
      'remill.lift.plan',
      'revng.pipeline.plan',
      'rizin.analyze',
      'analysis.evidence.graph',
      'artifact.read',
      'workflow.search',
    ],
    requiredArtifacts: ['pe_structure', 'elf_structure', 'macho_structure', 'function_index'],
    producesArtifacts: ['gtirb_ir_plan', 'gtirb_cfg_plan', 'binary_rewriting_plan'],
    evidence: ['structure', 'symbols', 'artifact', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'ir-inventory',
      title: 'IR inventory plan',
      purpose:
        'Correlate sections, symbols, relocations, functions, and CFG evidence before selecting GTIRB tooling.',
      inputs: ['pe_structure', 'elf_structure', 'macho_structure', 'function_index'],
      outputs: ['gtirb_ir_inventory'],
      safety: ['metadata_only'],
    },
    {
      id: 'cfg-symbol-plan',
      title: 'CFG and symbol plan',
      purpose:
        'Prepare expected CFG, symbol, module, and auxiliary-table outputs for a future GTIRB worker.',
      inputs: ['gtirb_ir_inventory'],
      outputs: ['gtirb_cfg_plan', 'gtirb_symbol_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'rewrite-boundary',
      title: 'Rewrite boundary plan',
      purpose:
        'Separate read-only IR generation from any future binary rewriting or patch workflow.',
      inputs: ['gtirb_cfg_plan', 'gtirb_symbol_plan'],
      outputs: ['binary_rewriting_plan'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'grammatech-gtirb',
      name: 'GrammaTech/gtirb',
      source: 'https://github.com/GrammaTech/gtirb',
      role: 'Binary intermediate representation for analysis, transformation, and rewriting workflows.',
      readiness: 'optional_external',
      notes: [
        'Keep read-only IR generation separate from rewrite or patch workflows.',
        'Pin GTIRB schema/tool versions before accepting persisted IR artifacts.',
      ],
    },
  ],
  recommendedNextTools: [
    'remill.lift.plan',
    'revng.pipeline.plan',
    'rizin.analyze',
    'analysis.evidence.graph',
    'artifact.read',
    'workflow.search',
  ],
  safetyNotes: [
    'GTIRB planning does not invoke GTIRB, rewrite binaries, run loaders, or start network access.',
    'Future rewriting workers must require explicit patch intent and output-only artifact paths.',
  ],
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : []
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function buildGtirbAspects(): PluginAspects {
  const base = buildBackendPlanAspects(spec)
  return {
    ...base,
    safety: uniqueStrings([
      ...(base.safety ?? []),
      'no_execute',
      'no_network',
      'no_mutation',
      'read_only_ir',
      'rewrite_boundary_declared',
    ]),
    capabilities: uniqueStrings([
      ...(base.capabilities ?? []),
      'search-profile',
      'workflow-handoff',
      'metadata-only-handoff',
      'binary-ir-handoff',
      'cfg-symbol-handoff',
      'rewrite-boundary-handoff',
      'cross-backend-ir-comparison',
    ]),
    evidence: uniqueStrings([
      ...(base.evidence ?? []),
      'cfg',
      'function-boundaries',
      'relocations',
      'byte-intervals',
      'ir-schema',
      'aux-data',
    ]),
    search: GTIRB_SEARCH_TERMS,
    profile: GTIRB_PROFILE_TERMS,
    route_terms: GTIRB_ROUTE_TERMS,
  }
}

const GTIRB_ASPECTS = buildGtirbAspects()

function buildGtirbEvidenceSummary(args: {
  sourceTool: string
  mode: 'plan' | 'worker'
  data: Record<string, unknown>
}) {
  return {
    schema: 'rikune.gtirb_ir.evidence_summary.v1',
    source_tool: args.sourceTool,
    backend: spec.backendName,
    evidence_kind: 'binary-ir',
    mode: args.mode,
    artifact_types:
      args.mode === 'plan'
        ? ['gtirb_ir_plan', 'gtirb_cfg_plan', 'binary_rewriting_plan']
        : ['gtirb_ir_artifact', 'gtirb_cfg_summary', 'gtirb_aux_data_summary'],
    modules: args.data.modules ?? null,
    cfg_blocks: args.data.cfg_blocks ?? null,
    symbols: stringArray(args.data.symbols).slice(0, 24),
    sections: Array.isArray(args.data.sections) ? args.data.sections : [],
    byte_intervals: Array.isArray(args.data.byte_intervals) ? args.data.byte_intervals : [],
    cfg_edges: args.data.cfg_edges ?? null,
    relocations: Array.isArray(args.data.relocations) ? args.data.relocations : [],
    read_only_ir_only: true,
    route_terms: GTIRB_ROUTE_TERMS,
    search_terms: GTIRB_SEARCH_TERMS,
    evidence_sources:
      args.mode === 'plan'
        ? ['existing static evidence', 'plan-only backend contract']
        : ['local artifact', 'bounded GTIRB worker fixture or external backend'],
  }
}

function buildGtirbWorkflowHandoff(args: {
  sourceTool: string
  mode: 'plan' | 'worker'
  data: Record<string, unknown>
}) {
  return {
    schema: 'rikune.gtirb_ir.workflow_handoff.v1',
    handoff_mode: 'gtirb_ir_to_lifting_rewrite_boundary_and_cross_backend_comparison',
    source_tool: args.sourceTool,
    sample_id: args.data.sample_id ?? null,
    artifact_contract: {
      consumes: [
        'local_artifact',
        'pe_structure',
        'elf_structure',
        'macho_structure',
        'function_index',
      ],
      produces:
        args.mode === 'plan'
          ? ['gtirb_ir_plan', 'gtirb_cfg_plan', 'binary_rewriting_plan']
          : ['gtirb_ir_artifact', 'gtirb_cfg_summary', 'gtirb_aux_data_summary'],
      expected_consumers: [
        'remill.lift.run',
        'manifold.fact.extract',
        'analysis.evidence.graph',
        'artifact.read',
      ],
    },
    routing: [
      {
        goal: 'cfg-symbol-correlation',
        priority: 'high',
        next_tools: ['manifold.fact.extract', 'analysis.evidence.graph'],
        required_evidence: ['gtirb_cfg_summary', 'symbols', 'function-boundaries'],
      },
      {
        goal: 'cross-backend-lift-comparison',
        priority: 'medium',
        next_tools: ['remill.lift.run', 'revng.pipeline.plan', 'analysis.evidence.graph'],
        required_evidence: ['gtirb_ir_artifact', 'gtirb_cfg_summary'],
      },
      {
        goal: 'rewrite-boundary-review',
        priority: 'medium',
        next_tools: ['artifact.read', 'report.generate'],
        required_evidence: ['gtirb_ir_artifact', 'binary_rewriting_plan'],
        boundary: 'review_only_no_binary_rewrite',
      },
    ],
    dynamic_boundary: {
      passive_static_only: true,
      sample_execution_allowed: false,
      network_allowed: false,
      mutation_allowed: false,
      binary_rewrite_allowed: false,
      sample_executed_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
      binary_rewrite_performed: false,
    },
    route_terms: GTIRB_ROUTE_TERMS,
    recommended_next_tools:
      args.mode === 'plan' ? GTIRB_PLAN_FOLLOW_UP_TOOLS : GTIRB_WORKER_FOLLOW_UP_TOOLS,
  }
}

function buildGtirbQualityGates(args: { mode: 'plan' | 'worker'; data: Record<string, unknown> }) {
  return {
    schema: 'rikune.gtirb_ir.quality_gates.v1',
    passive_static_only: true,
    read_only_ir_generation: true,
    read_only_ir_only: true,
    local_artifact_only: true,
    bounded_scope_required: true,
    schema_or_tool_version_pin_required: true,
    cfg_summary_present: args.mode === 'worker' ? typeof args.data.cfg_blocks === 'number' : false,
    cfg_summary_required: true,
    symbol_summary_present:
      args.mode === 'worker' ? stringArray(args.data.symbols).length > 0 : false,
    rewrite_boundary_declared: true,
    sample_executed_by_tool: false,
    network_used_by_tool: false,
    mutation_performed: false,
    binary_rewrite_performed: false,
  }
}

function enrichGtirbResult(
  result: WorkerResult,
  args: { sourceTool: string; mode: 'plan' | 'worker' }
): WorkerResult {
  if (!result.ok || !result.data || typeof result.data !== 'object') return result
  const data = asRecord(result.data)
  result.data = {
    ...data,
    evidence_summary: buildGtirbEvidenceSummary({ ...args, data }),
    workflow_handoff: buildGtirbWorkflowHandoff({ ...args, data }),
    quality_gates: buildGtirbQualityGates({ mode: args.mode, data }),
    route_terms: GTIRB_ROUTE_TERMS,
    recommended_next_tools: uniqueStrings([
      ...stringArray(data.recommended_next_tools),
      ...(args.mode === 'plan' ? GTIRB_PLAN_FOLLOW_UP_TOOLS : GTIRB_WORKER_FOLLOW_UP_TOOLS),
    ]),
  }
  return result
}

function createGtirbPlanHandler() {
  const baseHandler = createBackendPlanHandler(spec)
  return async (args: Parameters<typeof baseHandler>[0]): Promise<WorkerResult> => {
    const result = await baseHandler(args)
    return enrichGtirbResult(result, { sourceTool: spec.toolName, mode: 'plan' })
  }
}

const workerSpec: FrontierWorkerToolSpec = {
  pluginId: 'gtirb',
  toolName: 'gtirb.ir.generate',
  description:
    'Generate or summarize read-only GTIRB-style IR artifacts from local binary artifacts through a bounded worker contract.',
  backendName: 'GTIRB',
  adapter: 'gtirb.readonly.ir.generate',
  envVar: 'GTIRB_PYTHON',
  dockerFeature: 'gtirb',
  dockerDefault: '/opt/rikune-venvs/gtirb/bin/python',
  installRoute: 'profile-gated',
  installProfile: 'optional',
  aspects: GTIRB_ASPECTS,
  artifacts: [
    { type: 'gtirb_ir_artifact', description: 'Read-only GTIRB IR artifact metadata' },
    { type: 'gtirb_cfg_summary', description: 'GTIRB CFG and symbol summary' },
    {
      type: 'gtirb_aux_data_summary',
      description: 'GTIRB auxiliary data and rewrite boundary summary',
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: ['gtirb_ir_artifact'] },
    { category: 'symbols', artifactTypes: ['gtirb_cfg_summary'] },
    { category: 'cfg', artifactTypes: ['gtirb_cfg_summary'] },
    { category: 'relocations', artifactTypes: ['gtirb_aux_data_summary'] },
    { category: 'byte-intervals', artifactTypes: ['gtirb_aux_data_summary'] },
    { category: 'ir-schema', artifactTypes: ['gtirb_ir_artifact'] },
    { category: 'aux-data', artifactTypes: ['gtirb_aux_data_summary'] },
    { category: 'workflow', artifactTypes: ['gtirb_ir_artifact', 'gtirb_aux_data_summary'] },
    { category: 'provenance', artifactTypes: ['gtirb_ir_artifact', 'gtirb_aux_data_summary'] },
  ],
  workflowRecipe: {
    id: 'gtirb.binary.ir-worker',
    title: 'GTIRB read-only IR worker',
    startsWith: ['gtirb.ir.generate', 'pe.structure.analyze', 'elf.structure.analyze'],
    nextTools: GTIRB_WORKER_FOLLOW_UP_TOOLS,
    producesArtifacts: ['gtirb_ir_artifact', 'gtirb_cfg_summary', 'gtirb_aux_data_summary'],
    evidence: [
      'structure',
      'symbols',
      'cfg',
      'relocations',
      'byte-intervals',
      'ir-schema',
      'aux-data',
      'workflow',
      'provenance',
    ],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    routeTerms: GTIRB_ROUTE_TERMS,
  },
  readinessSetupActions: ['Set GTIRB_PYTHON to a Python interpreter with pinned GTIRB packages.'],
  fixtureData: {
    schema_version: 'rikune.gtirb_ir.fixture_summary.v1',
    modules: 1,
    cfg_blocks: 3,
    sections: [{ name: '.text', size: 64, flags: ['rx'] }],
    byte_intervals: [{ section: '.text', size: 64, initialized: true }],
    cfg_edges: { fallthrough: 1, call: 1, return: 1 },
    symbols: ['entry', 'func_0'],
    aux_data_tables: ['functionEntries', 'symbolForwarding'],
    relocations: [],
    read_only: true,
    rewrite_allowed: false,
    raw_generation_performed: false,
    backend_wrapper_required: true,
  },
  recommendedNextTools: GTIRB_WORKER_FOLLOW_UP_TOOLS,
}

function createGtirbWorkerHandler() {
  const baseHandler = createFrontierWorkerHandler(workerSpec)
  return async (args: Parameters<typeof baseHandler>[0]): Promise<WorkerResult> => {
    const result = await baseHandler(args)
    return enrichGtirbResult(result, { sourceTool: workerSpec.toolName, mode: 'worker' })
  }
}

const gtirbPlugin = definePlugin({
  id: 'gtirb',
  name: 'GTIRB IR Plan',
  executionDomain: 'static',
  aspects: GTIRB_ASPECTS,
  runtimePolicy: GTIRB_RUNTIME_POLICY,
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib'],
      findings: [
        'gtirb',
        'binary-ir',
        'ir-generation',
        'binary-rewrite',
        'rewrite-boundary',
        'cfg',
        'symbol-correlation',
        'cross-backend-check',
      ],
    },
    category: 'reverse-engineering',
  },
  description: 'Passive GTIRB binary IR and rewriting boundary planning.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'GTIRB_PYTHON',
      description: 'Optional Python interpreter with GTIRB packages installed for a future worker',
      required: false,
      defaultValue: 'python3',
    },
  ],
  systemDeps: [
    {
      type: 'python',
      name: 'gtirb',
      importName: 'gtirb',
      envVar: 'GTIRB_PYTHON',
      dockerDefault: '/opt/rikune-venvs/gtirb/bin/python',
      required: false,
      description: 'GTIRB Python package',
      dockerInstall: 'pip install gtirb or provide a pinned toolchain',
      dockerFeature: 'gtirb',
      dockerValidation: [
        '/opt/rikune-venvs/gtirb/bin/python -c "import gtirb; print(\'gtirb ok\')"',
      ],
      extraEnv: { GTIRB_PYTHON: '/opt/rikune-venvs/gtirb/bin/python' },
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      aspects: GTIRB_ASPECTS,
      runtimePolicy: GTIRB_RUNTIME_POLICY,
      handler: createGtirbPlanHandler(),
    }),
    defineTool({
      ...createFrontierWorkerToolDefinition(workerSpec),
      runtimePolicy: GTIRB_RUNTIME_POLICY,
      handler: createGtirbWorkerHandler(),
    }),
  ],
})

export default gtirbPlugin
