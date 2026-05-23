import { definePlugin, defineTool } from '../sdk.js'
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
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'imports', 'exports', 'artifact'],
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
  ],
  safetyNotes: [
    'GTIRB planning does not invoke GTIRB, rewrite binaries, run loaders, or start network access.',
    'Future rewriting workers must require explicit patch intent and output-only artifact paths.',
  ],
}

const workerSpec: FrontierWorkerToolSpec = {
  pluginId: 'gtirb',
  toolName: 'gtirb.ir.generate',
  description:
    'Generate or summarize read-only GTIRB-style IR artifacts from local binary artifacts through a bounded worker contract.',
  backendName: 'GTIRB',
  adapter: 'gtirb.readonly.ir.generate',
  envVar: 'GTIRB_PYTHON',
  aspects: buildBackendPlanAspects(spec),
  artifacts: [
    { type: 'gtirb_ir_artifact', description: 'Read-only GTIRB IR artifact metadata' },
    { type: 'gtirb_cfg_summary', description: 'GTIRB CFG and symbol summary' },
  ],
  evidence: [
    { category: 'structure', artifactTypes: ['gtirb_ir_artifact'] },
    { category: 'symbols', artifactTypes: ['gtirb_cfg_summary'] },
  ],
  workflowRecipe: {
    id: 'gtirb.binary.ir-worker',
    title: 'GTIRB read-only IR worker',
    startsWith: ['gtirb.ir.generate', 'pe.structure.analyze', 'elf.structure.analyze'],
    nextTools: ['remill.lift.run', 'manifold.fact.extract', 'analysis.evidence.graph'],
    producesArtifacts: ['gtirb_ir_artifact', 'gtirb_cfg_summary'],
    evidence: ['structure', 'symbols', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  readinessSetupActions: ['Set GTIRB_PYTHON to a Python interpreter with pinned GTIRB packages.'],
  fixtureData: {
    modules: 1,
    cfg_blocks: 3,
    symbols: ['entry', 'func_0'],
    read_only: true,
  },
  recommendedNextTools: ['remill.lift.run', 'manifold.fact.extract'],
}

const gtirbPlugin = definePlugin({
  id: 'gtirb',
  name: 'GTIRB IR Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib'],
      findings: ['binary-ir', 'binary-rewrite', 'cfg', 'cross-backend-check'],
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
      required: false,
      description: 'GTIRB Python package',
      dockerInstall: 'pip install gtirb or provide a pinned toolchain',
      dockerFeature: 'dynamic-python',
      extraEnv: { GTIRB_PYTHON: 'python3' },
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
    defineTool({
      ...createFrontierWorkerToolDefinition(workerSpec),
      handler: createFrontierWorkerHandler(workerSpec),
    }),
  ],
})

export default gtirbPlugin
