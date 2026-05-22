import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'manifold',
  toolName: 'manifold.decompilation.plan',
  title: 'Manifold superset decompilation plan',
  description:
    'Build a passive superset-decompilation and fact-modeling plan without running a decompiler, fact engine, lifter, or external backend.',
  backendName: 'Manifold',
  formats: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib'],
  platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
  capabilities: [
    'superset-decompilation-plan',
    'declarative-reverse-engineering',
    'fact-extraction-plan',
    'cross-backend-comparison',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'behavior', 'artifact'],
  artifactType: 'manifold_decompilation_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'manifold.superset.decompilation-plan',
    title: 'Manifold superset decompilation planning',
    description:
      'Plan declarative fact extraction, relation modeling, and superset decompilation comparison from existing static artifacts.',
    startsWith: ['manifold.decompilation.plan', 'code.function.cfg', 'code.function.disassemble'],
    nextTools: ['revng.pipeline.plan', 'gtirb.ir.plan', 'miasm.ir.plan', 'analysis.evidence.graph'],
    requiredArtifacts: ['function_disassembly', 'code_cfg', 'function_index'],
    producesArtifacts: [
      'manifold_decompilation_plan',
      'declarative_fact_plan',
      'superset_decompilation_handoff',
    ],
    evidence: ['structure', 'symbols', 'behavior', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'fact-scope',
      title: 'Declarative fact scope',
      purpose:
        'Select functions, CFG edges, call relations, type hints, and memory facts from existing artifacts.',
      inputs: ['function_disassembly', 'code_cfg', 'function_index', 'type_recovery_hints'],
      outputs: ['declarative_fact_plan'],
      safety: ['metadata_only'],
    },
    {
      id: 'relation-model',
      title: 'Relation model plan',
      purpose:
        'Plan predicates, constraints, provenance, and backend comparison facts for a future declarative worker.',
      inputs: ['declarative_fact_plan'],
      outputs: ['reverse_engineering_relation_model'],
      safety: ['plan_only'],
    },
    {
      id: 'decompile-compare',
      title: 'Superset decompilation comparison',
      purpose: 'Prepare comparison against Ghidra, rev.ng, Miasm, GTIRB, and native CFG artifacts.',
      inputs: ['reverse_engineering_relation_model'],
      outputs: ['superset_decompilation_handoff', 'cross_decompiler_fact_diff'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'manifold-pgsd',
      name: 'Superset Decompilation research direction',
      source: 'https://arxiv.org/abs/2603.28002',
      role: 'Superset decompilation design target for future local fact extraction and comparison workers.',
      readiness: 'future_worker',
      notes: [
        'Treat the paper/research direction as a task blueprint until a pinned implementation exists.',
        'Do not run a fact engine, decompiler, or solver from planner paths.',
      ],
    },
  ],
  recommendedNextTools: [
    'code.function.cfg',
    'revng.pipeline.plan',
    'gtirb.ir.plan',
    'analysis.evidence.graph',
  ],
  safetyNotes: [
    'Manifold planning does not start decompilers, lifters, solvers, fact engines, or network access.',
    'Future workers must emit facts with source artifact anchors and deterministic fixtures.',
  ],
}

const manifoldPlugin = definePlugin({
  id: 'manifold',
  name: 'Manifold Decompilation Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib'],
      findings: ['decompilation-needed', 'fact-extraction', 'cross-backend-check'],
    },
    category: 'reverse-engineering',
  },
  description: 'Passive superset decompilation and fact-modeling planning.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'MANIFOLD_WORKER_PATH',
      description: 'Optional future superset-decompilation fact worker path',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'manifold-worker',
      target: '$MANIFOLD_WORKER_PATH',
      envVar: 'MANIFOLD_WORKER_PATH',
      required: false,
      description: 'Optional future declarative reverse-engineering worker',
      dockerInstall: 'Provide a pinned local worker; not installed by default',
      dockerFeature: 'manifold',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default manifoldPlugin
