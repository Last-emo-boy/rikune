import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'triton',
  toolName: 'triton.symbolic.plan',
  title: 'Triton symbolic execution plan',
  description:
    'Build a passive Triton integration plan for instruction semantics, taint, symbolic execution, and path-constraint recovery without emulating or executing the sample.',
  backendName: 'Triton',
  formats: ['pe', 'elf', 'macho', 'shellcode', 'firmware'],
  platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64'],
  capabilities: [
    'symbolic-execution',
    'taint-analysis',
    'instruction-semantics',
    'constraint-solving',
    'path-constraints',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'behavior', 'memory', 'artifact'],
  artifactType: 'triton_symbolic_plan',
  category: 'symbolic-execution',
  recipe: {
    id: 'triton.symbolic.recovery-plan',
    title: 'Triton symbolic recovery planning',
    description:
      'Plan a Triton-backed symbolic analysis flow from existing disassembly, VM-analysis, and API-hash evidence without starting emulation by default.',
    startsWith: ['triton.symbolic.plan', 'vm.workflow.plan', 'code.function.disassemble'],
    nextTools: ['constraint.extract', 'smt.solve', 'vm.workflow.plan', 'analysis.evidence.graph'],
    requiredArtifacts: ['function_disassembly', 'vm_workflow_plan', 'api_hash_resolution'],
    producesArtifacts: ['triton_symbolic_plan', 'path_constraints', 'symbolic_trace'],
    evidence: ['structure', 'behavior', 'memory', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    runtimeBackends: ['unicorn'],
  },
  defaultStages: [
    {
      id: 'seed-selection',
      title: 'Seed selection',
      purpose:
        'Select bounded functions, shellcode ranges, VM handlers, or resolver loops from existing evidence.',
      inputs: ['function_disassembly', 'vm_workflow_plan', 'api_hash_resolution'],
      outputs: ['symbolic_seed_set'],
      safety: ['metadata_only'],
    },
    {
      id: 'semantics-model',
      title: 'Instruction semantics model',
      purpose:
        'Prepare architecture, calling convention, memory map, and taint sources for a future Triton worker.',
      inputs: ['symbolic_seed_set', 'pe_structure', 'elf_structure', 'macho_structure'],
      outputs: ['triton_semantics_model'],
      safety: ['plan_only'],
    },
    {
      id: 'constraint-recovery',
      title: 'Constraint recovery plan',
      purpose:
        'Plan path predicate, keygen, opaque predicate, and API resolver constraint extraction.',
      inputs: ['triton_semantics_model'],
      outputs: ['path_constraints', 'symbolic_trace'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'jonathansalwan-triton',
      name: 'JonathanSalwan/Triton',
      source: 'https://github.com/JonathanSalwan/Triton',
      role: 'Dynamic binary analysis and symbolic execution backend for bounded instruction-level workflows.',
      readiness: 'optional_external',
      notes: [
        'Use only after selecting explicit bounded ranges or functions.',
        'Do not run emulation or symbolic execution from discovery/readiness paths.',
      ],
    },
  ],
  recommendedNextTools: [
    'constraint.extract',
    'smt.solve',
    'vm.workflow.plan',
    'analysis.evidence.graph',
  ],
  safetyNotes: [
    'Triton plans may reference emulation semantics, but this tool never starts Unicorn or Triton.',
    'Future workers must require explicit bounded address ranges and timeout budgets.',
  ],
}

const tritonPlugin = definePlugin({
  id: 'triton',
  name: 'Triton Symbolic Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'shellcode', 'firmware'],
      findings: ['vm_detect', 'opaque-predicate', 'api-hash', 'keygen', 'symbolic'],
    },
    category: 'symbolic-execution',
  },
  description:
    'Passive Triton symbolic execution and taint-analysis planning for bounded reverse-engineering workflows.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'TRITON_PYTHON',
      description: 'Optional Python interpreter with Triton installed for a future bounded worker',
      required: false,
      defaultValue: 'python3',
    },
  ],
  systemDeps: [
    {
      type: 'python',
      name: 'triton',
      importName: 'triton',
      required: false,
      description: 'Triton dynamic binary analysis library',
      dockerInstall: 'pip install triton-library or provide a pinned build',
      dockerFeature: 'dynamic-python',
      dockerValidation: ['python3 -c "import triton; print(\'triton ok\')" || true'],
      extraEnv: { TRITON_PYTHON: 'python3' },
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default tritonPlugin
