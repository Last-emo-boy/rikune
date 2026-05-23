import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'miasm',
  toolName: 'miasm.ir.plan',
  title: 'Miasm IR and symbolic workflow plan',
  description:
    'Build a passive Miasm integration plan for disassembly, IR lifting, data-flow, and symbolic execution without launching Python workers or executing the sample.',
  backendName: 'Miasm',
  formats: ['pe', 'elf', 'macho', 'shellcode', 'firmware'],
  platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips'],
  capabilities: [
    'ir-lifting',
    'data-flow',
    'symbolic-execution',
    'deobfuscation-plan',
    'cfg-recovery',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'behavior', 'artifact'],
  artifactType: 'miasm_ir_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'miasm.ir.deobfuscation-plan',
    title: 'Miasm IR deobfuscation planning',
    description:
      'Plan Miasm-backed IR lifting, data-flow simplification, and symbolic workflows from existing disassembly and obfuscation evidence without starting a backend by default.',
    startsWith: ['miasm.ir.plan', 'obfuscation.detect', 'code.function.disassemble'],
    nextTools: ['code.function.cfg', 'constraint.extract', 'smt.solve', 'analysis.evidence.graph'],
    requiredArtifacts: ['function_disassembly', 'obfuscation_detection'],
    producesArtifacts: ['miasm_ir_plan', 'miasm_ir_graph', 'data_flow_summary'],
    evidence: ['structure', 'behavior', 'artifact', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'target-scope',
      title: 'Target scope selection',
      purpose:
        'Select functions, shellcode windows, or basic blocks with obfuscation and CFG evidence.',
      inputs: ['function_disassembly', 'obfuscation_detection', 'code_cfg'],
      outputs: ['miasm_scope_plan'],
      safety: ['metadata_only'],
    },
    {
      id: 'ir-lift',
      title: 'IR lifting plan',
      purpose:
        'Prepare architecture, address-space, and block boundaries for future Miasm IR lifting.',
      inputs: ['miasm_scope_plan'],
      outputs: ['miasm_ir_graph'],
      safety: ['plan_only'],
    },
    {
      id: 'data-flow',
      title: 'Data-flow simplification plan',
      purpose: 'Plan constant propagation, opaque predicate review, and expression simplification.',
      inputs: ['miasm_ir_graph'],
      outputs: ['data_flow_summary', 'symbolic_expression_plan'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'cea-sec-miasm',
      name: 'cea-sec/miasm',
      source: 'https://github.com/cea-sec/miasm',
      role: 'Python reverse-engineering framework for disassembly, IR, data-flow, and symbolic analysis.',
      readiness: 'optional_external',
      notes: [
        'Keep backend optional and bounded; Miasm should not load arbitrary samples during readiness.',
        'Use future workers on selected ranges/functions only, with strict timeout and artifact budgets.',
      ],
    },
  ],
  recommendedNextTools: [
    'code.function.cfg',
    'constraint.extract',
    'smt.solve',
    'analysis.evidence.graph',
  ],
  safetyNotes: [
    'Miasm integration starts as metadata-only planning.',
    'Future execution must be a bounded static worker, not a default plugin load action.',
  ],
}

const miasmPlugin = definePlugin({
  id: 'miasm',
  name: 'Miasm IR Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'shellcode', 'firmware'],
      findings: ['obfuscated', 'opaque-predicate', 'cfg', 'symbolic', 'deobfuscation-needed'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive Miasm IR, data-flow, and symbolic workflow planning for obfuscated native code.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'MIASM_PYTHON',
      description: 'Optional Python interpreter with Miasm installed for a future bounded worker',
      required: false,
      defaultValue: 'python3',
    },
  ],
  systemDeps: [
    {
      type: 'python',
      name: 'miasm',
      importName: 'miasm',
      required: false,
      description: 'Miasm reverse-engineering framework',
      dockerInstall: 'pip install miasm or provide a pinned source checkout',
      dockerFeature: 'dynamic-python',
      dockerValidation: ['python3 -c "import miasm; print(\'miasm ok\')" || true'],
      extraEnv: { MIASM_PYTHON: 'python3' },
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'license-gated',
      dockerInstallNotes: ['GPL-2.0 backend; excluded from default Docker backend profile.'],
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default miasmPlugin
