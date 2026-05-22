import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'culifter',
  toolName: 'culifter.gpu.plan',
  title: 'CuLifter GPU binary lifting plan',
  description:
    'Build a passive CuLifter-style GPU binary lifting plan for CUDA/SASS artifacts without running a lifter, GPU driver, profiler, or sample.',
  backendName: 'CuLifter',
  formats: ['elf', 'so', 'linux-binary', 'object', 'static-lib', 'firmware'],
  platforms: ['linux', 'embedded', 'cross-platform'],
  architectures: ['cuda', 'sass', 'ptx', 'gpu'],
  capabilities: [
    'gpu-binary-lifting-plan',
    'sass-lifting-plan',
    'ptx-correlation',
    'llvm-ir-plan',
    'accelerator-reversing',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'imports', 'exports', 'artifact'],
  artifactType: 'culifter_gpu_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'culifter.gpu.lift-plan',
    title: 'CuLifter GPU binary lifting planning',
    description:
      'Plan GPU binary inventory, SASS/PTX correlation, and future lift-to-IR workflows from passive ELF/native object evidence.',
    startsWith: ['culifter.gpu.plan', 'linux.binary.inventory', 'native.object.inventory'],
    nextTools: [
      'linux.binary.inventory',
      'native.object.inventory',
      'remill.lift.plan',
      'sbom.provenance.graph',
    ],
    requiredArtifacts: ['linux_binary_inventory', 'native_object_inventory', 'elf_structure'],
    producesArtifacts: ['culifter_gpu_plan', 'sass_lift_plan', 'gpu_ir_handoff_plan'],
    evidence: ['structure', 'symbols', 'imports', 'exports', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'gpu-artifact-inventory',
      title: 'GPU artifact inventory',
      purpose:
        'Identify CUDA, SASS, PTX, fatbin, cubin, and GPU symbol hints from existing ELF/object evidence.',
      inputs: [
        'linux_binary_inventory',
        'native_object_inventory',
        'elf_structure',
        'enriched_string_analysis',
      ],
      outputs: ['gpu_artifact_inventory'],
      safety: ['metadata_only'],
    },
    {
      id: 'sass-lift-plan',
      title: 'SASS lift plan',
      purpose:
        'Prepare bounded kernel ranges, architecture tags, constant memory, and PTX/SASS correlation expectations.',
      inputs: ['gpu_artifact_inventory'],
      outputs: ['sass_lift_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'ir-handoff',
      title: 'GPU IR handoff plan',
      purpose:
        'Plan future lifted IR, kernel CFG, and host/device correlation artifacts without requiring GPU execution.',
      inputs: ['sass_lift_plan'],
      outputs: ['gpu_ir_handoff_plan', 'gpu_kernel_cfg_plan'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'culifter-research',
      name: 'CuLifter research direction',
      source: 'https://arxiv.org/abs/2604.27486',
      role: 'GPU binary lifting design target for future CUDA/SASS-to-IR workflows.',
      readiness: 'future_worker',
      notes: [
        'Treat the paper as a design target until a pinned implementation is selected.',
        'Do not require GPU hardware, driver access, profiling, or code execution from planner paths.',
      ],
    },
  ],
  recommendedNextTools: [
    'linux.binary.inventory',
    'native.object.inventory',
    'strings.extract',
    'sbom.provenance.graph',
  ],
  safetyNotes: [
    'CuLifter planning does not start GPU drivers, profilers, emulators, lifters, or sample execution.',
    'Future workers must operate on local binary artifacts only and not require GPU hardware in CI.',
  ],
}

const culifterPlugin = definePlugin({
  id: 'culifter',
  name: 'CuLifter GPU Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['elf', 'so', 'linux-binary', 'object', 'static-lib', 'firmware'],
      findings: ['cuda', 'gpu', 'sass', 'ptx', 'accelerator'],
    },
    category: 'reverse-engineering',
  },
  description: 'Passive CuLifter-style CUDA/SASS GPU binary lifting planning.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'CULIFTER_WORKER_PATH',
      description: 'Optional future CuLifter worker path',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'culifter-worker',
      target: '$CULIFTER_WORKER_PATH',
      envVar: 'CULIFTER_WORKER_PATH',
      required: false,
      description: 'Optional future CuLifter worker',
      dockerInstall: 'Provide a pinned local CuLifter worker; not installed by default',
      dockerFeature: 'culifter',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default culifterPlugin
