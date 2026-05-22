import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'revng',
  toolName: 'revng.pipeline.plan',
  title: 'rev.ng lifting and decompilation plan',
  description:
    'Build a passive rev.ng integration plan for binary lifting, model recovery, CFG/export correlation, and decompilation without starting revng or processing the sample.',
  backendName: 'rev.ng',
  formats: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib'],
  platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
  capabilities: [
    'binary-lifting',
    'decompilation',
    'cfg-recovery',
    'type-recovery',
    'cross-backend-comparison',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'imports', 'exports', 'artifact'],
  artifactType: 'revng_pipeline_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'revng.lift-decompile.plan',
    title: 'rev.ng lift and decompile planning',
    description:
      'Plan a rev.ng-backed lift/decompile comparison flow from existing PE/ELF/Mach-O structure evidence, with Ghidra/Rizin/RetDec follow-ups and no backend invocation by default.',
    startsWith: ['revng.pipeline.plan', 'pe.structure.analyze', 'elf.structure.analyze'],
    nextTools: ['rizin.analyze', 'ghidra.analyze', 'retdec.decompile', 'analysis.evidence.graph'],
    requiredArtifacts: ['pe_structure', 'elf_structure', 'macho_structure'],
    producesArtifacts: ['revng_pipeline_plan', 'revng_lift_model', 'revng_decompile_artifact'],
    evidence: ['structure', 'symbols', 'artifact', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'inventory',
      title: 'Input inventory',
      purpose: 'Collect existing structure, import/export, symbol, and architecture evidence.',
      inputs: ['pe_structure', 'elf_structure', 'macho_structure', 'native_object_inventory'],
      outputs: ['revng_input_inventory'],
      safety: ['metadata_only'],
    },
    {
      id: 'lift-model',
      title: 'Lift model plan',
      purpose:
        'Prepare expected architecture, ABI, entrypoint, and relocation context for rev.ng model creation.',
      inputs: ['revng_input_inventory'],
      outputs: ['revng_lift_model'],
      safety: ['plan_only'],
    },
    {
      id: 'decompile-compare',
      title: 'Decompiler comparison plan',
      purpose: 'Compare future rev.ng output against Ghidra, Rizin, and RetDec artifacts.',
      inputs: ['revng_lift_model', 'ghidra_analysis', 'backend_rizin_functions'],
      outputs: ['revng_decompile_artifact', 'cross_backend_decompile_diff'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'revng-repo',
      name: 'revng/revng',
      source: 'https://github.com/revng/revng',
      role: 'Binary lifting and decompilation backend for cross-checking existing Ghidra/Rizin/RetDec results.',
      readiness: 'optional_external',
      notes: [
        'Keep optional because the backend is large and environment-sensitive.',
        'Use a pinned container or runtime worker before enabling actual execution.',
      ],
    },
  ],
  recommendedNextTools: [
    'rizin.analyze',
    'ghidra.analyze',
    'retdec.decompile',
    'analysis.evidence.graph',
  ],
  safetyNotes: [
    'rev.ng can be expensive and should not run during default discovery or readiness probes.',
    'Only invoke future workers on bounded local artifacts with explicit analyst opt-in.',
  ],
}

const revngPlugin = definePlugin({
  id: 'revng',
  name: 'rev.ng Pipeline Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib'],
      findings: ['decompilation-needed', 'low-decompiler-confidence', 'cross-backend-check'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive rev.ng binary lifting and decompilation planning for cross-backend reverse engineering.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'REVNG_PATH',
      description: 'Optional revng binary path for a future bounded backend worker',
      required: false,
      defaultValue: 'revng',
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'revng',
      target: '$REVNG_PATH',
      envVar: 'REVNG_PATH',
      versionFlag: '--version',
      required: false,
      description: 'rev.ng binary analysis framework',
      dockerInstall: 'Install a pinned rev.ng release or container image; not installed by default',
      dockerFeature: 'revng',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default revngPlugin
