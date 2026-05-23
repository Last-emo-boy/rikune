import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'radare2',
  toolName: 'radare2.pipeline.plan',
  title: 'radare2 compatibility pipeline plan',
  description:
    'Build a passive radare2/r2pipe compatibility plan for cross-checking Rizin, Ghidra, and RetDec results without starting radare2 or analyzing the sample.',
  backendName: 'radare2',
  formats: ['pe', 'elf', 'macho', 'wasm', 'firmware', 'shellcode', 'object'],
  platforms: ['windows', 'linux', 'macos', 'ios', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc', 'riscv', 'wasm'],
  capabilities: [
    'r2pipe-integration-plan',
    'cross-backend-comparison',
    'function-discovery',
    'xref-correlation',
    'string-correlation',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'imports', 'exports', 'strings', 'artifact'],
  artifactType: 'radare2_pipeline_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'radare2.cross-backend.plan',
    title: 'radare2 cross-backend comparison planning',
    description:
      'Plan radare2-backed comparison against Rizin, Ghidra, RetDec, and native structure artifacts without invoking radare2 by default.',
    startsWith: ['radare2.pipeline.plan', 'rizin.analyze'],
    nextTools: ['rizin.analyze', 'ghidra.analyze', 'retdec.decompile', 'analysis.evidence.graph'],
    requiredArtifacts: ['backend_rizin_analysis', 'ghidra_analysis', 'pe_structure'],
    producesArtifacts: ['radare2_pipeline_plan', 'radare2_function_index'],
    evidence: ['structure', 'symbols', 'strings', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'backend-gap',
      title: 'Backend gap review',
      purpose:
        'Identify where Rizin, Ghidra, RetDec, or native structure analyzers disagree before selecting radare2.',
      inputs: ['backend_rizin_analysis', 'ghidra_analysis', 'retdec_decompile', 'pe_structure'],
      outputs: ['radare2_gap_review'],
      safety: ['metadata_only'],
    },
    {
      id: 'r2pipe-plan',
      title: 'r2pipe command plan',
      purpose:
        'Prepare bounded command sets for info, functions, strings, xrefs, sections, and imports/exports.',
      inputs: ['radare2_gap_review'],
      outputs: ['radare2_pipeline_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'comparison',
      title: 'Cross-backend comparison plan',
      purpose:
        'Plan comparison of radare2 function and xref output against Rizin/Ghidra without executing the backend here.',
      inputs: ['radare2_pipeline_plan'],
      outputs: ['radare2_function_index', 'cross_backend_function_diff'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'radareorg-radare2',
      name: 'radareorg/radare2',
      source: 'https://github.com/radareorg/radare2',
      role: 'Reverse-engineering framework and r2pipe backend for comparison with Rizin/Ghidra results.',
      readiness: 'optional_external',
      notes: [
        'Use as a compatibility backend, not as the default Rizin replacement.',
        'Pin version and command profile before enabling automated r2pipe workers.',
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
    'radare2 is never started from this planner.',
    'Future workers must use bounded command allowlists and timeout budgets.',
  ],
}

const radare2Plugin = definePlugin({
  id: 'radare2',
  name: 'radare2 Pipeline Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'wasm', 'firmware', 'shellcode', 'object'],
      findings: ['cross-backend-check', 'function-gap', 'xref-gap', 'low-decompiler-confidence'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive radare2 compatibility planning for cross-backend reverse-engineering comparison.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'RADARE2_PATH',
      description: 'Optional radare2 binary path for a future bounded backend worker',
      required: false,
      defaultValue: 'radare2',
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'radare2',
      target: '$RADARE2_PATH',
      envVar: 'RADARE2_PATH',
      dockerDefault: '/usr/local/bin/radare2',
      versionFlag: '-v',
      required: false,
      description: 'radare2 reverse-engineering framework',
      dockerInstall: 'Install radare2 from distro packages or provide a pinned release',
      dockerFeature: 'radare2',
      aptPackages: ['radare2'],
      dockerValidation: ['radare2 -v >/dev/null 2>&1', 'rabin2 -h >/dev/null 2>&1'],
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

export default radare2Plugin
