import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'wabt',
  toolName: 'wabt.toolchain.plan',
  title: 'WABT WebAssembly toolchain plan',
  description:
    'Build a passive WABT integration plan for wasm2wat, wasm-objdump, wasm-decompile, wasm2c, and WASI capability review without instantiating or executing the module.',
  backendName: 'WABT',
  formats: ['wasm', 'wasi', 'wat'],
  platforms: ['wasm', 'cross-platform'],
  architectures: ['wasm'],
  capabilities: [
    'wasm-disassembly-plan',
    'wasm-decompile-plan',
    'wasm2c-plan',
    'wasi-capability-review',
    'cross-toolchain-comparison',
    'workflow-routing',
  ],
  evidence: ['structure', 'imports', 'exports', 'artifact'],
  artifactType: 'wabt_toolchain_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'wabt.wasm.toolchain-plan',
    title: 'WABT WebAssembly toolchain planning',
    description:
      'Plan WABT-backed wasm2wat, wasm-objdump, wasm-decompile, and wasm2c analysis from passive WASM inventory without starting a WASM runtime.',
    startsWith: ['wasm.structure.analyze', 'wabt.toolchain.plan'],
    nextTools: ['strings.extract', 'sbom.generate', 'wasm.runtime.plan', 'analysis.evidence.graph'],
    requiredArtifacts: ['wasm_structure'],
    producesArtifacts: ['wabt_toolchain_plan', 'wat_disassembly_plan', 'wasm2c_translation_plan'],
    evidence: ['structure', 'imports', 'exports', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'wasm-inventory',
      title: 'WASM inventory correlation',
      purpose:
        'Correlate existing WASM sections, imports, exports, custom sections, strings, and SBOM evidence.',
      inputs: ['wasm_structure', 'enriched_string_analysis', 'sbom_document'],
      outputs: ['wabt_input_inventory'],
      safety: ['metadata_only'],
    },
    {
      id: 'tool-selection',
      title: 'WABT tool selection plan',
      purpose:
        'Choose bounded wasm2wat, wasm-objdump, wasm-decompile, wasm2c, and wasm-validate outputs.',
      inputs: ['wabt_input_inventory'],
      outputs: ['wabt_toolchain_plan', 'wat_disassembly_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'runtime-correlation',
      title: 'Runtime correlation plan',
      purpose:
        'Map WABT outputs to WASI import risk, wasm.runtime.plan gates, and cross-toolchain validation.',
      inputs: ['wabt_toolchain_plan', 'wat_disassembly_plan'],
      outputs: ['wasm2c_translation_plan', 'wasi_capability_review'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'webassembly-wabt',
      name: 'WebAssembly/wabt',
      source: 'https://github.com/WebAssembly/wabt',
      role: 'WebAssembly Binary Toolkit for passive disassembly, objdump, decompile, validation, and wasm2c planning.',
      readiness: 'optional_external',
      notes: [
        'Use WABT tools only through future bounded workers and local artifact paths.',
        'Do not instantiate modules or grant WASI resources from WABT workflows.',
      ],
    },
  ],
  recommendedNextTools: [
    'wasm.structure.analyze',
    'strings.extract',
    'sbom.generate',
    'wasm.runtime.plan',
  ],
  safetyNotes: [
    'This planner never instantiates WASM modules or starts wasmtime.',
    'Future WABT workers must keep filesystem/network capability grants out of scope.',
  ],
}

const wabtPlugin = definePlugin({
  id: 'wabt',
  name: 'WABT Toolchain Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['wasm', 'wasi', 'wat'],
      findings: ['wasi', 'wasm-decompile', 'toolchain-comparison'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive WABT WebAssembly toolchain planning for wasm2wat, wasm-objdump, wasm-decompile, wasm2c, and WASI review.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'WABT_PATH',
      description: 'Optional directory containing WABT binaries for a future bounded worker',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'directory',
      name: 'wabt',
      target: '$WABT_PATH',
      envVar: 'WABT_PATH',
      dockerDefault: '/opt/wabt/bin',
      required: false,
      description: 'WebAssembly Binary Toolkit binaries',
      dockerInstall: 'Install a pinned WABT release to /opt/wabt',
      dockerFeature: 'wabt',
      dockerValidation: [
        '/opt/wabt/bin/wasm2wat --help >/dev/null 2>&1',
        '/opt/wabt/bin/wasm-objdump --help >/dev/null 2>&1',
      ],
      buildArgs: { WABT_VERSION: '1.0.39' },
      dockerInstallRoute: 'installed',
      dockerInstallProfile: 'default',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default wabtPlugin
