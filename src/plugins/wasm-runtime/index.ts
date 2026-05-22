import { definePlugin, defineTool } from '../sdk.js'
import {
  buildRuntimePlanAspects,
  buildRuntimePlanPolicy,
  createRuntimePlanHandler,
  createRuntimePlanToolDefinition,
  type RuntimePlanSpec,
} from '../runtime-plan.js'

const spec: RuntimePlanSpec = {
  pluginId: 'wasm-runtime',
  toolName: 'wasm.runtime.plan',
  description:
    'Build a passive WebAssembly/WASI runtime plan for wasmtime-backed capability review and import/export behavior mapping without instantiating the module.',
  platform: 'wasm',
  formats: ['wasm', 'wasi'],
  runtimes: ['wasmtime'],
  capabilities: ['readiness', 'wasi-capability-plan', 'import-trace-plan', 'sandbox-plan'],
  evidence: ['timeline', 'behavior', 'imports', 'exports', 'filesystem', 'network'],
  recommendedStaticTools: ['wasm.structure.analyze', 'strings.extract', 'sbom.generate'],
  recommendedControlTools: ['dynamic.runtime.status', 'dynamic.toolkit.status'],
  backends: [
    {
      backend: 'wasmtime',
      purpose: 'Isolated WASM/WASI runtime plan for import/export and capability validation.',
      readiness_checks: [
        'wasmtime available',
        'WASI preopens and network policy explicitly selected',
      ],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['wasm.runtime.plan'],
      evidence: ['imports', 'exports', 'filesystem', 'network', 'timeline'],
      limitations: ['This planner does not instantiate the WASM module or grant WASI resources.'],
    },
  ],
  staticCorrelation: [
    'Map WASI imports, custom sections, exports, and memory/table sections to runtime capability gates.',
    'Map static strings and SBOM hints to preopen/network policy review before any runtime execution.',
  ],
  safetyNotes: [
    'Do not instantiate WASM, start wasmtime, grant filesystem preopens, or allow network from this planner.',
    'Keep WASI resource grants disabled until explicit opt-in.',
  ],
  nextActions: [
    'Run wasm.structure.analyze first to identify WASI imports and custom sections.',
    'Use tool.readiness for any runtime-backed WASM execution tool before instantiation.',
    'Review filesystem/network resource grants separately from module analysis.',
  ],
}

const wasmRuntimePlugin = definePlugin({
  id: 'wasm-runtime',
  name: 'WASM Runtime Plan',
  executionDomain: 'dynamic',
  aspects: buildRuntimePlanAspects(spec),
  runtimePolicy: buildRuntimePlanPolicy(spec),
  surfaceRules: {
    tier: 2,
    activateOn: { fileTypes: ['wasm', 'wasi'] },
    category: 'dynamic-analysis',
  },
  description:
    'Passive WASM/WASI runtime planning for wasmtime readiness, capability review, and import/export behavior mapping.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...createRuntimePlanToolDefinition(spec),
      handler: createRuntimePlanHandler(spec),
    }),
  ],
})

export default wasmRuntimePlugin
