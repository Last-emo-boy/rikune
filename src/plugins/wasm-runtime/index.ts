import { definePlugin, defineTool, type ToolDefinition } from '../sdk.js'
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
  formats: ['wasm', 'wasi', 'wat'],
  runtimes: ['wasmtime'],
  capabilities: [
    'readiness',
    'wasi-capability-plan',
    'wasi-import-review',
    'import-export-mapping',
    'resource-grant-review',
    'preopen-policy-review',
    'network-policy-review',
    'custom-section-provenance',
    'sandbox-plan',
  ],
  evidence: [
    'structure',
    'timeline',
    'behavior',
    'imports',
    'exports',
    'wasi-capability',
    'custom-section',
    'resource-grant',
    'filesystem',
    'network',
    'workflow',
    'provenance',
  ],
  recommendedStaticTools: [
    'wasm.structure.analyze',
    'wabt.toolchain.plan',
    'strings.extract',
    'sbom.generate',
    'artifact.read',
    'analysis.evidence.graph',
  ],
  recommendedControlTools: [
    'tool.readiness',
    'artifact.read',
    'analysis.evidence.graph',
    'dynamic.runtime.status',
    'dynamic.toolkit.status',
  ],
  backends: [
    {
      backend: 'wasmtime',
      purpose: 'Isolated WASM/WASI runtime plan for import/export and capability validation.',
      readiness_checks: [
        'wasmtime available',
        'WASI preopens disabled until explicitly selected',
        'WASI resource grants disabled until explicitly selected',
        'network policy remains disabled by default',
      ],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['wasm.runtime.plan'],
      evidence: [
        'structure',
        'imports',
        'exports',
        'wasi-capability',
        'custom-section',
        'resource-grant',
        'filesystem',
        'network',
        'timeline',
        'provenance',
      ],
      limitations: [
        'This planner does not instantiate the WASM module or grant WASI resources.',
        'No WASI preopens, filesystem grants, resource grants, or network access are created.',
      ],
    },
  ],
  staticCorrelation: [
    'Map WASI imports, custom sections, exports, and memory/table sections to runtime capability gates.',
    'Map static strings and SBOM hints to preopen/network policy review before any runtime execution.',
    'Map custom-section provenance and resource-grant requests to analysis.evidence.graph before any wasmtime session.',
  ],
  safetyNotes: [
    'Do not instantiate WASM, start wasmtime, grant filesystem preopens, grant WASI resources, or allow network from this planner.',
    'Keep WASI resource grants, preopens, and network disabled until explicit opt-in.',
  ],
  nextActions: [
    'Run wasm.structure.analyze first to identify WASI imports and custom sections.',
    'Use tool.readiness for any runtime-backed WASM execution tool before instantiation.',
    'Use artifact.read and analysis.evidence.graph to carry wasm_structure provenance into runtime planning.',
    'Review filesystem/network resource grants separately from module analysis.',
  ],
}

const wasmRuntimeAspects = {
  ...buildRuntimePlanAspects(spec),
  architectures: ['wasm', 'wasm32'],
}

const baseRuntimePolicy = buildRuntimePlanPolicy(spec)
const wasmRuntimePolicy = {
  ...baseRuntimePolicy,
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noInstantiation: true,
  noWasiGrants: true,
  noResourceGrants: true,
  resourceGrants: 'none',
  wasiPreopens: [],
  networkDefault: 'disabled',
  notes: [
    ...baseRuntimePolicy.notes,
    'No WASI preopens, filesystem grants, resource grants, or network access are created by wasm.runtime.plan.',
    'Static wasm_structure, WAT, custom-section, import/export, and provenance evidence should be reviewed before explicit runtime opt-in.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noInstantiation: true
  noWasiGrants: true
  noResourceGrants: true
  resourceGrants: 'none'
  wasiPreopens: []
  networkDefault: 'disabled'
}

const wasmRuntimeToolDefinition = createRuntimePlanToolDefinition(spec)

function createWasmRuntimePlanHandler() {
  const baseHandler = createRuntimePlanHandler(spec)
  return async (args: Parameters<typeof baseHandler>[0]) => {
    const result = await baseHandler(args)
    if (!result.ok || !result.data || typeof result.data !== 'object') return result

    const data = result.data as Record<string, unknown>
    const recommendedNextTools = Array.isArray(data.recommended_next_tools)
      ? (data.recommended_next_tools as string[])
      : []
    const safetyNotes = Array.isArray(data.safety_notes) ? (data.safety_notes as string[]) : []

    return {
      ...result,
      data: {
        ...data,
        policy: wasmRuntimePolicy,
        runtime_handoff: {
          from_static_tool: 'wasm.structure.analyze',
          static_artifact_type: 'wasm_structure',
          required_before_execution: [
            'wasm.runtime.plan',
            'tool.readiness',
            'analysis.evidence.graph',
            'artifact.read',
          ],
          execution_constraints: {
            no_instantiation: true,
            no_wasi_grants: true,
            no_network: true,
            resource_grants: 'none',
          },
        },
        recommended_next_tools: Array.from(
          new Set([
            ...recommendedNextTools,
            'wasm.runtime.plan',
            'tool.readiness',
            'analysis.evidence.graph',
            'artifact.read',
          ])
        ),
        safety_notes: Array.from(
          new Set([
            ...safetyNotes,
            'No WASI preopens, filesystem grants, resource grants, or network access were created.',
          ])
        ),
      },
    }
  }
}

const wasmRuntimePlugin = definePlugin({
  id: 'wasm-runtime',
  name: 'WASM Runtime Plan',
  executionDomain: 'dynamic',
  aspects: wasmRuntimeAspects,
  runtimePolicy: wasmRuntimePolicy,
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['wasm', 'wasi', 'wat'],
      findings: ['wasi', 'resource-grant', 'preopen', 'custom-section'],
    },
    category: 'dynamic-analysis',
  },
  description:
    'Passive WASM/WASI runtime planning for wasmtime readiness, capability review, and import/export behavior mapping.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'WASMTIME_PATH',
      description: 'Optional wasmtime binary path for explicit future WASM/WASI runtime sessions',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'wasmtime',
      target: '$WASMTIME_PATH',
      envVar: 'WASMTIME_PATH',
      dockerDefault: '/opt/wasmtime/bin/wasmtime',
      required: false,
      description:
        'Wasmtime runtime binary used only after explicit opt-in; wasm.runtime.plan does not execute it.',
      dockerInstall: 'Install a pinned wasmtime release to /opt/wasmtime',
      dockerFeature: 'wasmtime',
      dockerValidation: ['/opt/wasmtime/bin/wasmtime --version'],
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'runtime',
      dockerInstallNotes: [
        'Keep wasmtime disabled for default static and plan-only workflows.',
        'Enable only in an isolated runtime profile with explicit WASI resource grants.',
      ],
    },
  ],
  tools: [
    defineTool({
      ...wasmRuntimeToolDefinition,
      aspects: wasmRuntimeAspects,
      runtimePolicy: wasmRuntimePolicy,
      handler: createWasmRuntimePlanHandler(),
    }),
  ],
})

export default wasmRuntimePlugin
