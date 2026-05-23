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
  pluginId: 'qbdi',
  toolName: 'qbdi.instrumentation.plan',
  title: 'QBDI instrumentation plan',
  description:
    'Build a passive QBDI dynamic binary instrumentation handoff plan without loading a process, injecting instrumentation, or executing the sample.',
  backendName: 'QBDI',
  formats: ['pe', 'elf', 'macho', 'shellcode', 'firmware'],
  platforms: ['windows', 'linux', 'macos', 'android', 'ios', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64'],
  capabilities: [
    'dynamic-binary-instrumentation-plan',
    'instruction-trace-plan',
    'memory-access-trace-plan',
    'coverage-guided-triage',
    'runtime-handoff',
    'workflow-routing',
  ],
  evidence: ['structure', 'behavior', 'memory', 'timeline', 'artifact'],
  artifactType: 'qbdi_instrumentation_plan',
  category: 'dynamic-analysis',
  recipe: {
    id: 'qbdi.dbi.opt-in-plan',
    title: 'QBDI DBI opt-in planning',
    description:
      'Plan a QBDI instruction, memory-access, and coverage trace session from existing static/runtime evidence before explicit isolated execution.',
    startsWith: ['qbdi.instrumentation.plan', 'dynamic.runtime.status', 'tool.readiness'],
    nextTools: [
      'windows.runtime.plan',
      'linux.runtime.plan',
      'macos.runtime.plan',
      'dynamic.runtime.status',
      'analysis.evidence.graph',
    ],
    requiredArtifacts: ['function_disassembly', 'runtime_plan', 'vm_workflow_plan'],
    producesArtifacts: ['qbdi_instrumentation_plan', 'dbi_trace_plan', 'coverage_trace_plan'],
    evidence: ['structure', 'behavior', 'memory', 'timeline', 'workflow', 'provenance'],
    safety: [
      'passive',
      'opt_in_dynamic',
      'requires_isolation',
      'no_live_sample_by_default',
      'no_network_by_default',
    ],
    runtimeBackends: ['qbdi'],
  },
  defaultStages: [
    {
      id: 'trace-scope',
      title: 'Trace scope selection',
      purpose:
        'Select bounded functions, modules, memory ranges, and instruction events from existing static evidence.',
      inputs: ['function_disassembly', 'code_cfg', 'runtime_plan'],
      outputs: ['dbi_trace_scope'],
      safety: ['metadata_only'],
    },
    {
      id: 'instrumentation-contract',
      title: 'Instrumentation contract plan',
      purpose:
        'Prepare event filters, callback budgets, register/memory capture limits, and runtime isolation requirements.',
      inputs: ['dbi_trace_scope'],
      outputs: ['qbdi_instrumentation_plan', 'coverage_trace_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'runtime-handoff',
      title: 'Runtime handoff plan',
      purpose:
        'Route future DBI sessions through platform runtime plans and readiness checks before any live execution.',
      inputs: ['qbdi_instrumentation_plan'],
      outputs: ['dbi_runtime_handoff_plan'],
      safety: ['requires_explicit_runtime_opt_in'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'qbdi-qbdi',
      name: 'QBDI/QBDI',
      source: 'https://github.com/QBDI/QBDI',
      role: 'Dynamic binary instrumentation backend for bounded instruction, memory, and coverage traces.',
      readiness: 'optional_external',
      notes: [
        'Never load QBDI from discovery, profile, readiness, or planner paths.',
        'Require isolated runtime, explicit opt-in, timeout budgets, and artifact quotas before execution.',
      ],
    },
  ],
  recommendedNextTools: [
    'tool.readiness',
    'windows.runtime.plan',
    'linux.runtime.plan',
    'dynamic.runtime.status',
  ],
  safetyNotes: [
    'QBDI planning does not inject instrumentation, load a process, attach to a debugger, or execute code.',
    'Future DBI workers must be runtime-gated, isolated, opt-in, and network-disabled by default.',
  ],
}

const workerSpec: FrontierWorkerToolSpec = {
  pluginId: 'qbdi',
  toolName: 'qbdi.trace.run',
  description:
    'Dispatch a QBDI trace request through an explicit opt-in delegated runtime worker contract. This local MCP server never starts QBDI directly.',
  backendName: 'QBDI',
  adapter: 'qbdi.delegated.trace',
  backendKind: 'delegated-runtime',
  envVar: 'QBDI_PATH',
  aspects: buildBackendPlanAspects(spec),
  artifacts: [
    { type: 'qbdi_trace_artifact', description: 'Delegated QBDI trace artifact metadata' },
    { type: 'dbi_trace_summary', description: 'Instruction, coverage, and memory trace summary' },
  ],
  evidence: [
    { category: 'timeline', artifactTypes: ['qbdi_trace_artifact'] },
    { category: 'memory', artifactTypes: ['dbi_trace_summary'] },
  ],
  workflowRecipe: {
    id: 'qbdi.dbi.trace-worker',
    title: 'QBDI opt-in delegated trace worker',
    startsWith: ['qbdi.instrumentation.plan', 'tool.readiness', 'qbdi.trace.run'],
    nextTools: ['dynamic.runtime.status', 'analysis.evidence.graph', 'report.generate'],
    producesArtifacts: ['qbdi_trace_artifact', 'dbi_trace_summary'],
    evidence: ['timeline', 'memory', 'workflow', 'provenance'],
    safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_network_by_default'],
    runtimeBackends: ['qbdi'],
  },
  policy: {
    requiresUserOptIn: true,
    requiresIsolation: true,
    noLiveExecution: false,
    defaultTimeoutMs: 30_000,
  },
  readinessSetupActions: [
    'Attach a runtime endpoint that advertises QBDI before calling qbdi.trace.run.',
    'Pass approved=true only after analyst approval and isolation setup.',
  ],
  fixtureData: {
    trace_events: 0,
    delegated: true,
    runtime_required: true,
  },
  recommendedNextTools: ['dynamic.runtime.status', 'analysis.evidence.graph'],
}

const qbdiPlugin = definePlugin({
  id: 'qbdi',
  name: 'QBDI Instrumentation Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'shellcode', 'firmware'],
      findings: ['runtime-trace', 'coverage', 'anti-debug', 'vm_detect', 'dynamic-needed'],
    },
    category: 'dynamic-analysis',
  },
  description: 'Passive QBDI dynamic binary instrumentation handoff planning.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'QBDI_PATH',
      description: 'Optional QBDI runtime/tooling path for a future isolated worker',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'directory',
      name: 'qbdi',
      target: '$QBDI_PATH',
      envVar: 'QBDI_PATH',
      required: false,
      description: 'QBDI runtime and tooling directory',
      dockerInstall: 'Install or provide a pinned QBDI release; not installed by default',
      dockerFeature: 'qbdi',
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

export default qbdiPlugin
