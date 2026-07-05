import { definePlugin, defineTool } from '../sdk.js'
import {
  buildRuntimePlanAspects,
  buildRuntimePlanPolicy,
  createRuntimePlanHandler,
  createRuntimePlanToolDefinition,
  type RuntimePlanSpec,
} from '../runtime-plan.js'

const spec: RuntimePlanSpec = {
  pluginId: 'windows-runtime',
  toolName: 'windows.runtime.plan',
  description:
    'Build a passive Windows dynamic-analysis plan for PE/.NET binaries across Windows Sandbox, Hyper-V, host-agent, Wine, and Speakeasy without executing the sample.',
  platform: 'windows',
  formats: ['pe', 'dll', 'sys', 'efi', 'dotnet', 'pe-clr', 'msi', 'msix', 'appx'],
  runtimes: ['windows-sandbox', 'hyperv', 'windows-host-agent', 'wine', 'speakeasy'],
  capabilities: ['readiness', 'behavior-plan', 'debug-plan', 'telemetry-plan', 'registry-plan'],
  evidence: [
    'timeline',
    'behavior',
    'process',
    'filesystem',
    'registry',
    'network',
    'memory',
    'api-calls',
  ],
  recommendedStaticTools: [
    'pe.structure.analyze',
    'pe.imports.extract',
    'pe.exports.extract',
    'dotnet.assembly.inspect',
    'installer.inventory',
  ],
  recommendedControlTools: ['dynamic.runtime.status', 'dynamic.toolkit.status'],
  backends: [
    {
      backend: 'windows-sandbox',
      purpose:
        'Isolated live Windows execution with file, registry, network, and process telemetry.',
      readiness_checks: [
        'Host Agent reachable',
        'Sandbox feature enabled',
        'Runtime Node endpoint advertised',
      ],
      setup_tools: ['dynamic.runtime.status', 'dynamic.persona.plan'],
      execution_tools: ['sandbox.execute', 'debug.telemetry.plan', 'debug.network.plan'],
      evidence: ['process', 'filesystem', 'registry', 'network', 'timeline'],
      limitations: ['Requires explicit opt-in and an isolated Windows host.'],
    },
    {
      backend: 'hyperv',
      purpose:
        'Snapshot-backed Windows VM analysis for higher isolation or persistence-sensitive samples.',
      readiness_checks: [
        'Hyper-V available',
        'snapshot policy selected',
        'host-agent lifecycle policy configured',
      ],
      setup_tools: ['runtime.hyperv.control', 'dynamic.runtime.status'],
      execution_tools: ['runtime.debug.session.start', 'debug.cdb.plan', 'debug.procdump.plan'],
      evidence: ['process', 'memory', 'filesystem', 'registry', 'timeline'],
      limitations: ['Requires explicit lifecycle policy and VM snapshot hygiene.'],
    },
    {
      backend: 'windows-host-agent',
      purpose: 'Control-plane bridge for Windows Sandbox/Hyper-V runtime sessions.',
      readiness_checks: ['Host Agent endpoint reachable', 'runtime endpoint published'],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['runtime.debug.session.start', 'runtime.debug.command'],
      evidence: ['provenance', 'timeline'],
    },
    {
      backend: 'wine',
      purpose: 'Linux-hosted compatibility execution for PE behavior hints.',
      readiness_checks: ['Wine binary present', 'prefix policy selected'],
      setup_tools: ['wine.env', 'wine.dll_overrides'],
      execution_tools: ['wine.run', 'wine.reg'],
      evidence: ['api-calls', 'filesystem', 'registry', 'network'],
      limitations: [
        'Wine behavior is not equivalent to native Windows; record backend confidence.',
      ],
    },
    {
      backend: 'speakeasy',
      purpose: 'User-mode PE and shellcode emulation for API trace and anti-analysis hints.',
      readiness_checks: ['speakeasy Python package available'],
      setup_tools: ['dynamic.toolkit.status'],
      execution_tools: ['speakeasy.emulate', 'speakeasy.api_trace', 'speakeasy.shellcode'],
      evidence: ['api-calls', 'memory', 'timeline'],
      limitations: [
        'Coverage depends on emulator support and may miss native environment effects.',
      ],
    },
  ],
  staticCorrelation: [
    'Map PE imports and delay imports to API breakpoint or emulator trace candidates.',
    'Map resources, manifests, TLS callbacks, and .NET metadata to runtime setup and debugger plans.',
    'Map installer custom actions and nested payloads to sandbox telemetry profiles without installing by default.',
  ],
  safetyNotes: [
    'Do not start Windows Sandbox, Hyper-V, Wine, or Speakeasy from this planner.',
    'Keep network disabled or record-only until the user explicitly selects an isolated runtime.',
  ],
  nextActions: [
    'Run tool.readiness for the selected runtime-backed tool before live work.',
    'Use dynamic.runtime.status to inspect Host Agent and Runtime Node capability without launching a sample.',
    'Pair this plan with PE/static evidence before selecting breakpoints or telemetry.',
  ],
}

const windowsRuntimePlugin = definePlugin({
  id: 'windows-runtime',
  name: 'Windows Runtime Plan',
  executionDomain: 'dynamic',
  aspects: buildRuntimePlanAspects(spec),
  runtimePolicy: buildRuntimePlanPolicy(spec),
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['pe', 'dll', 'sys', 'efi', 'dotnet', 'pe-clr', 'msi', 'msix', 'appx'],
    },
    category: 'dynamic-analysis',
  },
  description:
    'Passive Windows runtime planning for Sandbox, Hyper-V, host-agent, Wine, Speakeasy, debugging, and telemetry evidence.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...createRuntimePlanToolDefinition(spec),
      handler: createRuntimePlanHandler(spec),
    }),
  ],
})

export default windowsRuntimePlugin
