import { definePlugin, defineTool } from '../sdk.js'
import {
  buildRuntimePlanAspects,
  buildRuntimePlanPolicy,
  createRuntimePlanHandler,
  createRuntimePlanToolDefinition,
  type RuntimePlanSpec,
} from '../runtime-plan.js'

const spec: RuntimePlanSpec = {
  pluginId: 'ios-runtime',
  toolName: 'ios.runtime.plan',
  description:
    'Build a passive iOS dynamic-analysis plan for IPA, Mach-O, app bundles, provisioning profiles, and entitlements across Frida iOS and idevice tooling without installing or attaching to a device.',
  platform: 'ios',
  formats: [
    'ipa',
    'macho',
    'fat',
    'universal',
    'app-bundle',
    'mobileprovision',
    'entitlements',
    'plist',
  ],
  runtimes: ['frida', 'idevice-tools', 'lldb'],
  capabilities: [
    'readiness',
    'hook-plan',
    'device-gating',
    'provisioning-plan',
    'method-trace-plan',
  ],
  evidence: ['timeline', 'behavior', 'method-calls', 'filesystem', 'network', 'code-signature'],
  recommendedStaticTools: [
    'apple.container.inventory',
    'apple.signing.inspect',
    'macho.structure.analyze',
    'frida.script.generate',
  ],
  recommendedControlTools: ['dynamic.runtime.status', 'dynamic.toolkit.status'],
  backends: [
    {
      backend: 'frida',
      purpose:
        'iOS hook planning for Objective-C/Swift method calls, crypto, filesystem, and network APIs.',
      readiness_checks: [
        'Frida tooling available',
        'device or simulator explicitly selected',
        'provisioning and consent reviewed',
      ],
      setup_tools: ['frida.script.generate', 'dynamic.toolkit.status'],
      execution_tools: ['frida.script.inject', 'frida.trace.capture', 'frida.runtime.instrument'],
      evidence: ['method-calls', 'network', 'filesystem', 'timeline'],
      limitations: [
        'Requires explicit device/simulator opt-in and may require jailbreak/dev profile constraints.',
      ],
    },
    {
      backend: 'idevice-tools',
      purpose: 'Device readiness and app metadata collection plan without install/launch.',
      readiness_checks: [
        'idevice tools present',
        'device pairing approved',
        'target bundle ID known',
      ],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['ios.runtime.plan'],
      evidence: ['provenance', 'code-signature'],
      limitations: ['This planner does not install IPA files or connect to a device.'],
    },
    {
      backend: 'lldb',
      purpose: 'Debugger handoff plan for simulator or explicitly approved device sessions.',
      readiness_checks: [
        'macOS host available',
        'debug entitlement/provisioning reviewed',
        'target process selected',
      ],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['runtime.debug.session.start', 'runtime.debug.command'],
      evidence: ['process', 'memory', 'method-calls', 'timeline'],
    },
  ],
  staticCorrelation: [
    'Map IPA Info.plist, entitlements, URL schemes, and permissions to hook targets.',
    'Map Mach-O imports and Objective-C/Swift metadata to Frida script generation.',
    'Map provisioning profile and code signature data to device/simulator readiness gates.',
  ],
  safetyNotes: [
    'Do not install IPA files, start a simulator, connect to a device, inject Frida, or attach LLDB from this planner.',
    'Treat device/provisioning operations as explicit opt-in dynamic work.',
  ],
  nextActions: [
    'Run apple.container.inventory and apple.signing.inspect before selecting iOS runtime hooks.',
    'Generate scripts with frida.script.generate while keeping injection disabled.',
    'Use tool.readiness and dynamic.runtime.status before any device or simulator interaction.',
  ],
}

const iosRuntimePlugin = definePlugin({
  id: 'ios-runtime',
  name: 'iOS Runtime Plan',
  executionDomain: 'dynamic',
  aspects: buildRuntimePlanAspects(spec),
  runtimePolicy: buildRuntimePlanPolicy(spec),
  surfaceRules: {
    tier: 2,
    activateOn: { fileTypes: ['ipa', 'macho', 'mobileprovision', 'entitlements', 'app-bundle'] },
    category: 'dynamic-analysis',
  },
  description:
    'Passive iOS runtime planning for IPA hook plans, Frida/idevice readiness, provisioning gates, and method trace evidence.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...createRuntimePlanToolDefinition(spec),
      handler: createRuntimePlanHandler(spec),
    }),
  ],
})

export default iosRuntimePlugin
