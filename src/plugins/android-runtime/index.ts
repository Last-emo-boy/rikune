import { definePlugin, defineTool } from '../sdk.js'
import {
  buildRuntimePlanAspects,
  buildRuntimePlanPolicy,
  createRuntimePlanHandler,
  createRuntimePlanToolDefinition,
  type RuntimePlanSpec,
} from '../runtime-plan.js'

const spec: RuntimePlanSpec = {
  pluginId: 'android-runtime',
  toolName: 'android.runtime.plan',
  description:
    'Build a passive Android dynamic-analysis plan for APK, AAB, split APKs, DEX/OAT/VDex, and native libraries across ADB, emulator, and Frida without installing, launching, or attaching.',
  platform: 'android',
  formats: [
    'android-package',
    'apk',
    'aab',
    'apks',
    'xapk',
    'split-apk',
    'dex',
    'multi-dex',
    'oat',
    'vdex',
    'odex',
    'aar',
  ],
  runtimes: ['adb', 'android-emulator', 'frida', 'frida-server'],
  capabilities: [
    'readiness',
    'hook-plan',
    'emulator-plan',
    'device-gating',
    'classloader-trace-plan',
  ],
  evidence: [
    'timeline',
    'behavior',
    'method-calls',
    'class-loads',
    'crypto',
    'filesystem',
    'network',
  ],
  recommendedStaticTools: [
    'android.package.inventory',
    'apk.structure.analyze',
    'dex.classes.list',
    'apk.manifest.parse',
    'frida.script.generate',
  ],
  recommendedControlTools: ['dynamic.runtime.status', 'dynamic.toolkit.status'],
  backends: [
    {
      backend: 'adb',
      purpose:
        'ADB readiness and device/emulator command plan without install, push, launch, or logcat capture.',
      readiness_checks: [
        'adb available',
        'device/emulator explicitly selected',
        'install policy approved',
      ],
      setup_tools: ['dynamic.toolkit.status'],
      execution_tools: ['android.runtime.plan'],
      evidence: ['provenance', 'timeline'],
      limitations: ['This planner does not connect to devices or install packages.'],
    },
    {
      backend: 'android-emulator',
      purpose: 'Isolated emulator execution plan for APK behavior capture after explicit opt-in.',
      readiness_checks: [
        'emulator backend available',
        'snapshot policy selected',
        'network policy selected',
      ],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['android.runtime.plan', 'frida.trace.capture'],
      evidence: ['method-calls', 'filesystem', 'network', 'timeline'],
      limitations: ['Do not auto-start emulator or install APKs from readiness paths.'],
    },
    {
      backend: 'frida',
      purpose:
        'Frida hook plan for root bypass, SSL pinning bypass, crypto trace, classloader trace, and API monitoring.',
      readiness_checks: [
        'Frida tools available',
        'target process/package known',
        'script intent reviewed',
      ],
      setup_tools: ['frida.script.generate', 'dynamic.toolkit.status'],
      execution_tools: ['frida.script.inject', 'frida.trace.capture', 'frida.runtime.instrument'],
      evidence: ['method-calls', 'class-loads', 'crypto', 'network', 'filesystem'],
      limitations: ['Bypass scripts are high-risk and require explicit opt-in.'],
    },
    {
      backend: 'frida-server',
      purpose: 'Device-side Frida server readiness plan.',
      readiness_checks: ['Frida server version compatible', 'device trust boundary approved'],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['frida.trace.capture'],
      evidence: ['method-calls', 'timeline'],
      limitations: ['This planner does not deploy or start frida-server.'],
    },
  ],
  staticCorrelation: [
    'Map manifest permissions, exported components, receivers, providers, and URL schemes to hook targets.',
    'Map DEX class/package names and native libraries to Frida script templates and emulator trace scope.',
    'Map split APK/APKS/XAPK layout to install plan requirements without installing by default.',
  ],
  safetyNotes: [
    'Do not start emulator, run adb install, push files, launch APKs, deploy frida-server, or attach Frida from this planner.',
    'Root bypass and SSL bypass scripts require explicit opt-in and clear evidence provenance.',
  ],
  nextActions: [
    'Run android.package.inventory and dex.classes.list to identify components and class targets.',
    'Generate hook templates with frida.script.generate while keeping injection disabled.',
    'Use tool.readiness before any adb, emulator, or Frida-backed dynamic tool.',
  ],
}

const androidRuntimePlugin = definePlugin({
  id: 'android-runtime',
  name: 'Android Runtime Plan',
  executionDomain: 'dynamic',
  aspects: buildRuntimePlanAspects(spec),
  runtimePolicy: buildRuntimePlanPolicy(spec),
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: [
        'android-package',
        'apk',
        'aab',
        'apks',
        'xapk',
        'split-apk',
        'dex',
        'oat',
        'vdex',
      ],
    },
    category: 'android-analysis',
  },
  description:
    'Passive Android runtime planning for ADB/emulator/Frida readiness, APK hook plans, and behavior evidence mapping.',
  version: '1.0.0',
  resources: { scripts: 'scripts' },
  tools: [
    defineTool({
      ...createRuntimePlanToolDefinition(spec),
      handler: createRuntimePlanHandler(spec),
    }),
  ],
})

export default androidRuntimePlugin
