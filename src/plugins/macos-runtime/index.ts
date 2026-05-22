import { definePlugin, defineTool } from '../sdk.js'
import {
  buildRuntimePlanAspects,
  buildRuntimePlanPolicy,
  createRuntimePlanHandler,
  createRuntimePlanToolDefinition,
  type RuntimePlanSpec,
} from '../runtime-plan.js'

const spec: RuntimePlanSpec = {
  pluginId: 'macos-runtime',
  toolName: 'macos.runtime.plan',
  description:
    'Build a passive macOS dynamic-analysis plan for Mach-O, universal binaries, app bundles, frameworks, PKG, and DMG samples across LLDB, DTrace, fs_usage, codesign runtime checks, and sandbox-exec without executing the sample.',
  platform: 'macos',
  formats: ['macho', 'fat', 'universal', 'dylib', 'framework', 'app-bundle', 'pkg', 'dmg', 'dsym'],
  runtimes: ['lldb', 'dtrace', 'fs-usage', 'sandbox-exec', 'codesign-runtime'],
  capabilities: [
    'readiness',
    'debug-plan',
    'filesystem-trace-plan',
    'codesign-plan',
    'sandbox-profile-plan',
  ],
  evidence: [
    'timeline',
    'behavior',
    'process',
    'filesystem',
    'network',
    'memory',
    'code-signature',
  ],
  recommendedStaticTools: [
    'macho.structure.analyze',
    'apple.container.inventory',
    'apple.signing.inspect',
    'native.object.inventory',
  ],
  recommendedControlTools: ['dynamic.runtime.status', 'dynamic.toolkit.status'],
  backends: [
    {
      backend: 'lldb',
      purpose:
        'Debugger readiness and breakpoint plan for Mach-O modules, dyld loading, and memory/register evidence.',
      readiness_checks: [
        'macOS host available',
        'lldb present',
        'entitlement/debug permission understood',
      ],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['runtime.debug.session.start', 'runtime.debug.command'],
      evidence: ['process', 'memory', 'modules', 'timeline'],
      limitations: [
        'Requires a macOS host and explicit opt-in; this planner does not attach LLDB.',
      ],
    },
    {
      backend: 'dtrace',
      purpose: 'DTrace probe plan for process, syscall, filesystem, and network behavior.',
      readiness_checks: [
        'macOS host available',
        'DTrace permission available',
        'SIP/entitlement constraints reviewed',
      ],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['macos.runtime.plan'],
      evidence: ['syscalls', 'filesystem', 'network', 'timeline'],
      limitations: ['DTrace can require elevated permissions; keep plan-only until approved.'],
    },
    {
      backend: 'fs-usage',
      purpose: 'Filesystem activity plan for app bundles, dylib loads, and dropped files.',
      readiness_checks: ['fs_usage available', 'collection filters selected'],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['macos.runtime.plan'],
      evidence: ['filesystem', 'process', 'timeline'],
    },
    {
      backend: 'sandbox-exec',
      purpose: 'Sandbox profile planning for constrained macOS execution.',
      readiness_checks: ['sandbox-exec availability reviewed', 'profile policy selected'],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['macos.runtime.plan'],
      evidence: ['filesystem', 'network', 'process'],
      limitations: ['Do not rely on sandbox-exec for complete malware containment.'],
    },
    {
      backend: 'codesign-runtime',
      purpose: 'Runtime code-signing and entitlement verification plan.',
      readiness_checks: [
        'codesign available',
        'sample signature and entitlements already inspected statically',
      ],
      setup_tools: ['apple.signing.inspect'],
      execution_tools: ['macos.runtime.plan'],
      evidence: ['code-signature', 'provenance'],
    },
  ],
  staticCorrelation: [
    'Map Mach-O load commands, dylib imports, entitlements, and code signatures to LLDB/DTrace/fs_usage probes.',
    'Map app bundle Info.plist and framework layout to sandbox profile and filesystem trace scope.',
    'Map dSYM/native object metadata to debugger symbol lookup without attaching by default.',
  ],
  safetyNotes: [
    'Do not run LLDB, DTrace, fs_usage, sandbox-exec, codesign runtime checks, mount DMG files, or launch app bundles from this planner.',
    'Distinguish macOS host gating from generic runtime capability readiness.',
  ],
  nextActions: [
    'Run macho.structure.analyze and apple.signing.inspect before choosing runtime probes.',
    'Use tool.readiness for selected debugger/runtime tools and verify macOS host support.',
    'Keep DMG/PKG handling passive until extraction/mount policy is explicitly approved.',
  ],
}

const macosRuntimePlugin = definePlugin({
  id: 'macos-runtime',
  name: 'macOS Runtime Plan',
  executionDomain: 'dynamic',
  aspects: buildRuntimePlanAspects(spec),
  runtimePolicy: buildRuntimePlanPolicy(spec),
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: [
        'macho',
        'fat',
        'universal',
        'dylib',
        'framework',
        'app-bundle',
        'pkg',
        'dmg',
        'dsym',
      ],
    },
    category: 'dynamic-analysis',
  },
  description:
    'Passive macOS runtime planning for Mach-O debugging, filesystem tracing, code-signing, and sandbox profile guidance.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...createRuntimePlanToolDefinition(spec),
      handler: createRuntimePlanHandler(spec),
    }),
  ],
})

export default macosRuntimePlugin
