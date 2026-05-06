export type LocalDynamicToolPolicy =
  | 'artifact-generation'
  | 'artifact-import'
  | 'control-plane'
  | 'dependency-report'
  | 'planning'
  | 'post-processing'

const LOCAL_DYNAMIC_TOOL_POLICIES = new Map<string, LocalDynamicToolPolicy>([
  ['behavior.ioc', 'post-processing'],
  ['behavior.network', 'post-processing'],
  ['debug.cdb.plan', 'planning'],
  ['debug.gui.handoff', 'planning'],
  ['debug.managed.plan', 'planning'],
  ['debug.network.plan', 'planning'],
  ['debug.procdump.plan', 'planning'],
  ['debug.telemetry.plan', 'planning'],
  ['dynamic.auto.hook', 'artifact-generation'],
  ['dynamic.behavior.diff', 'post-processing'],
  ['dynamic.deep_plan', 'planning'],
  ['dynamic.dependencies', 'dependency-report'],
  ['dynamic.memory.import', 'artifact-import'],
  ['dynamic.persona.plan', 'planning'],
  ['dynamic.runtime.status', 'control-plane'],
  ['dynamic.toolkit.status', 'control-plane'],
  ['dynamic.trace.attribute', 'post-processing'],
  ['dynamic.trace.import', 'artifact-import'],
  ['frida.script.generate', 'artifact-generation'],
  ['runtime.debug.command', 'control-plane'],
  ['runtime.debug.session.start', 'control-plane'],
  ['runtime.debug.session.status', 'control-plane'],
  ['runtime.debug.session.stop', 'control-plane'],
  ['runtime.hyperv.control', 'control-plane'],
])

export function getLocalDynamicToolPolicy(toolName: string): LocalDynamicToolPolicy | undefined {
  return LOCAL_DYNAMIC_TOOL_POLICIES.get(toolName)
}

export function isExplicitLocalDynamicTool(toolName: string): boolean {
  return LOCAL_DYNAMIC_TOOL_POLICIES.has(toolName)
}

export function listExplicitLocalDynamicTools(): Array<{
  name: string
  policy: LocalDynamicToolPolicy
}> {
  return [...LOCAL_DYNAMIC_TOOL_POLICIES.entries()].map(([name, policy]) => ({ name, policy }))
}
