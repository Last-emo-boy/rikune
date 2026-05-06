import type { RuntimeBackendCapability, ToolRuntimeContract } from '@rikune/shared'

export interface RuntimeDelegatedToolContract {
  tool_name: string
  runtime_contract: ToolRuntimeContract
}

export interface RuntimeToolSupport extends RuntimeDelegatedToolContract {
  supported: boolean
  capability: RuntimeBackendCapability | null
  requires_sample: boolean | null
}

const DEBUG_SESSION_CONTRACT: ToolRuntimeContract = {
  type: 'inline',
  handler: 'executeDebugSession',
}
const FRIDA_CONTRACT: ToolRuntimeContract = { type: 'python-worker', handler: 'frida_worker.py' }
const RUNTIME_DEOBFUSCATION_CONTRACT: ToolRuntimeContract = {
  type: 'python-worker',
  handler: 'src/plugins/runtime-deobfuscate/workers/deobfuscate_worker.py',
}

const RUNTIME_DELEGATED_TOOL_CONTRACTS: RuntimeDelegatedToolContract[] = [
  { tool_name: 'debug.session.breakpoint', runtime_contract: DEBUG_SESSION_CONTRACT },
  { tool_name: 'debug.session.continue', runtime_contract: DEBUG_SESSION_CONTRACT },
  { tool_name: 'debug.session.end', runtime_contract: DEBUG_SESSION_CONTRACT },
  { tool_name: 'debug.session.inspect', runtime_contract: DEBUG_SESSION_CONTRACT },
  { tool_name: 'debug.session.smart_breakpoint', runtime_contract: DEBUG_SESSION_CONTRACT },
  { tool_name: 'debug.session.snapshot', runtime_contract: DEBUG_SESSION_CONTRACT },
  { tool_name: 'debug.session.start', runtime_contract: DEBUG_SESSION_CONTRACT },
  { tool_name: 'debug.session.step', runtime_contract: DEBUG_SESSION_CONTRACT },
  { tool_name: 'debug.session.watch', runtime_contract: DEBUG_SESSION_CONTRACT },
  {
    tool_name: 'sandbox.execute',
    runtime_contract: { type: 'inline', handler: 'executeSandboxExecute' },
  },
  {
    tool_name: 'behavior.capture',
    runtime_contract: { type: 'inline', handler: 'executeBehaviorCapture' },
  },
  {
    tool_name: 'dynamic.behavior.capture',
    runtime_contract: { type: 'inline', handler: 'executeBehaviorCapture' },
  },
  {
    tool_name: 'dynamic.memory.dump',
    runtime_contract: { type: 'inline', handler: 'executeDynamicMemoryDump' },
  },
  {
    tool_name: 'managed.safe_run',
    runtime_contract: { type: 'inline', handler: 'executeManagedSafeRun' },
  },
  {
    tool_name: 'qiling.inspect',
    runtime_contract: { type: 'inline', handler: 'executeQilingInspect' },
  },
  {
    tool_name: 'panda.inspect',
    runtime_contract: { type: 'inline', handler: 'executePandaInspect' },
  },
  {
    tool_name: 'speakeasy.api_trace',
    runtime_contract: { type: 'inline', handler: 'executeSpeakeasyApiTrace' },
  },
  {
    tool_name: 'speakeasy.emulate',
    runtime_contract: { type: 'inline', handler: 'executeSpeakeasyEmulate' },
  },
  {
    tool_name: 'speakeasy.shellcode',
    runtime_contract: { type: 'inline', handler: 'executeSpeakeasyShellcode' },
  },
  {
    tool_name: 'wine.dll_overrides',
    runtime_contract: { type: 'inline', handler: 'executeWineDllOverrides' },
  },
  { tool_name: 'wine.env', runtime_contract: { type: 'inline', handler: 'executeWineEnv' } },
  { tool_name: 'wine.reg', runtime_contract: { type: 'inline', handler: 'executeWineReg' } },
  { tool_name: 'wine.run', runtime_contract: { type: 'inline', handler: 'executeWineRun' } },
  { tool_name: 'frida.runtime.instrument', runtime_contract: FRIDA_CONTRACT },
  { tool_name: 'frida.script.inject', runtime_contract: FRIDA_CONTRACT },
  { tool_name: 'frida.trace.capture', runtime_contract: FRIDA_CONTRACT },
  { tool_name: 'deobf.api_resolve', runtime_contract: RUNTIME_DEOBFUSCATION_CONTRACT },
  { tool_name: 'deobf.cfg_trace', runtime_contract: RUNTIME_DEOBFUSCATION_CONTRACT },
  { tool_name: 'deobf.dotnet', runtime_contract: RUNTIME_DEOBFUSCATION_CONTRACT },
  { tool_name: 'deobf.strings', runtime_contract: RUNTIME_DEOBFUSCATION_CONTRACT },
  {
    tool_name: 'managed.fake_c2',
    runtime_contract: {
      type: 'python-worker',
      handler: 'src/plugins/managed-fake-c2/workers/managed_fake_c2_worker.py',
    },
  },
]

function cloneRuntimeContract(contract: ToolRuntimeContract): ToolRuntimeContract {
  const clone: ToolRuntimeContract = { ...contract }
  if (contract.modes) {
    clone.modes = [...contract.modes]
  }
  return clone
}

function findCapability(
  capabilities: RuntimeBackendCapability[],
  contract: ToolRuntimeContract
): RuntimeBackendCapability | null {
  return (
    capabilities.find(
      (capability) => capability.type === contract.type && capability.handler === contract.handler
    ) ?? null
  )
}

export function listRuntimeDelegatedToolContracts(): RuntimeDelegatedToolContract[] {
  return RUNTIME_DELEGATED_TOOL_CONTRACTS.map((entry) => ({
    tool_name: entry.tool_name,
    runtime_contract: cloneRuntimeContract(entry.runtime_contract),
  }))
}

export function getRuntimeDelegatedToolContract(
  toolName: string
): RuntimeDelegatedToolContract | null {
  const entry = RUNTIME_DELEGATED_TOOL_CONTRACTS.find((item) => item.tool_name === toolName)
  return entry
    ? {
        tool_name: entry.tool_name,
        runtime_contract: cloneRuntimeContract(entry.runtime_contract),
      }
    : null
}

export function buildRuntimeToolSupport(
  capabilities: RuntimeBackendCapability[]
): RuntimeToolSupport[] {
  return RUNTIME_DELEGATED_TOOL_CONTRACTS.map((entry) => {
    const capability = findCapability(capabilities, entry.runtime_contract)
    return {
      tool_name: entry.tool_name,
      runtime_contract: cloneRuntimeContract(entry.runtime_contract),
      supported: Boolean(capability),
      capability: capability ? { ...capability } : null,
      requires_sample:
        typeof capability?.requiresSample === 'boolean' ? capability.requiresSample : null,
    }
  })
}

export function buildRuntimeToolSupportSummary(capabilities: RuntimeBackendCapability[]) {
  const runtimeToolSupport = buildRuntimeToolSupport(capabilities)
  const supportedRuntimeTools = runtimeToolSupport
    .filter((tool) => tool.supported)
    .map((tool) => tool.tool_name)
  const missingRuntimeTools = runtimeToolSupport
    .filter((tool) => !tool.supported)
    .map((tool) => tool.tool_name)

  return {
    runtime_tool_support: runtimeToolSupport,
    runtime_tool_summary: {
      supported_count: supportedRuntimeTools.length,
      missing_count: missingRuntimeTools.length,
      total_count: runtimeToolSupport.length,
    },
    supported_runtime_tools: supportedRuntimeTools,
    missing_runtime_tools: missingRuntimeTools,
  }
}
