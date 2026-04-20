export type RuntimeToolCategory =
  | 'debugger'
  | 'dump'
  | 'telemetry'
  | 'network'
  | 'managed'
  | 'instrumentation'
  | 'manual-gui'
  | 'runtime'

export interface RuntimeToolSpec {
  id: string
  displayName: string
  category: RuntimeToolCategory
  role: string
  filenames: string[]
  relativePaths: string[]
  installHint: string
  profiles: string[]
}

export interface RuntimeToolProfileDefinition {
  id: string
  requiredTools: string[]
  optionalTools: string[]
  recommendedTools: string[]
}

export const RUNTIME_TOOL_SPECS: RuntimeToolSpec[] = [
  {
    id: 'cdb',
    displayName: 'CDB / Windows Debugger',
    category: 'debugger',
    role: 'Automated breakpoints, register/stack inspection, dumps on debugger events.',
    filenames: ['cdb.exe'],
    relativePaths: [
      'debuggers\\x64\\cdb.exe',
      'debuggers\\x86\\cdb.exe',
      'Windows Kits\\10\\Debuggers\\x64\\cdb.exe',
      'Windows Kits\\11\\Debuggers\\x64\\cdb.exe',
      'cdb.exe',
    ],
    installHint:
      'Install Windows SDK Debugging Tools or mount cdb.exe under C:\\rikune-tools\\debuggers\\x64.',
    profiles: ['debugger_cdb', 'ttd_recording', 'memory_dump'],
  },
  {
    id: 'windbg',
    displayName: 'WinDbg',
    category: 'debugger',
    role: 'Manual debugger fallback and postmortem dump review.',
    filenames: ['windbg.exe', 'WinDbgX.exe'],
    relativePaths: [
      'debuggers\\x64\\windbg.exe',
      'Windows Kits\\10\\Debuggers\\x64\\windbg.exe',
      'Windows Kits\\11\\Debuggers\\x64\\windbg.exe',
      'windbg.exe',
      'WinDbgX.exe',
    ],
    installHint:
      'Install WinDbg from Windows SDK or Microsoft Store, then expose it inside the runtime tool cache.',
    profiles: ['manual_gui_debug', 'memory_dump'],
  },
  {
    id: 'procdump',
    displayName: 'ProcDump',
    category: 'dump',
    role: 'Crash, timeout, and breakpoint-adjacent memory dump capture.',
    filenames: ['procdump64.exe', 'procdump.exe'],
    relativePaths: [
      'Sysinternals\\procdump64.exe',
      'Sysinternals\\procdump.exe',
      'procdump64.exe',
      'procdump.exe',
    ],
    installHint:
      'Download Sysinternals ProcDump and place procdump64.exe in C:\\rikune-tools\\Sysinternals.',
    profiles: ['memory_dump', 'debugger_cdb'],
  },
  {
    id: 'procmon',
    displayName: 'Process Monitor',
    category: 'telemetry',
    role: 'File, registry, process, and network activity capture for ProcMon-grade traces.',
    filenames: ['Procmon64.exe', 'Procmon.exe'],
    relativePaths: [
      'Sysinternals\\Procmon64.exe',
      'Sysinternals\\Procmon.exe',
      'Procmon64.exe',
      'Procmon.exe',
    ],
    installHint:
      'Download Sysinternals Process Monitor and place Procmon64.exe in C:\\rikune-tools\\Sysinternals.',
    profiles: ['procmon_capture', 'behavior_capture'],
  },
  {
    id: 'sysmon',
    displayName: 'Sysmon',
    category: 'telemetry',
    role: 'Process, network, image-load, registry, and file-create event telemetry.',
    filenames: ['Sysmon64.exe', 'Sysmon.exe'],
    relativePaths: [
      'Sysinternals\\Sysmon64.exe',
      'Sysinternals\\Sysmon.exe',
      'Sysmon64.exe',
      'Sysmon.exe',
    ],
    installHint:
      'Download Sysinternals Sysmon and provide a sandbox-safe config before enabling service-backed capture.',
    profiles: ['sysmon_capture', 'behavior_capture'],
  },
  {
    id: 'ttd',
    displayName: 'Time Travel Debugging',
    category: 'debugger',
    role: 'Record/replay execution for deep manual debugging and branch replay.',
    filenames: ['TTD.exe', 'TTTracer.exe', 'TTDRecord.exe'],
    relativePaths: [
      'debuggers\\x64\\TTD.exe',
      'debuggers\\x64\\TTTracer.exe',
      'debuggers\\x64\\TTDRecord.exe',
      'TTD\\TTD.exe',
      'TTD\\TTTracer.exe',
      'TTD.exe',
    ],
    installHint:
      'Install WinDbg Preview / Debugging Tools with TTD support or mount TTD tooling in C:\\rikune-tools.',
    profiles: ['ttd_recording'],
  },
  {
    id: 'x64dbg',
    displayName: 'x64dbg',
    category: 'manual-gui',
    role: 'Manual GUI debugger for retained Hyper-V or visible Sandbox review.',
    filenames: ['x64dbg.exe', 'x96dbg.exe'],
    relativePaths: [
      'x64dbg\\release\\x64\\x64dbg.exe',
      'x64dbg\\x64dbg.exe',
      'x96dbg.exe',
      'x64dbg.exe',
    ],
    installHint:
      'Place x64dbg in the runtime tool cache when manual GUI debugging profiles are needed.',
    profiles: ['manual_gui_debug', 'anti_evasion'],
  },
  {
    id: 'dnspy',
    displayName: 'dnSpyEx',
    category: 'manual-gui',
    role: '.NET assembly inspection, edit-and-continue style manual debugging, and resource review.',
    filenames: ['dnSpy.exe', 'dnSpy.Console.exe'],
    relativePaths: ['dnSpy\\dnSpy.exe', 'dnSpyEx\\dnSpy.exe', 'dnSpy.exe'],
    installHint:
      'Place dnSpyEx in the runtime tool cache for manual .NET debugging and resource review.',
    profiles: ['dotnet_runtime', 'manual_gui_debug'],
  },
  {
    id: 'frida',
    displayName: 'Frida CLI',
    category: 'instrumentation',
    role: 'Runtime API tracing, anti-analysis bypass hooks, and decrypted string capture.',
    filenames: ['frida.exe', 'frida-trace.exe', 'frida-ps.exe', 'frida'],
    relativePaths: [
      'frida\\frida.exe',
      'frida\\frida-trace.exe',
      'frida.exe',
      'frida-trace.exe',
      'frida',
    ],
    installHint:
      'Install frida-tools in the runtime Python environment or mount standalone Frida CLI binaries.',
    profiles: ['frida_runtime', 'anti_evasion', 'network_lab'],
  },
  {
    id: 'dotnet',
    displayName: '.NET SDK / Runtime',
    category: 'managed',
    role: 'Managed sample execution, .NET runtime inspection, and future CLRMD/dotnet-dump flows.',
    filenames: ['dotnet.exe', 'dotnet'],
    relativePaths: ['dotnet\\dotnet.exe', 'dotnet.exe', 'dotnet'],
    installHint:
      'Install the .NET runtime/SDK in the Runtime Node when managed samples need native execution.',
    profiles: ['dotnet_runtime'],
  },
  {
    id: 'fakenet',
    displayName: 'FakeNet-NG',
    category: 'network',
    role: 'Network service emulation, DNS/HTTP capture, and malware traffic sinkholing.',
    filenames: ['fakenet.exe', 'fakenet.py', 'FakeNet-NG.exe'],
    relativePaths: [
      'FakeNet-NG\\fakenet.py',
      'FakeNet-NG\\fakenet.exe',
      'FakeNet-NG.exe',
      'fakenet.py',
    ],
    installHint:
      'Install FakeNet-NG or expose a compatible fake-service harness in the runtime tool cache.',
    profiles: ['network_lab'],
  },
]

export const RUNTIME_TOOL_PROFILE_DEFINITIONS: RuntimeToolProfileDefinition[] = [
  {
    id: 'behavior_capture',
    requiredTools: [],
    optionalTools: ['procmon', 'sysmon', 'frida', 'fakenet'],
    recommendedTools: [
      'dynamic.behavior.capture',
      'dynamic.toolkit.status',
      'dynamic.trace.import',
    ],
  },
  {
    id: 'debugger_cdb',
    requiredTools: ['cdb'],
    optionalTools: ['procdump', 'windbg'],
    recommendedTools: [
      'runtime.debug.command',
      'debug.session.inspect',
      'debug.session.breakpoint',
      'debug.session.snapshot',
    ],
  },
  {
    id: 'memory_dump',
    requiredTools: [],
    optionalTools: ['procdump', 'cdb', 'windbg'],
    recommendedTools: ['dynamic.memory_dump', 'runtime.debug.command'],
  },
  {
    id: 'procmon_capture',
    requiredTools: ['procmon'],
    optionalTools: [],
    recommendedTools: ['dynamic.behavior.capture'],
  },
  {
    id: 'sysmon_capture',
    requiredTools: ['sysmon'],
    optionalTools: [],
    recommendedTools: ['dynamic.behavior.capture'],
  },
  {
    id: 'ttd_recording',
    requiredTools: ['cdb', 'ttd'],
    optionalTools: ['windbg'],
    recommendedTools: ['runtime.debug.command'],
  },
  {
    id: 'network_lab',
    requiredTools: [],
    optionalTools: ['fakenet', 'frida'],
    recommendedTools: [
      'debug.network.plan',
      'dynamic.behavior.capture',
      'debug.telemetry.plan',
      'dynamic.trace.import',
    ],
  },
  {
    id: 'frida_runtime',
    requiredTools: ['frida'],
    optionalTools: [],
    recommendedTools: ['frida.runtime.instrument', 'frida.trace.capture', 'frida.script.inject'],
  },
  {
    id: 'dotnet_runtime',
    requiredTools: ['dotnet'],
    optionalTools: ['dnspy'],
    recommendedTools: [
      'debug.managed.plan',
      'runtime.debug.command',
      'managed.safe_run',
      'debug.gui.handoff',
    ],
  },
  {
    id: 'manual_gui_debug',
    requiredTools: [],
    optionalTools: ['x64dbg', 'dnspy', 'windbg'],
    recommendedTools: [
      'debug.gui.handoff',
      'runtime.debug.session.start',
      'runtime.hyperv.control',
    ],
  },
  {
    id: 'anti_evasion',
    requiredTools: [],
    optionalTools: ['frida', 'x64dbg'],
    recommendedTools: ['dynamic.auto_hook', 'frida.script.generate', 'runtime.debug.command'],
  },
]

export function getRuntimeToolSpec(id: string): RuntimeToolSpec | undefined {
  return RUNTIME_TOOL_SPECS.find((spec) => spec.id === id)
}
