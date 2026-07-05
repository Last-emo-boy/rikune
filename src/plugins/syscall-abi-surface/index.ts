/**
 * Syscall ABI Surface Plugin
 *
 * Passive syscall ABI and user-kernel boundary inventory. It reads bounded
 * bytes only and never executes samples, invokes syscalls, attaches tracers or
 * debuggers, starts emulation, opens devices, invokes external tools, or
 * mutates samples.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createSyscallAbiSurfaceInventoryHandler,
  syscallAbiSurfaceInventoryAspects,
  syscallAbiSurfaceInventoryToolDefinition,
} from './tools/syscall-abi-surface-inventory.js'

const syscallAbiSurfacePlugin = definePlugin({
  id: 'syscall-abi-surface',
  name: 'Syscall ABI Surface Inventory',
  executionDomain: 'static',
  aspects: syscallAbiSurfaceInventoryAspects,
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: [
        'syscall',
        'syscall-stub',
        'direct-syscall',
        'raw-shellcode',
        'shellcode',
        'ntdll-stub',
        'linux-syscall',
        'mach-trap',
        'svc',
        'ecall',
      ],
      findings: [
        'syscall',
        'sysenter',
        'int 0x80',
        'int 0x2e',
        'svc',
        'ecall',
        'SysWhispers',
        'HellsGate',
        "Hell's Gate",
        'HalosGate',
        "Halo's Gate",
        'TartarusGate',
        'NtAllocateVirtualMemory',
        'NtProtectVirtualMemory',
        'NtWriteVirtualMemory',
        'NtCreateThreadEx',
        'NtQueueApcThread',
        'seccomp',
        'PTRACE_TRACEME',
        'mach_msg',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive syscall ABI and user-kernel boundary inventory for Windows direct syscall stubs, NT resolver strings, Linux syscall/seccomp hints, Mach traps, SVC/ecall patterns, and evasion risk handoff.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...syscallAbiSurfaceInventoryToolDefinition,
      handler: (args, deps) => createSyscallAbiSurfaceInventoryHandler(deps)(args as never),
    }),
  ],
})

export default syscallAbiSurfacePlugin
