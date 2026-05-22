import { definePlugin, defineTool } from '../sdk.js'
import {
  buildRuntimePlanAspects,
  buildRuntimePlanPolicy,
  createRuntimePlanHandler,
  createRuntimePlanToolDefinition,
  type RuntimePlanSpec,
} from '../runtime-plan.js'

const spec: RuntimePlanSpec = {
  pluginId: 'linux-runtime',
  toolName: 'linux.runtime.plan',
  description:
    'Build a passive Linux dynamic-analysis plan for ELF, shared objects, core dumps, and packages across Qiling, Unicorn, gdb, strace, ltrace, ptrace, seccomp, and eBPF without executing the sample.',
  platform: 'linux',
  formats: [
    'elf',
    'elf-executable',
    'so',
    'elf-so',
    'elf-core',
    'linux-kernel-module',
    'deb',
    'rpm',
    'apk-alpine',
    'appimage',
  ],
  runtimes: ['qiling', 'unicorn', 'gdb', 'strace', 'ltrace', 'ptrace', 'seccomp', 'ebpf'],
  capabilities: ['readiness', 'syscall-plan', 'debug-plan', 'emulation-plan', 'kernel-event-plan'],
  evidence: [
    'timeline',
    'behavior',
    'process',
    'filesystem',
    'network',
    'memory',
    'modules',
    'syscalls',
    'kernel-events',
  ],
  recommendedStaticTools: [
    'linux.binary.inventory',
    'elf.structure.analyze',
    'elf.imports.extract',
    'elf.exports.extract',
    'linux.package.inventory',
  ],
  recommendedControlTools: ['dynamic.runtime.status', 'dynamic.toolkit.status'],
  backends: [
    {
      backend: 'qiling',
      purpose: 'Cross-platform emulation for syscall, memory-map, and file/network attempt hints.',
      readiness_checks: ['Qiling Python environment available', 'rootfs path configured read-only'],
      setup_tools: ['dynamic.toolkit.status'],
      execution_tools: ['qiling.inspect'],
      evidence: ['syscalls', 'memory-map', 'filesystem', 'network', 'timeline'],
      limitations: ['Emulation coverage depends on architecture, loader, and rootfs support.'],
    },
    {
      backend: 'unicorn',
      purpose: 'CPU-level emulation for focused code paths or shellcode-like fragments.',
      readiness_checks: ['Unicorn engine available', 'architecture supported'],
      setup_tools: ['dynamic.toolkit.status'],
      execution_tools: ['qiling.inspect'],
      evidence: ['memory', 'api-calls', 'timeline'],
    },
    {
      backend: 'gdb',
      purpose:
        'Debugger plan for registers, memory, modules, breakpoints, and controlled stepping.',
      readiness_checks: ['gdb available in isolated runtime', 'ptrace permission policy selected'],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['runtime.debug.session.start', 'runtime.debug.command'],
      evidence: ['process', 'memory', 'modules', 'timeline'],
      limitations: ['Never ptrace unknown ELF without explicit opt-in and isolation.'],
    },
    {
      backend: 'strace',
      purpose: 'Syscall trace plan for process, file, network, and signal activity.',
      readiness_checks: ['strace available', 'seccomp/ptrace restrictions understood'],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['linux.runtime.plan'],
      evidence: ['syscalls', 'filesystem', 'network', 'process'],
      limitations: ['This planner does not run strace; use a runtime-backed tool after opt-in.'],
    },
    {
      backend: 'ltrace',
      purpose: 'Library-call trace plan for dynamically linked ELF behavior.',
      readiness_checks: ['ltrace available', 'dynamic linking expected'],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['linux.runtime.plan'],
      evidence: ['api-calls', 'modules', 'timeline'],
    },
    {
      backend: 'ebpf',
      purpose: 'Optional kernel-event telemetry plan for high-fidelity host events.',
      readiness_checks: [
        'eBPF capability available',
        'privilege boundary approved',
        'collection filters defined',
      ],
      setup_tools: ['dynamic.runtime.status'],
      execution_tools: ['linux.runtime.plan'],
      evidence: ['kernel-events', 'filesystem', 'network', 'process'],
      limitations: ['Requires elevated privileges; keep optional and opt-in only.'],
    },
  ],
  staticCorrelation: [
    'Map ELF imports, symbols, RPATH/RUNPATH, and hardening flags to syscall/debugger probes.',
    'Map package maintainer scripts and nested ELF candidates to runtime trace plans without installing.',
    'Map core dump metadata back to module and symbol inventories.',
  ],
  safetyNotes: [
    'Do not run ELF files, ptrace processes, attach gdb, load kernel modules, or start eBPF collection from this planner.',
    'Treat ptrace/seccomp/eBPF as optional elevated backends with explicit user approval.',
  ],
  nextActions: [
    'Use linux.binary.inventory and ELF tools to identify imports, symbols, and architecture first.',
    'Use tool.readiness for qiling.inspect or runtime.debug.session.start before execution.',
    'Keep eBPF/seccomp collection disabled until an isolated runtime and permission model are selected.',
  ],
}

const linuxRuntimePlugin = definePlugin({
  id: 'linux-runtime',
  name: 'Linux Runtime Plan',
  executionDomain: 'dynamic',
  aspects: buildRuntimePlanAspects(spec),
  runtimePolicy: buildRuntimePlanPolicy(spec),
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: [
        'elf',
        'elf-executable',
        'so',
        'elf-so',
        'elf-core',
        'deb',
        'rpm',
        'apk-alpine',
        'appimage',
      ],
    },
    category: 'dynamic-analysis',
  },
  description:
    'Passive Linux runtime planning for ELF emulation, debugger, syscall/library tracing, and optional kernel telemetry.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...createRuntimePlanToolDefinition(spec),
      handler: createRuntimePlanHandler(spec),
    }),
  ],
})

export default linuxRuntimePlugin
