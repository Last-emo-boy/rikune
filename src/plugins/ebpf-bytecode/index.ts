/**
 * eBPF Bytecode Plugin
 *
 * Passive static inventory for raw eBPF bytecode and ELF EM_BPF objects. It
 * never calls the kernel verifier, bpf(), bpftool, or runtime telemetry.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createEbpfBytecodeInventoryHandler,
  ebpfBytecodeInventoryToolDefinition,
} from './tools/ebpf-bytecode-inventory.js'

const ebpfBytecodePlugin = definePlugin({
  id: 'ebpf-bytecode',
  name: 'eBPF Bytecode Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['ebpf', 'bpf', 'ebpf-bytecode', 'raw-ebpf', 'ebpf-elf', 'bpf-object'],
    platforms: ['linux'],
    architectures: ['ebpf'],
    execution: ['static', 'triage', 'workflow-plan'],
    safety: [
      'passive',
      'no_execute',
      'no_bpf_syscall',
      'no_kernel_verifier_run',
      'no_program_load',
      'no_attach',
      'no_map_create',
      'no_runtime_start',
      'no_network_by_default',
    ],
    capabilities: [
      'bytecode-inventory',
      'instruction-decode',
      'helper-call-hints',
      'map-reference-hints',
      'control-flow',
      'verifier-precheck',
      'routing',
      'workflow-plan',
    ],
    evidence: ['structure', 'bytecode', 'control-flow', 'kernel-events', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'ebpf',
        'bpf',
        'ebpf-bytecode',
        'raw-ebpf',
        'ebpf-elf',
        'bpf-object',
        'xdp',
        'tc-bpf',
        'kprobe-bpf',
        'tracepoint-bpf',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive eBPF bytecode and ELF EM_BPF inventory with helper/map/control-flow/verifier-precheck evidence and opt-in Linux runtime handoff.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...ebpfBytecodeInventoryToolDefinition,
      handler: (args, deps) => createEbpfBytecodeInventoryHandler(deps)(args as never),
    }),
  ],
})

export default ebpfBytecodePlugin
