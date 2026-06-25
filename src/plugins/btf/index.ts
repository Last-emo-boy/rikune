/**
 * BTF Type Inventory Plugin
 *
 * Passive inventory for BPF Type Format metadata and CO-RE relocation records.
 * It never calls bpftool, libbpf, bpf(), or the kernel verifier.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  btfTypeInventoryToolDefinition,
  createBtfTypeInventoryHandler,
} from './tools/btf-type-inventory.js'

const btfPlugin = definePlugin({
  id: 'btf',
  name: 'BTF Type Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['btf', 'btf-ext', 'btf-elf', 'bpf-btf', 'core-relocations'],
    platforms: ['linux'],
    architectures: ['ebpf'],
    execution: ['static', 'triage', 'correlation', 'workflow-plan'],
    safety: [
      'passive',
      'no_execute',
      'no_bpf_syscall',
      'no_kernel_verifier_run',
      'no_program_load',
      'no_libbpf',
      'no_bpftool',
      'no_runtime_start',
      'no_network_by_default',
    ],
    capabilities: [
      'btf-type-inventory',
      'core-relocation-inventory',
      'kernel-type-metadata',
      'type-layout-summary',
      'ebpf-portability-handoff',
      'workflow-routing',
    ],
    evidence: ['structure', 'types', 'metadata', 'relocations', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'btf',
        'btf-ext',
        'btf-elf',
        'bpf-btf',
        'core-relocations',
        'ebpf-elf',
        'bpf-object',
      ],
      findings: ['btf', 'btf.ext', 'co-re', 'core-relocation', 'bpf_core_read'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive BPF Type Format and CO-RE relocation inventory for eBPF portability and type metadata analysis.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...btfTypeInventoryToolDefinition,
      handler: (args, deps) => createBtfTypeInventoryHandler(deps)(args as never),
    }),
  ],
})

export default btfPlugin
