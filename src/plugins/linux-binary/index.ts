/**
 * Linux Binary Inventory Plugin
 *
 * Passive inventory for ELF executables/shared objects, core dumps, kernel
 * modules, and initramfs/cpio images. It never executes, loads, mounts,
 * replays, inserts modules, or starts runtimes.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createLinuxBinaryInventoryHandler,
  linuxBinaryInventoryToolDefinition,
} from './tools/linux-binary-inventory.js'

const linuxBinaryPlugin = definePlugin({
  id: 'linux-binary',
  name: 'Linux Binary Inventory',
  executionDomain: 'static',
  aspects: {
    formats: [
      'linux-binary',
      'elf',
      'elf-executable',
      'so',
      'elf-so',
      'elf-core',
      'linux-kernel-module',
      'initramfs',
      'cpio',
      'dwarf',
    ],
    platforms: ['linux', 'embedded'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_auto_mount', 'no_live_sample_by_default'],
    capabilities: [
      'inventory',
      'structure',
      'symbols',
      'debug-metadata',
      'nested-binaries',
      'routing',
    ],
    evidence: ['structure', 'symbols', 'filesystem', 'memory', 'nested-binaries', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'linux-binary',
        'elf',
        'elf-executable',
        'so',
        'elf-so',
        'elf-core',
        'core',
        'linux-kernel-module',
        'initramfs',
        'cpio',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Linux ELF/core/module/initramfs inventory with static routing hints and no execute/load/mount behavior.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...linuxBinaryInventoryToolDefinition,
      handler: (args, deps) => createLinuxBinaryInventoryHandler(deps)(args as never),
    }),
  ],
})

export default linuxBinaryPlugin
