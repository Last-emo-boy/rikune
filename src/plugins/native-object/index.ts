/**
 * Native Object Inventory Plugin
 *
 * Passive inventory for object files, static libraries, kernel modules, and
 * debug bundles. It never links, loads, or executes binary content.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createNativeObjectInventoryHandler,
  nativeObjectInventoryToolDefinition,
} from './tools/native-object-inventory.js'

const nativeObjectPlugin = definePlugin({
  id: 'native-object',
  name: 'Native Object Inventory',
  executionDomain: 'static',
  aspects: {
    formats: [
      'object',
      'static-lib',
      'ar',
      'ar-static-lib',
      'coff',
      'coff-lib',
      'elf-object',
      'linux-kernel-module',
      'macho-object',
      'dsym',
      'dwarf',
    ],
    platforms: ['windows', 'linux', 'macos', 'ios', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['inventory', 'symbols', 'debug-metadata', 'nested-binaries', 'routing'],
    evidence: ['structure', 'symbols', 'package-metadata', 'nested-binaries', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'object',
        'static-lib',
        'ar',
        'ar-static-lib',
        'coff',
        'coff-lib',
        'elf-object',
        'linux-kernel-module',
        'macho-object',
        'dsym',
        'dwarf',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive native object/static-library/debug-bundle inventory with safe routing hints for ELF, Mach-O, COFF, and kernel modules.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...nativeObjectInventoryToolDefinition,
      handler: (args, deps) => createNativeObjectInventoryHandler(deps)(args as never),
    }),
  ],
})

export default nativeObjectPlugin
