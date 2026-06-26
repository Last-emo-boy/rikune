/**
 * Native Debug Types Plugin
 *
 * Passive DWARF, split-DWARF, and CTF type/debug metadata inventory. It never
 * calls debuggers, dwarfdump/readelf/pahole/libctf, symbol servers, or source
 * fetchers.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createNativeDebugTypesInventoryHandler,
  nativeDebugTypesInventoryAspects,
  nativeDebugTypesInventoryToolDefinition,
} from './tools/native-debug-types-inventory.js'

const nativeDebugTypesPlugin = definePlugin({
  id: 'native-debug-types',
  name: 'Native Debug Types Inventory',
  executionDomain: 'static',
  aspects: nativeDebugTypesInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'dwarf',
        'dwarf-debug',
        'dwarf5',
        'debug-info',
        'debug-types',
        'dwo',
        'dwp',
        'ctf',
        'compact-ctf',
        'elf',
        'elf-object',
        'linux-kernel-module',
        'dsym',
        'debug-file',
        'debug-section',
      ],
      findings: [
        '.debug_info',
        '.debug_abbrev',
        '.debug_names',
        'split-dwarf',
        '.dwo',
        '.dwp',
        '.ctf',
        'ctf',
        'compact-ctf',
        'gnu-debuglink',
        'build-id',
        'type-graph',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive DWARF/split-DWARF/CTF native debug type inventory with compile-unit, section, source-path, and type-graph handoff hints.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...nativeDebugTypesInventoryToolDefinition,
      handler: (args, deps) => createNativeDebugTypesInventoryHandler(deps)(args as never),
    }),
  ],
})

export default nativeDebugTypesPlugin
