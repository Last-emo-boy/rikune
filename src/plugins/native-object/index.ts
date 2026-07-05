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
import {
  NATIVE_OBJECT_RUNTIME_POLICY,
  NATIVE_OBJECT_TOOL_VERSION,
  nativeObjectAspects,
} from './native-object-metadata.js'

const nativeObjectPlugin = definePlugin({
  id: 'native-object',
  name: 'Native Object Inventory',
  executionDomain: 'static',
  aspects: nativeObjectAspects(),
  runtimePolicy: NATIVE_OBJECT_RUNTIME_POLICY,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'coff',
        'coff-lib',
        'elf-object',
        'linux-kernel-module',
        'macho-object',
        'dsym',
        'dwo',
        'dwp',
        'debug-metadata',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive native object/static-library/debug-bundle inventory with safe routing hints for ELF, Mach-O, COFF, and kernel modules.',
  version: NATIVE_OBJECT_TOOL_VERSION,
  tools: [
    defineTool({
      ...nativeObjectInventoryToolDefinition,
      handler: (args, deps) => createNativeObjectInventoryHandler(deps)(args as never),
    }),
  ],
})

export default nativeObjectPlugin
