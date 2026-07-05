/**
 * Windows Debug Symbols Plugin
 *
 * Passive inventory for PDB, COFF object, and COFF library metadata. It never
 * downloads symbols from a symbol server or executes object code.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createWindowsDebugMetadataInspectHandler,
  windowsDebugMetadataInspectToolDefinition,
} from './tools/windows-debug-metadata-inspect.js'
import {
  WINDOWS_DEBUG_METADATA_RUNTIME_POLICY,
  WINDOWS_DEBUG_METADATA_TOOL_VERSION,
  windowsDebugMetadataAspects,
} from './windows-debug-symbols-metadata.js'

const windowsDebugSymbolsPlugin = definePlugin({
  id: 'windows-debug-symbols',
  name: 'Windows Debug Symbols Inventory',
  executionDomain: 'static',
  aspects: windowsDebugMetadataAspects(),
  runtimePolicy: WINDOWS_DEBUG_METADATA_RUNTIME_POLICY,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'pdb',
        'obj',
        'lib',
        'coff',
        'coff-lib',
        'dwo',
        'dwp',
        'debug',
        '.debug',
        'codeview',
        'CodeView',
        'symbols',
        'debug-symbols',
        'debug-info',
        'debug-metadata',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive PDB, COFF object/library, CodeView, DWARF sidecar, and debug metadata inventory without symbol server download.',
  version: WINDOWS_DEBUG_METADATA_TOOL_VERSION,
  tools: [
    defineTool({
      ...windowsDebugMetadataInspectToolDefinition,
      handler: (args, deps) => createWindowsDebugMetadataInspectHandler(deps)(args as never),
    }),
  ],
})

export default windowsDebugSymbolsPlugin
