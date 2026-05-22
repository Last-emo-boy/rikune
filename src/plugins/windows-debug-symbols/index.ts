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

const windowsDebugSymbolsPlugin = definePlugin({
  id: 'windows-debug-symbols',
  name: 'Windows Debug Symbols Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['pdb', 'coff', 'coff-lib'],
    platforms: ['windows'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['metadata', 'symbols', 'source-map-plan', 'routing'],
    evidence: ['symbols', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['pdb', 'coff', 'coff-lib', 'symbols', 'debug-metadata'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive PDB, COFF object, and COFF library metadata inventory without symbol server download.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...windowsDebugMetadataInspectToolDefinition,
      handler: (args, deps) => createWindowsDebugMetadataInspectHandler(deps)(args as never),
    }),
  ],
})

export default windowsDebugSymbolsPlugin
