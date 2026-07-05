/**
 * Script Bytecode Plugin
 *
 * Passive metadata inventory for script bytecode containers such as Python
 * PYC, Lua bytecode, and V8 cached data. It never starts an interpreter.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  bytecodeMetadataInspectToolDefinition,
  createBytecodeMetadataInspectHandler,
} from './tools/bytecode-metadata-inspect.js'

const bytecodePlugin = definePlugin({
  id: 'bytecode',
  name: 'Script Bytecode Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['pyc', 'lua-bytecode', 'v8-cache'],
    platforms: ['python', 'lua', 'node', 'cross-platform'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['metadata', 'strings', 'version-hints', 'decompile-plan', 'routing'],
    evidence: ['structure', 'strings', 'package-metadata', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['pyc', 'lua-bytecode', 'v8-cache', 'python', 'lua', 'node'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive metadata inventory for Python PYC, Lua bytecode, and V8 cached data without interpreter execution.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...bytecodeMetadataInspectToolDefinition,
      handler: (args, deps) => createBytecodeMetadataInspectHandler(deps)(args as never),
    }),
  ],
})

export default bytecodePlugin
