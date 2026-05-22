/**
 * WebAssembly Plugin
 *
 * Passive inventory for WASM/WASI modules. It never instantiates modules,
 * starts a runtime, or executes WASI imports.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createWasmStructureAnalyzeHandler,
  wasmStructureAnalyzeToolDefinition,
} from './tools/wasm-structure-analyze.js'

const wasmPlugin = definePlugin({
  id: 'wasm',
  name: 'WebAssembly Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['wasm', 'wasi'],
    platforms: ['wasm', 'cross-platform'],
    architectures: ['wasm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['structure', 'imports', 'exports', 'capabilities', 'runtime-plan', 'routing'],
    evidence: ['structure', 'imports', 'exports', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['wasm', 'wasi'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive WebAssembly/WASI section, import/export, and capability inventory without module instantiation.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...wasmStructureAnalyzeToolDefinition,
      handler: (args, deps) => createWasmStructureAnalyzeHandler(deps)(args as never),
    }),
  ],
})

export default wasmPlugin
