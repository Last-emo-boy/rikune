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
    formats: ['wasm', 'wasi', 'wat'],
    platforms: ['wasm', 'cross-platform'],
    architectures: ['wasm', 'wasm32'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'no_live_sample_by_default',
      'no_runtime_start',
      'no_instantiation',
      'no_wasi_grants',
      'no_resource_grants',
      'no_network_by_default',
    ],
    capabilities: [
      'structure',
      'imports',
      'exports',
      'wasi-capability-review',
      'resource-grant-review',
      'preopen-policy-review',
      'network-policy-review',
      'custom-section-inventory',
      'runtime-plan',
      'runtime-handoff',
      'routing',
    ],
    evidence: [
      'structure',
      'imports',
      'exports',
      'wasi-capability',
      'resource-grant',
      'custom-section',
      'workflow',
      'provenance',
    ],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['wasm', 'wasi', 'wat'],
      findings: ['wasi', 'resource-grant', 'preopen', 'custom-section'],
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
