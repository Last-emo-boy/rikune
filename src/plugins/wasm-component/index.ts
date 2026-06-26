/**
 * WebAssembly Component Model Plugin
 *
 * Passive inventory for Component Model binaries. It never invokes wasm-tools,
 * instantiates components, starts wasmtime, grants WASI resources, or fetches OCI packages.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createWasmComponentInventoryHandler,
  wasmComponentInventoryToolDefinition,
} from './tools/wasm-component-inventory.js'

const wasmComponentPlugin = definePlugin({
  id: 'wasm-component',
  name: 'WebAssembly Component Model Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['wasm-component', 'component-model', 'wit-component', 'wasi-preview2'],
    platforms: ['wasm', 'wasi', 'cross-platform'],
    architectures: ['wasm', 'component-model'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'no_runtime_start',
      'no_instantiation',
      'no_wasi_grants',
      'no_resource_grants',
      'no_external_tool',
      'no_network_by_default',
    ],
    capabilities: [
      'component-model-inventory',
      'wit-interface-hints',
      'wasi-preview2-capability-review',
      'canonical-abi-summary',
      'component-section-inventory',
      'component-import-export-inventory',
      'runtime-plan',
      'runtime-handoff',
      'workflow-routing',
    ],
    evidence: [
      'structure',
      'imports',
      'exports',
      'wasi-capability',
      'wit-interface',
      'canonical-abi',
      'custom-section',
      'workflow',
      'provenance',
    ],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['wasm-component', 'component-model', 'wit-component', 'wasi-preview2'],
      findings: ['component-model', 'wit', 'wasi-preview2', 'canonical-abi'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive WebAssembly Component Model inventory for WIT/WASI Preview 2 and Canonical ABI hints without component instantiation.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...wasmComponentInventoryToolDefinition,
      handler: (args, deps) => createWasmComponentInventoryHandler(deps)(args as never),
    }),
  ],
})

export default wasmComponentPlugin
