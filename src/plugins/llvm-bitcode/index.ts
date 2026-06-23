/**
 * LLVM Bitcode Plugin
 *
 * Passive inventory for raw LLVM bitcode streams and wrapper files. It never
 * invokes LLVM tools, compilers, linkers, JITs, or lifted artifacts.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createLlvmBitcodeInventoryHandler,
  llvmBitcodeInventoryToolDefinition,
} from './tools/llvm-bitcode-inventory.js'

const llvmBitcodePlugin = definePlugin({
  id: 'llvm-bitcode',
  name: 'LLVM Bitcode Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['llvm-bitcode', 'llvm-bitcode-wrapper', 'llvm-bc', 'llvm-ir', 'bc', 'll'],
    platforms: ['cross-platform'],
    architectures: ['llvm-ir'],
    execution: ['static', 'triage', 'decompilation', 'correlation'],
    safety: [
      'passive',
      'no_llvm_toolchain_required',
      'no_compile',
      'no_link',
      'no_execute',
      'no_network_by_default',
    ],
    capabilities: [
      'structure',
      'strings',
      'ir-metadata',
      'bitstream-summary',
      'wrapper-inventory',
      'workflow-routing',
    ],
    evidence: ['structure', 'strings', 'metadata', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['llvm-bitcode', 'llvm-bitcode-wrapper', 'llvm-bc', 'llvm-ir', 'bc', 'll'],
      findings: ['llvm', 'bitcode', 'lto', 'llvmbc', 'llvm-ir'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive LLVM bitcode and wrapper inventory for IR-level static analysis without LLVM toolchain execution.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...llvmBitcodeInventoryToolDefinition,
      handler: (args, deps) => createLlvmBitcodeInventoryHandler(deps)(args as never),
    }),
  ],
})

export default llvmBitcodePlugin
