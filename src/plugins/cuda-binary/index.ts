/**
 * CUDA Binary Inventory Plugin
 *
 * Passive inventory for PTX, CUBIN ELF, CUDA fatbin, and host-embedded GPU
 * artifact hints. It never starts CUDA tooling, GPU drivers, or samples.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createCudaBinaryInventoryHandler,
  cudaBinaryInventoryAspects,
  cudaBinaryInventoryToolDefinition,
} from './tools/cuda-binary-inventory.js'

const cudaBinaryPlugin = definePlugin({
  id: 'cuda-binary',
  name: 'CUDA Binary Inventory',
  executionDomain: 'static',
  aspects: cudaBinaryInventoryAspects,
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['cuda', 'ptx', 'cubin', 'fatbin', 'cuda-fatbin', 'cuda-cubin', 'cuda-ptx'],
      findings: ['cuda', 'gpu', 'sass', 'ptx', 'cubin', 'fatbin', 'accelerator'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive CUDA/PTX/CUBIN/fatbin inventory and GPU lift handoff without CUDA driver, GPU, external tools, or sample execution.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...cudaBinaryInventoryToolDefinition,
      handler: (args, deps) => createCudaBinaryInventoryHandler(deps)(args as never),
    }),
  ],
})

export default cudaBinaryPlugin
