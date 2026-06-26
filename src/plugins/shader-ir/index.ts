/**
 * Shader IR Inventory Plugin
 *
 * Passive inventory for SPIR-V, DirectX shader containers, Metal libraries,
 * and WGSL source. It never invokes validators, compilers, GPU drivers, or
 * shader runtimes.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createShaderIrInventoryHandler,
  shaderIrInventoryAspects,
  shaderIrInventoryToolDefinition,
} from './tools/shader-ir-inventory.js'

const shaderIrPlugin = definePlugin({
  id: 'shader-ir',
  name: 'Shader IR Inventory',
  executionDomain: 'static',
  aspects: shaderIrInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'shader-ir',
        'spir-v',
        'spv',
        'dxil',
        'dxbc',
        'dxcontainer',
        'wgsl',
        'metallib',
        'metal-metallib',
      ],
      findings: ['shader', 'spir-v', 'dxil', 'dxbc', 'webgpu', 'vulkan', 'directx', 'metal'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive shader IR and GPU program inventory for SPIR-V, DXIL/DXBC containers, WGSL, and Metal libraries without validators, compilers, drivers, or GPU access.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...shaderIrInventoryToolDefinition,
      handler: (args, deps) => createShaderIrInventoryHandler(deps)(args as never),
    }),
  ],
})

export default shaderIrPlugin
