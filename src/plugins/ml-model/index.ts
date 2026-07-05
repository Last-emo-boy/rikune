/**
 * ML Model Artifact Inventory Plugin
 *
 * Passive inventory for AI/ML model artifacts. It never deserializes pickle,
 * loads PyTorch/TensorFlow/ONNX/TFLite runtimes, runs inference, extracts model
 * archives to disk, or accesses model hubs/network resources.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createMlModelInventoryHandler,
  mlModelInventoryToolDefinition,
} from './tools/ml-model-inventory.js'

const mlModelPlugin = definePlugin({
  id: 'ml-model',
  name: 'ML Model Artifact Inventory',
  executionDomain: 'static',
  aspects: {
    formats: [
      'ml-model',
      'ai-model',
      'safetensors',
      'gguf',
      'ggml',
      'onnx',
      'tflite',
      'pytorch-checkpoint',
      'torch',
      'pickle',
      'npy',
      'npz',
    ],
    platforms: ['cross-platform', 'linux', 'windows', 'macos'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'gpu'],
    execution: ['static', 'triage', 'correlation', 'workflow-plan'],
    safety: [
      'passive',
      'no_deserialization',
      'no_model_load',
      'no_inference',
      'no_ml_framework_load',
      'no_network_by_default',
      'no_mutation',
      'no_extract_to_execution_path',
    ],
    capabilities: [
      'ml-model-inventory',
      'tensor-metadata',
      'model-supply-chain',
      'pickle-risk-triage',
      'external-reference-detection',
      'workflow-routing',
    ],
    evidence: ['structure', 'metadata', 'strings', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'ml-model',
        'ai-model',
        'safetensors',
        'gguf',
        'ggml',
        'onnx',
        'tflite',
        'pytorch-checkpoint',
        'torch',
        'pickle',
        'npy',
        'npz',
      ],
      findings: ['model-checkpoint', 'unsafe-deserialization', 'external-data', 'chat-template'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive AI/ML model artifact inventory for SafeTensors, GGUF/GGML, ONNX, TFLite, PyTorch/pickle checkpoints, and NumPy arrays without model loading or inference.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...mlModelInventoryToolDefinition,
      handler: (args, deps) => createMlModelInventoryHandler(deps)(args as never),
    }),
  ],
})

export default mlModelPlugin
