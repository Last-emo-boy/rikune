/**
 * Unity Managed/IL2CPP Plugin
 *
 * Passive inventory for Unity metadata, IL2CPP native bridges, and managed
 * assembly layouts. It never starts Unity, loads GameAssembly, or runs code.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createUnityMetadataInspectHandler,
  unityMetadataInspectToolDefinition,
} from './tools/unity-metadata-inspect.js'

const unityManagedPlugin = definePlugin({
  id: 'unity-managed',
  name: 'Unity Managed Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['unity', 'unity-metadata', 'il2cpp', 'mono'],
    platforms: ['dotnet', 'windows', 'linux', 'macos', 'android', 'ios'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['metadata', 'managed-native-map', 'decompile-plan', 'routing'],
    evidence: ['manifest', 'symbols', 'nested-binaries', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['unity', 'unity-metadata', 'il2cpp', 'mono'],
    },
    category: 'dotnet-analysis',
  },
  description:
    'Passive Unity metadata, Mono assembly, and IL2CPP bridge inventory without Unity runtime execution.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...unityMetadataInspectToolDefinition,
      handler: (args, deps) => createUnityMetadataInspectHandler(deps)(args as never),
    }),
  ],
})

export default unityManagedPlugin
