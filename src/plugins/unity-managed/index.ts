/**
 * Unity Managed/IL2CPP Plugin
 *
 * Passive inventory for Unity metadata, IL2CPP native bridges, and managed
 * assembly layouts. It never starts Unity, loads GameAssembly, or runs code.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  UNITY_METADATA_CAPABILITIES,
  UNITY_METADATA_EVIDENCE,
  UNITY_METADATA_FORMATS,
  UNITY_METADATA_PLATFORMS,
  UNITY_METADATA_RUNTIME_POLICY,
  UNITY_METADATA_SAFETY,
  createUnityMetadataInspectHandler,
  unityMetadataInspectToolDefinition,
} from './tools/unity-metadata-inspect.js'

const unityManagedPlugin = definePlugin({
  id: 'unity-managed',
  name: 'Unity Managed Inventory',
  executionDomain: 'static',
  aspects: {
    formats: UNITY_METADATA_FORMATS,
    platforms: UNITY_METADATA_PLATFORMS,
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: UNITY_METADATA_SAFETY,
    capabilities: UNITY_METADATA_CAPABILITIES,
    evidence: UNITY_METADATA_EVIDENCE,
  },
  runtimePolicy: UNITY_METADATA_RUNTIME_POLICY,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'unity',
        'unity-metadata',
        'global-metadata',
        'global-metadata.dat',
        'il2cpp',
        'gameassembly',
        'libil2cpp',
        'mono',
      ],
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
