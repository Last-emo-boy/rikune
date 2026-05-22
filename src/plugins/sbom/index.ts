/**
 * SBOM Plugin
 *
 * Software Bill of Materials generation.
 */

import { definePlugin, defineTool, requireDatabase, requireWorkspaceManager } from '../sdk.js'
import { sbomGenerateToolDefinition, createSbomGenerateHandler } from './tools/sbom-generate.js'

const sbomPlugin = definePlugin({
  id: 'sbom',
  name: 'SBOM',
  executionDomain: 'static',
  aspects: {
    formats: [
      'pe',
      'elf',
      'macho',
      'apk',
      'jar',
      'dotnet',
      'nupkg',
      'deb',
      'rpm',
      'apk-alpine',
      'firmware',
      'archive',
      'container',
      'docker-image',
      'oci-image',
    ],
    platforms: [
      'windows',
      'linux',
      'macos',
      'android',
      'jvm',
      'dotnet',
      'embedded',
      'cross-platform',
    ],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['sbom', 'dependency-inventory', 'provenance'],
    evidence: ['sbom', 'package-metadata', 'imports', 'strings', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['dotnet', 'go'] },
    category: 'static-analysis',
  },
  description: 'Software Bill of Materials (SBOM) generation from binary analysis',
  version: '1.0.0',
  tools: [
    defineTool({
      ...sbomGenerateToolDefinition,
      handler: (args, deps) =>
        createSbomGenerateHandler(
          requireWorkspaceManager(deps, 'sbom.generate'),
          requireDatabase(deps, 'sbom.generate')
        )(args as never),
    }),
  ],
})

export default sbomPlugin
