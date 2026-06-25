/**
 * Container Analysis Plugin
 *
 * Passive inventory for generic archives, installers, packages, Docker/OCI
 * images, and container-like bundles. It does not extract to an execution
 * path, mount images, install packages, or run entrypoints/hooks.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  containerStructureAnalyzeToolDefinition,
  createContainerStructureAnalyzeHandler,
} from './tools/container-structure-analyze.js'
import {
  containerImageSecurityProfileToolDefinition,
  createContainerImageSecurityProfileHandler,
} from './tools/container-image-security-profile.js'

const containerAnalysisPlugin = definePlugin({
  id: 'container-analysis',
  name: 'Container / Archive Inventory',
  executionDomain: 'static',
  aspects: {
    formats: [
      'archive',
      'container',
      'zip',
      '7z',
      'rar',
      'tar',
      'gz',
      'xz',
      'zstd',
      'iso',
      'ar',
      'static-lib',
      'ar-static-lib',
      'docker-image',
      'oci-image',
      'installer',
    ],
    platforms: ['windows', 'linux', 'macos', 'ios', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_network_by_default', 'no_installer_execution', 'no_auto_mount'],
    capabilities: ['inventory', 'nested-binaries', 'hashes', 'extraction-plan', 'routing'],
    evidence: ['nested-binaries', 'filesystem', 'package-metadata', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'archive',
        'container',
        'zip',
        '7z',
        'rar',
        'tar',
        'gz',
        'xz',
        'zstd',
        'iso',
        'ar',
        'static-lib',
        'ar-static-lib',
        'docker-image',
        'oci-image',
        'installer',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive archive/container inventory, Docker/OCI image security profiling, nested binary routing, and extraction safety planning.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...containerStructureAnalyzeToolDefinition,
      handler: (args, deps) => createContainerStructureAnalyzeHandler(deps)(args as never),
    }),
    defineTool({
      ...containerImageSecurityProfileToolDefinition,
      handler: (args, deps) => createContainerImageSecurityProfileHandler(deps)(args as never),
    }),
  ],
})

export default containerAnalysisPlugin
