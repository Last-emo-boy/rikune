/**
 * Apple Container Plugin
 *
 * Passive inventory for IPA, DMG, PKG, app bundle, framework, and provisioning
 * containers. It does not mount images, install packages, launch apps, or
 * connect to devices.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  appleContainerInventoryToolDefinition,
  createAppleContainerInventoryHandler,
} from './tools/apple-container-inventory.js'

const appleContainerPlugin = definePlugin({
  id: 'apple-container',
  name: 'Apple Container Inventory',
  executionDomain: 'static',
  aspects: {
    formats: [
      'ipa',
      'dmg',
      'pkg',
      'app-bundle',
      'framework',
      'xcframework',
      'dylib',
      'dsym',
      'mobileprovision',
    ],
    platforms: ['macos', 'ios'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_installer_execution', 'no_auto_mount'],
    capabilities: ['inventory', 'package-metadata', 'provisioning', 'nested-binaries', 'routing'],
    evidence: ['package-metadata', 'manifest', 'certificates', 'nested-binaries', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'ipa',
        'dmg',
        'pkg',
        'app-bundle',
        'framework',
        'xcframework',
        'dylib',
        'dsym',
        'mobileprovision',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Apple container inventory for IPA, DMG, PKG, app bundle, framework, and provisioning metadata without mount/install/device actions.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...appleContainerInventoryToolDefinition,
      handler: (args, deps) => createAppleContainerInventoryHandler(deps)(args as never),
    }),
  ],
})

export default appleContainerPlugin
