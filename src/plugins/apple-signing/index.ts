/**
 * Apple Signing Inventory Plugin
 *
 * Passive inventory for Apple code signing, provisioning profiles,
 * entitlements, and bundle metadata. It does not call codesign, access
 * keychains, mount images, install apps, or connect devices.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  appleSigningInspectToolDefinition,
  createAppleSigningInspectHandler,
} from './tools/apple-signing-inspect.js'

const appleSigningPlugin = definePlugin({
  id: 'apple-signing',
  name: 'Apple Signing Inventory',
  executionDomain: 'static',
  aspects: {
    formats: [
      'apple-signing',
      'codesignature',
      'entitlements',
      'plist',
      'mobileprovision',
      'ipa',
      'app-bundle',
      'framework',
      'xcframework',
      'dylib',
      'macho',
      'dsym',
    ],
    platforms: ['macos', 'ios'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_network_by_default', 'no_live_sample_by_default'],
    capabilities: ['inventory', 'package-metadata', 'provisioning', 'certificates', 'routing'],
    evidence: ['manifest', 'certificates', 'package-metadata', 'nested-binaries', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'apple-signing',
        'codesignature',
        'entitlements',
        'plist',
        'mobileprovision',
        'ipa',
        'app-bundle',
        'framework',
        'xcframework',
        'dylib',
        'macho',
        'mach-o',
        'mach-o-fat',
        'dsym',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Apple signing, provisioning, entitlement, and bundle metadata inventory without codesign/keychain/device actions.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...appleSigningInspectToolDefinition,
      handler: (args, deps) => createAppleSigningInspectHandler(deps)(args as never),
    }),
  ],
})

export default appleSigningPlugin
