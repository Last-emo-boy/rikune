/**
 * Android Package Inventory Plugin
 *
 * Passive inventory for APK, AAB, APKS, XAPK, AAR, and Android bytecode. It
 * never installs packages, launches runtimes, starts decompilers, or connects
 * to devices.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  androidPackageInventoryToolDefinition,
  createAndroidPackageInventoryHandler,
} from './tools/android-package-inventory.js'

const androidPackagePlugin = definePlugin({
  id: 'android-package',
  name: 'Android Package Inventory',
  executionDomain: 'static',
  aspects: {
    formats: [
      'android-package',
      'android-bytecode',
      'apk',
      'aab',
      'apks',
      'xapk',
      'split-apk',
      'aar',
      'dex',
      'multi-dex',
      'oat',
      'vdex',
      'odex',
      'art',
      'apk-signature',
      'arsc',
    ],
    platforms: ['android', 'jvm', 'linux'],
    architectures: ['arm', 'arm64', 'x86', 'x64', 'riscv'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'no_install',
      'no_device_connection',
      'no_decompiler_launch',
      'no_live_sample_by_default',
    ],
    capabilities: [
      'inventory',
      'manifest',
      'resources',
      'signatures',
      'native-lib',
      'routing',
      'workflow-plan',
      'metadata-only-handoff',
    ],
    evidence: [
      'structure',
      'manifest',
      'signatures',
      'nested-binaries',
      'package-metadata',
      'provenance',
    ],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'android-package',
        'android-bytecode',
        'apk',
        'aab',
        'apks',
        'xapk',
        'split-apk',
        'aar',
        'dex',
        'multi-dex',
        'oat',
        'vdex',
        'odex',
        'art',
      ],
    },
    category: 'android-analysis',
  },
  description:
    'Passive Android package and bytecode inventory with DEX, native library, signing, and split-package routing hints.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...androidPackageInventoryToolDefinition,
      handler: (args, deps) => createAndroidPackageInventoryHandler(deps)(args as never),
    }),
  ],
})

export default androidPackagePlugin
