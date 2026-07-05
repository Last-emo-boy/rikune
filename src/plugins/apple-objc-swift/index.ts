/**
 * Apple Objective-C / Swift Metadata Plugin
 *
 * Passive Objective-C and Swift metadata inventory for Mach-O and standalone
 * Swift metadata artifacts. It never mounts images, launches apps, attaches
 * debuggers, calls otool, swift-demangle, codesign, class-dump, nm, lipo, or
 * starts Apple runtime tooling.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  appleObjcSwiftMetadataInspectToolDefinition,
  createAppleObjcSwiftMetadataInspectHandler,
} from './tools/apple-objc-swift-metadata-inspect.js'

const appleObjcSwiftPlugin = definePlugin({
  id: 'apple-objc-swift',
  name: 'Apple ObjC / Swift Metadata Inventory',
  executionDomain: 'static',
  aspects: {
    formats: [
      'objc-metadata',
      'objective-c',
      'objc',
      'swift-metadata',
      'swift',
      'swiftmodule',
      'swiftinterface',
      'swiftdoc',
      'swift-abi',
      'swift-reflection',
      'macho',
      'mach-o',
      'mach-o-fat',
      'macho-object',
      'dylib',
      'framework',
      'xcframework',
      'app-bundle',
      'ipa',
      'dsym',
    ],
    platforms: ['macos', 'ios'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage', 'workflow-plan'],
    safety: [
      'passive',
      'no_execute',
      'no_debug_attach',
      'no_app_launch',
      'no_auto_mount',
      'no_external_tool',
      'no_runtime_start',
      'no_network_by_default',
      'no_mutation',
    ],
    capabilities: [
      'objc-runtime-metadata-inventory',
      'swift-abi-metadata-inventory',
      'selector-inventory',
      'class-protocol-inventory',
      'swift-reflection-hints',
      'demangle-plan',
      'runtime-handoff',
      'workflow-routing',
    ],
    evidence: [
      'structure',
      'symbols',
      'classes',
      'selectors',
      'protocols',
      'swift-metadata',
      'workflow',
      'provenance',
    ],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'objc-metadata',
        'objective-c',
        'objc',
        'swift-metadata',
        'swift',
        'swiftmodule',
        'swiftinterface',
        'swiftdoc',
        'swift-abi',
        'swift-reflection',
        'macho',
        'mach-o',
        'mach-o-fat',
        'macho-object',
        'dylib',
        'framework',
        'xcframework',
        'app-bundle',
        'ipa',
        'dsym',
      ],
      findings: ['objc', 'objective-c', 'swift', 'swift5', 'selector', 'classlist'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Objective-C and Swift metadata inventory from Mach-O sections, symbols, and standalone Swift metadata files without app launch, debugger attach, external Apple tooling, or runtime start.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...appleObjcSwiftMetadataInspectToolDefinition,
      handler: (args, deps) => createAppleObjcSwiftMetadataInspectHandler(deps)(args as never),
    }),
  ],
})

export default appleObjcSwiftPlugin
