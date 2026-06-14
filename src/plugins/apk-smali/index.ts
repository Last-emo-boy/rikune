/**
 * apk-smali — APK disassembly, resource decoding, and manifest parsing via apktool.
 */

import type { Plugin } from '../sdk.js'

import {
  apkDisassembleToolDefinition,
  createApkDisassembleHandler,
} from './tools/apk-disassemble.js'
import {
  apkResourcesDecodeToolDefinition,
  createApkResourcesDecodeHandler,
} from './tools/apk-resources-decode.js'
import {
  apkManifestParseToolDefinition,
  createApkManifestParseHandler,
} from './tools/apk-manifest-parse.js'

const APK_SMALI_SAFETY = [
  'passive',
  'static',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
  'no_live_execution',
]

const apkSmaliPlugin: Plugin = {
  id: 'apk-smali',
  name: 'APK Smali Analysis',
  executionDomain: 'static',
  aspects: {
    formats: ['apk', 'aab', 'apks', 'xapk', 'split-apk', 'dex', 'aar'],
    platforms: ['android'],
    architectures: ['arm', 'arm64', 'x86', 'x64'],
    execution: ['static', 'triage', 'decompilation'],
    safety: APK_SMALI_SAFETY,
    capabilities: [
      'smali',
      'multi-dex',
      'manifest',
      'permissions',
      'android-components',
      'resources',
      'classes',
      'routing',
      'workflow-handoff',
    ],
    evidence: ['structure', 'manifest', 'resources', 'strings', 'workflow', 'provenance'],
    search: [
      'apktool',
      'smali',
      'multi-dex',
      'androidmanifest',
      'permissions',
      'activities',
      'services',
      'receivers',
      'resources',
      'strings.xml',
    ],
  },
  surfaceRules: {
    tier: 1,
    activateOn: { fileTypes: ['apk', 'aab', 'apks', 'xapk', 'split-apk', 'aar', 'android'] },
    category: 'android-analysis',
  },
  description:
    'Passive APK disassembly to Smali bytecode, resource decoding, manifest parsing, and multi-dex Android routing via apktool.',
  version: '1.0.0',
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'apk-smali tools invoke apktool to decode local APK content and never execute Android bytecode.',
      'Decoded output is temporary unless the caller requests persisted listing artifacts.',
    ],
  } as Plugin['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
  },

  systemDeps: [
    {
      type: 'binary',
      name: 'apktool',
      target: '$APKTOOL_PATH',
      envVar: 'APKTOOL_PATH',
      dockerDefault: '/usr/bin/apktool',
      versionFlag: '--version',
      required: false,
      description: 'APKTool for APK disassembly and resource decoding.',
      aptPackages: ['apktool'],
      dockerValidation: ['apktool --version >/dev/null 2>&1'],
    },
  ],

  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(apkDisassembleToolDefinition, createApkDisassembleHandler(wm, db))
    server.registerTool(apkManifestParseToolDefinition, createApkManifestParseHandler(wm, db))
    server.registerTool(apkResourcesDecodeToolDefinition, createApkResourcesDecodeHandler(wm, db))

    return ['apk.disassemble', 'apk.manifest.parse', 'apk.resources.decode']
  },
}

export default apkSmaliPlugin
