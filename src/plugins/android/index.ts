/**
 * Android / APK Analysis Plugin
 *
 * APK manifest extraction, DEX decompilation, packer detection.
 */

import { accessSync } from 'fs'
import type { Plugin } from '../sdk.js'
import {
  apkStructureAnalyzeToolDefinition,
  createApkStructureAnalyzeHandler,
} from './tools/apk-structure-analyze.js'
import { dexDecompileToolDefinition, createDexDecompileHandler } from './tools/dex-decompile.js'
import {
  dexClassesListToolDefinition,
  createDexClassesListHandler,
} from './tools/dex-classes-list.js'
import {
  apkPackerDetectToolDefinition,
  createApkPackerDetectHandler,
} from './tools/apk-packer-detect.js'

const androidPlugin: Plugin = {
  id: 'android',
  name: 'Android / APK Analysis',
  executionDomain: 'static',
  aspects: {
    formats: ['apk', 'aab', 'apks', 'xapk', 'split-apk', 'dex', 'multi-dex', 'oat', 'vdex', 'aar'],
    platforms: ['android'],
    architectures: ['arm', 'arm64', 'x86', 'x64'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: [
      'structure',
      'resources',
      'signatures',
      'classes',
      'native-lib',
      'packer',
      'runtime-routing',
      'hook-plan-input',
    ],
    evidence: ['structure', 'manifest', 'strings', 'signatures', 'nested-binaries', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'apk',
        'aab',
        'apks',
        'xapk',
        'split-apk',
        'android',
        'dex',
        'oat',
        'vdex',
        'aar',
      ],
    },
    category: 'android-analysis',
  },
  description: 'APK manifest extraction, DEX decompilation, and packer detection',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'JADX_PATH',
      description: 'Path to jadx binary for DEX decompilation',
      required: false,
      defaultValue: '/opt/jadx/bin/jadx',
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'JADX',
      target: '$JADX_PATH',
      envVar: 'JADX_PATH',
      dockerDefault: '/opt/jadx/bin/jadx',
      required: true,
      description: 'JADX DEX/APK decompiler',
      dockerInstall: 'Download jadx release to /opt/jadx',
      dockerFeature: 'jadx',
      dockerValidation: ['jadx --version >/dev/null 2>&1'],
      buildArgs: { JADX_VERSION: '1.5.1' },
    },
  ],
  resources: { workers: 'workers', scripts: 'scripts' },
  check() {
    const jadx = process.env.JADX_PATH ?? '/opt/jadx/bin/jadx'
    try {
      accessSync(jadx)
      return true
    } catch {
      return false
    }
  },
  register(server, deps) {
    server.registerTool(apkStructureAnalyzeToolDefinition, createApkStructureAnalyzeHandler(deps))
    server.registerTool(dexDecompileToolDefinition, createDexDecompileHandler(deps))
    server.registerTool(dexClassesListToolDefinition, createDexClassesListHandler(deps))
    server.registerTool(apkPackerDetectToolDefinition, createApkPackerDetectHandler(deps))
    return ['apk.structure.analyze', 'dex.decompile', 'dex.classes.list', 'apk.packer.detect']
  },
}

export default androidPlugin
