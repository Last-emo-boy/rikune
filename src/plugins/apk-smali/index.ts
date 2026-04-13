/**
 * apk-smali — APK disassembly, resource decoding, and manifest parsing via apktool.
 */

import type { Plugin } from '../sdk.js'

import { apkDisassembleToolDefinition, createApkDisassembleHandler } from './tools/apk-disassemble.js'
import { apkResourcesDecodeToolDefinition, createApkResourcesDecodeHandler } from './tools/apk-resources-decode.js'
import { apkManifestParseToolDefinition, createApkManifestParseHandler } from './tools/apk-manifest-parse.js'

const apkSmaliPlugin: Plugin = {
  id: 'apk-smali',
  name: 'APK Smali Analysis',
  surfaceRules: { tier: 1, activateOn: { fileTypes: ['apk', 'android'] }, category: 'android-analysis' },
  description: 'APK disassembly to Smali bytecode, resource decoding, and manifest parsing via apktool.',
  version: '1.0.0',

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
