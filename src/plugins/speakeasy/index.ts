/**
 * Speakeasy Plugin
 *
 * Windows user-mode emulation via Mandiant Speakeasy.
 * Emulates PE files and shellcode without running them natively.
 */

import type { Plugin } from '../sdk.js'
import { speakeasyEmulateToolDefinition, createSpeakeasyEmulateHandler } from './tools/speakeasy-emulate.js'
import { speakeasyShellcodeToolDefinition, createSpeakeasyShellcodeHandler } from './tools/speakeasy-shellcode.js'
import { speakeasyApiTraceToolDefinition, createSpeakeasyApiTraceHandler } from './tools/speakeasy-api-trace.js'

const speakeasyPlugin: Plugin = {
  id: 'speakeasy',
  name: 'Speakeasy Emulator',
  executionDomain: 'dynamic',
  surfaceRules: { tier: 2, activateOn: { findings: ['shellcode', 'suspicious_imports', 'packed'] }, category: 'dynamic-analysis' },
  description: 'Windows user-mode emulation for PE files and shellcode via Mandiant Speakeasy',
  version: '1.0.0',
  systemDeps: [
    {
      type: 'python',
      name: 'speakeasy-emulator',
      importName: 'speakeasy',
      required: false,
      description: 'Mandiant Speakeasy Windows emulator',
      dockerInstall: 'pip install speakeasy-emulator',
      dockerFeature: 'dynamic-python',
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(speakeasyEmulateToolDefinition, createSpeakeasyEmulateHandler(wm, db))
    server.registerTool(speakeasyShellcodeToolDefinition, createSpeakeasyShellcodeHandler(wm, db))
    server.registerTool(speakeasyApiTraceToolDefinition, createSpeakeasyApiTraceHandler(wm, db))

    return ['speakeasy.emulate', 'speakeasy.shellcode', 'speakeasy.api_trace']
  },
}

export default speakeasyPlugin
