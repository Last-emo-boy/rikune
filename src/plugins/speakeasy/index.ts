/**
 * Speakeasy Plugin
 *
 * Windows user-mode emulation via Mandiant Speakeasy.
 * Emulates PE files and shellcode without running them natively.
 */

import type { Plugin } from '../sdk.js'
import {
  speakeasyEmulateToolDefinition,
  createSpeakeasyEmulateHandler,
} from './tools/speakeasy-emulate.js'
import {
  speakeasyShellcodeToolDefinition,
  createSpeakeasyShellcodeHandler,
} from './tools/speakeasy-shellcode.js'
import {
  speakeasyApiTraceToolDefinition,
  createSpeakeasyApiTraceHandler,
} from './tools/speakeasy-api-trace.js'
import {
  SPEAKEASY_ARCHITECTURES,
  SPEAKEASY_CAPABILITIES,
  SPEAKEASY_EVIDENCE,
  SPEAKEASY_FORMATS,
  SPEAKEASY_PLATFORMS,
  SPEAKEASY_RUNTIME_BACKENDS,
  SPEAKEASY_RUNTIME_POLICY,
  SPEAKEASY_SAFETY,
  SPEAKEASY_SYSTEM_DEP,
} from './speakeasy-metadata.js'

const speakeasyPlugin: Plugin = {
  id: 'speakeasy',
  name: 'Speakeasy Emulator',
  executionDomain: 'dynamic',
  aspects: {
    formats: SPEAKEASY_FORMATS,
    platforms: SPEAKEASY_PLATFORMS,
    architectures: SPEAKEASY_ARCHITECTURES,
    execution: ['dynamic', 'emulation'],
    runtimes: SPEAKEASY_RUNTIME_BACKENDS,
    safety: SPEAKEASY_SAFETY,
    capabilities: SPEAKEASY_CAPABILITIES,
    evidence: SPEAKEASY_EVIDENCE,
  },
  runtimePolicy: SPEAKEASY_RUNTIME_POLICY,
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['shellcode', 'suspicious_imports', 'packed'] },
    category: 'dynamic-analysis',
  },
  description: 'Windows user-mode emulation for PE files and shellcode via Mandiant Speakeasy',
  version: '1.0.0',
  systemDeps: [SPEAKEASY_SYSTEM_DEP],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(speakeasyEmulateToolDefinition, createSpeakeasyEmulateHandler(wm, db))
    server.registerTool(speakeasyShellcodeToolDefinition, createSpeakeasyShellcodeHandler(wm, db))
    server.registerTool(speakeasyApiTraceToolDefinition, createSpeakeasyApiTraceHandler(wm, db))

    return ['speakeasy.emulate', 'speakeasy.shellcode', 'speakeasy.api_trace']
  },
}

export default speakeasyPlugin
