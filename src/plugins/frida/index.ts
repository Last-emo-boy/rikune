/**
 * Frida Instrumentation Plugin
 *
 * Runtime instrumentation, script injection, and trace capture via Frida.
 */

import { execFileSync } from 'child_process'
import type { Plugin } from '../sdk.js'
import { getWorkspaceServices } from '../sdk.js'
import {
  fridaRuntimeInstrumentToolDefinition,
  createFridaRuntimeInstrumentHandler,
} from './tools/frida-runtime-instrument.js'
import {
  fridaScriptInjectToolDefinition,
  createFridaScriptInjectHandler,
} from './tools/frida-script-inject.js'
import {
  fridaTraceCaptureToolDefinition,
  createFridaTraceCaptureHandler,
} from './tools/frida-trace-capture.js'
import {
  fridaScriptGenerateToolDefinition,
  createFridaScriptGenerateHandler,
} from './tools/frida-script-generate.js'

const fridaPlugin: Plugin = {
  id: 'frida',
  name: 'Frida Instrumentation',
  executionDomain: 'dynamic',
  aspects: {
    formats: ['pe', 'dll', 'dotnet', 'elf', 'so', 'macho', 'ipa', 'apk', 'dex', 'android-package'],
    platforms: ['windows', 'linux', 'macos', 'ios', 'android'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['dynamic'],
    runtimes: ['frida', 'frida-server', 'adb', 'android-emulator', 'idevice-tools'],
    safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
    capabilities: [
      'hook-plan',
      'script-generation',
      'script-injection',
      'trace-capture',
      'method-trace',
    ],
    evidence: ['method-calls', 'api-calls', 'filesystem', 'network', 'crypto', 'timeline'],
  },
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: true,
    allowedBackends: ['frida', 'frida-server', 'adb', 'android-emulator', 'idevice-tools'],
    maxRuntimeMs: 120000,
    networkPolicy: 'disabled',
    notes: [
      'Frida injection and trace capture require explicit opt-in and an approved target process/device.',
      'Script generation is local planning, but injection/capture must remain runtime-gated.',
    ],
  },
  surfaceRules: { tier: 3, category: 'dynamic-analysis' },
  description: 'Runtime instrumentation, script injection, and trace capture via Frida',
  version: '1.0.0',
  configSchema: [
    { envVar: 'FRIDA_PATH', description: 'Path to frida CLI binary', required: false },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'frida',
      versionFlag: '--version',
      envVar: 'FRIDA_PATH',
      required: true,
      description: 'Frida dynamic instrumentation toolkit',
      dockerInstall: 'pip install frida-tools',
      dockerFeature: 'frida',
      dockerValidation: ['frida-ps --help >/dev/null 2>&1'],
    },
  ],
  resources: { scripts: 'scripts' },
  check() {
    try {
      execFileSync('frida', ['--version'], { stdio: 'ignore', timeout: 3000 })
      return true
    } catch {
      return false
    }
  },
  register(server, deps) {
    const workspace = getWorkspaceServices(deps)
    server.registerTool(
      fridaRuntimeInstrumentToolDefinition,
      createFridaRuntimeInstrumentHandler(deps)
    )
    server.registerTool(fridaScriptInjectToolDefinition, createFridaScriptInjectHandler(deps))
    server.registerTool(fridaTraceCaptureToolDefinition, createFridaTraceCaptureHandler(deps))
    server.registerTool(
      fridaScriptGenerateToolDefinition,
      createFridaScriptGenerateHandler(workspace.manager, workspace.database)
    )
    return [
      'frida.runtime.instrument',
      'frida.script.inject',
      'frida.trace.capture',
      'frida.script.generate',
    ]
  },
}

export default fridaPlugin
