/**
 * Wine Plugin
 *
 * Wine Windows compatibility layer for running Windows executables.
 * Provides prefix management, DLL override configuration, registry
 * manipulation, and supervised execution/debugging of PE binaries.
 */

import type { Plugin } from '../sdk.js'
import { wineRunToolDefinition, createWineRunHandler } from './tools/wine-run.js'
import { wineEnvToolDefinition, createWineEnvHandler } from './tools/wine-env.js'
import {
  wineDllOverridesToolDefinition,
  createWineDllOverridesHandler,
} from './tools/wine-dll-overrides.js'
import { wineRegToolDefinition, createWineRegHandler } from './tools/wine-reg.js'

const winePlugin: Plugin = {
  id: 'wine',
  name: 'Wine',
  executionDomain: 'dynamic',
  aspects: {
    formats: ['pe', 'dll', 'dotnet', 'pe-clr', 'msi', 'installer'],
    platforms: ['windows', 'linux'],
    architectures: ['x86', 'x64', 'arm64'],
    execution: ['dynamic', 'emulation'],
    runtimes: ['wine'],
    safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
    capabilities: ['wine-prefix', 'dll-overrides', 'registry', 'execution-plan', 'behavior-hints'],
    evidence: ['process', 'filesystem', 'registry', 'network', 'api-calls', 'timeline'],
  },
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: true,
    allowedBackends: ['wine'],
    maxRuntimeMs: 120000,
    networkPolicy: 'disabled',
    notes: [
      'Wine behavior is a compatibility/emulation signal and must not be treated as native Windows ground truth.',
      'Readiness and planning paths must not launch Wine or execute PE payloads.',
    ],
  },
  surfaceRules: { tier: 3, category: 'dynamic-analysis' },
  description:
    'Wine Windows compatibility layer — prefix management, DLL overrides, registry manipulation, and supervised execution of PE binaries',
  version: '2.0.0',
  configSchema: [
    {
      envVar: 'WINE_PATH',
      description: 'Path to Wine binary',
      required: false,
      defaultValue: '/usr/bin/wine',
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'wine',
      target: '$WINE_PATH',
      envVar: 'WINE_PATH',
      dockerDefault: '/usr/bin/wine',
      required: false,
      description: 'Wine Windows compatibility layer (64-bit + 32-bit)',
      dockerInstall:
        'dpkg --add-architecture i386 && apt-get update && apt-get install -y wine wine64 wine32:i386',
      dockerFeature: 'wine',
      dockerValidation: ['wine --version >/dev/null 2>&1', 'command -v winedbg >/dev/null 2>&1'],
      extraEnv: { WINEDEBUG: '-all' },
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(wineRunToolDefinition, createWineRunHandler(wm, db))
    server.registerTool(wineEnvToolDefinition, createWineEnvHandler(wm, db))
    server.registerTool(wineDllOverridesToolDefinition, createWineDllOverridesHandler(wm, db))
    server.registerTool(wineRegToolDefinition, createWineRegHandler(wm, db))
    return ['wine.run', 'wine.env', 'wine.dll_overrides', 'wine.reg']
  },
}

export default winePlugin
