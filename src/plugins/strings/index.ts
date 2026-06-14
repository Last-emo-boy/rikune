/**
 * Strings Extraction Plugin
 *
 * Unicode/ASCII string extraction and FLOSS-based obfuscated string decoding.
 */

import type { Plugin } from '../sdk.js'
import { getPlatformServices, getWorkspaceServices } from '../sdk.js'
import {
  stringsExtractToolDefinition,
  createStringsExtractHandler,
} from './tools/strings-extract.js'
import {
  stringsFlossDecodeToolDefinition,
  createStringsFlossDecodeHandler,
} from './tools/strings-floss-decode.js'

const stringsPlugin: Plugin = {
  id: 'strings',
  name: 'Strings Extraction',
  executionDomain: 'static',
  aspects: {
    formats: [
      'pe',
      'elf',
      'macho',
      'apk',
      'dex',
      'jar',
      'dotnet',
      'wasm',
      'firmware',
      'archive',
      'container',
      'pyc',
      'lua-bytecode',
      'v8-cache',
    ],
    platforms: [
      'windows',
      'linux',
      'macos',
      'android',
      'jvm',
      'dotnet',
      'wasm',
      'embedded',
      'cross-platform',
    ],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'external_static_backend',
      'no_live_sample_by_default',
      'no_network_by_default',
      'no_mutation',
    ],
    capabilities: [
      'strings',
      'ioc',
      'floss-decode',
      'context-windows',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: [
      'strings',
      'network',
      'filesystem',
      'registry',
      'encoded-config',
      'workflow',
      'provenance',
    ],
  },
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description: 'Extract printable strings and decode obfuscated strings via FLOSS',
  version: '1.0.0',
  systemDeps: [
    {
      type: 'python',
      name: 'flare-floss',
      importName: 'floss',
      required: false,
      description:
        'FLARE-FLOSS Python package used by the optional static decoded-string backend.',
      dockerInstall: 'pip install flare-floss',
      dockerFeature: 'static-python',
      dockerValidation: ['python3 -m floss --version'],
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
    {
      type: 'binary',
      name: 'floss',
      target: '$FLOSS_PATH',
      envVar: 'FLOSS_PATH',
      required: false,
      description:
        'Optional FLARE-FLOSS command used for decoded string recovery when available.',
      dockerInstall: 'pip install flare-floss',
      dockerFeature: 'static-python',
      dockerValidation: ['floss --version'],
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
  ],
  register(server, deps) {
    const workspace = getWorkspaceServices(deps)
    const platform = getPlatformServices(deps)
    server.registerTool(
      stringsExtractToolDefinition,
      createStringsExtractHandler(
        workspace.manager,
        workspace.database,
        platform.cacheManager,
        platform.jobQueue
      )
    )
    server.registerTool(
      stringsFlossDecodeToolDefinition,
      createStringsFlossDecodeHandler(
        workspace.manager,
        workspace.database,
        platform.cacheManager,
        platform.jobQueue
      )
    )
    return ['strings.extract', 'strings.floss.decode']
  },
}

export default stringsPlugin
