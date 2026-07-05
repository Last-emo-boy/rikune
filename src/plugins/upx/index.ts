/**
 * UPX Plugin
 *
 * UPX packer/unpacker for executable compression analysis.
 */

import type { Plugin } from '../sdk.js'
import { upxInspectToolDefinition, createUPXInspectHandler } from './tools/upx-inspect.js'

const upxPlugin: Plugin = {
  id: 'upx',
  name: 'UPX',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'upx-packed'],
    platforms: ['windows', 'linux', 'macos', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'unpacking', 'triage'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'upx-detection',
      'upx-unpacking',
      'packer-analysis',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: ['packed', 'structure', 'unpacked-binary', 'workflow', 'provenance'],
  },
  surfaceRules: { tier: 2, activateOn: { findings: ['packed', 'upx'] }, category: 'unpacking' },
  description: 'UPX packer/unpacker for executable compression analysis',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'UPX_PATH',
      description: 'Path to UPX binary',
      required: false,
      defaultValue: '/usr/local/bin/upx',
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'upx',
      target: '$UPX_PATH',
      envVar: 'UPX_PATH',
      dockerDefault: '/usr/local/bin/upx',
      required: false,
      description: 'UPX packer/unpacker',
      dockerInstall: 'Download UPX release to /usr/local/bin',
      dockerFeature: 'upx',
      dockerValidation: ['upx --version >/dev/null 2>&1'],
      buildArgs: { UPX_VERSION: '5.1.1' },
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(upxInspectToolDefinition, createUPXInspectHandler(wm, db))
    return ['upx.inspect']
  },
}

export default upxPlugin
