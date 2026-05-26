/**
 * YARA-X Plugin
 *
 * YARA-X next-gen pattern matching for malware detection.
 */

import type { Plugin } from '../sdk.js'
import { yaraXScanToolDefinition, createYaraXScanHandler } from './tools/yara-x-scan.js'

const yaraXPlugin: Plugin = {
  id: 'yara-x',
  name: 'YARA-X',
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
    ],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'signatures',
      'pattern-matching',
      'rule-matching',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: ['signatures', 'strings', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['packed', 'obfuscated'] },
    category: 'malware-analysis',
  },
  description: 'YARA-X next-gen pattern matching for malware detection',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'YARAX_PYTHON',
      description: 'Python binary with YARA-X installed',
      required: false,
      defaultValue: '/usr/local/bin/python3',
    },
  ],
  systemDeps: [
    {
      type: 'python',
      name: 'yara-x',
      importName: 'yara_x',
      required: false,
      description: 'YARA-X next-gen pattern matching',
      dockerInstall: 'pip install yara-x',
      dockerFeature: 'dynamic-python',
      extraEnv: { YARAX_PYTHON: '/usr/local/bin/python3' },
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(yaraXScanToolDefinition, createYaraXScanHandler(wm, db))
    return ['yara_x.scan']
  },
}

export default yaraXPlugin
