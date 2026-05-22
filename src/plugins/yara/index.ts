/**
 * YARA Plugin
 *
 * YARA rule scanning, single-rule generation, and batch rule generation.
 */

import type { Plugin } from '../sdk.js'
import { yaraScanToolDefinition, createYaraScanHandler } from './tools/yara-scan.js'
import { yaraGenerateToolDefinition, createYaraGenerateHandler } from './tools/yara-generate.js'
import {
  yaraGenerateBatchToolDefinition,
  createYaraGenerateBatchHandler,
} from './tools/yara-generate-batch.js'

const yaraPlugin: Plugin = {
  id: 'yara',
  name: 'YARA',
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
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['signatures', 'malware-family', 'packer', 'rule-generation'],
    evidence: ['signatures', 'strings', 'imports', 'provenance'],
  },
  surfaceRules: { tier: 0, category: 'malware-analysis' },
  description: 'YARA rule scanning and generation (single and batch)',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db, cacheManager: cm } = deps

    server.registerTool(yaraScanToolDefinition, createYaraScanHandler(wm, db, cm))
    server.registerTool(yaraGenerateToolDefinition, createYaraGenerateHandler(wm, db))
    server.registerTool(yaraGenerateBatchToolDefinition, createYaraGenerateBatchHandler(wm, db))

    return ['yara.scan', 'yara.generate', 'yara.generate.batch']
  },
}

export default yaraPlugin
