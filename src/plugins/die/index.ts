/**
 * Detect It Easy (DIE) Plugin
 *
 * Deep signature-based identification of compilers, packers, linkers,
 * and cryptographic algorithms using Detect It Easy.
 */

import type { Plugin } from '../sdk.js'
import { dieScanToolDefinition, createDieScanHandler } from './tools/die-scan.js'
import { dieIdentifyToolDefinition, createDieIdentifyHandler } from './tools/die-identify.js'

const diePlugin: Plugin = {
  id: 'die',
  name: 'Detect It Easy',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'apk', 'firmware', 'archive'],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'compiler-detect',
      'packer',
      'linker-detect',
      'crypto-detect',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: [
      'signatures',
      'toolchain',
      'packer',
      'protector',
      'file-type',
      'workflow',
      'provenance',
      'structure',
    ],
  },
  surfaceRules: {
    tier: 0,
    category: 'static-analysis',
    extractSignals: (data: Record<string, unknown>): string[] => {
      const signals: string[] = []
      const detections = data.detections as Array<Record<string, unknown>> | undefined
      if (Array.isArray(detections)) {
        for (const det of detections) {
          const type = ((det.type || det.name || '') as string).toLowerCase()
          if (type.includes('upx')) signals.push('packed', 'upx')
          if (type.includes('pack') || type.includes('protector')) signals.push('packed')
          if (type.includes('.net') || type.includes('msil') || type.includes('dotnet'))
            signals.push('dotnet')
          if (type.includes('golang') || type === 'go') signals.push('go')
        }
      }
      return signals
    },
  },
  description:
    'Deep signature-based identification of compilers, packers, linkers, and crypto using DIE',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'DIE_PATH',
      description: 'Path to diec (DIE console) binary',
      required: false,
      defaultValue: '/usr/bin/diec',
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'diec',
      target: '$DIE_PATH',
      envVar: 'DIE_PATH',
      dockerDefault: '/usr/bin/diec',
      versionFlag: '--version',
      required: false,
      description: 'Detect It Easy console scanner',
      dockerFeature: 'die',
      dockerValidation: ['diec --version >/dev/null 2>&1'],
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(dieScanToolDefinition, createDieScanHandler(wm, db))
    server.registerTool(dieIdentifyToolDefinition, createDieIdentifyHandler(wm, db))

    return ['die.scan', 'die.identify']
  },
}

export default diePlugin
