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
          if (type.includes('.net') || type.includes('msil') || type.includes('dotnet')) signals.push('dotnet')
          if (type.includes('golang') || type === 'go') signals.push('go')
        }
      }
      return signals
    },
  },
  description: 'Deep signature-based identification of compilers, packers, linkers, and crypto using DIE',
  version: '1.0.0',
  configSchema: [
    { envVar: 'DIEC_PATH', description: 'Path to diec (DIE console) binary', required: false, defaultValue: '/usr/local/bin/diec' },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'diec',
      target: '$DIEC_PATH',
      envVar: 'DIEC_PATH',
      dockerDefault: '/usr/local/bin/diec',
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
