/**
 * Firmware Plugin
 *
 * Firmware analysis and embedded file extraction using binwalk.
 */

import type { Plugin } from '../sdk.js'
import { firmwareScanToolDefinition, createFirmwareScanHandler } from './tools/firmware-scan.js'
import { firmwareExtractToolDefinition, createFirmwareExtractHandler } from './tools/firmware-extract.js'
import { firmwareEntropyToolDefinition, createFirmwareEntropyHandler } from './tools/firmware-entropy.js'

const firmwarePlugin: Plugin = {
  id: 'firmware',
  name: 'Firmware Analysis',
  executionDomain: 'static',
  surfaceRules: {
    tier: 1,
    activateOn: { fileTypes: ['firmware'] },
    category: 'static-analysis',
    extractSignals: (data: Record<string, unknown>): string[] => {
      if (Array.isArray(data.firmware_signatures) && data.firmware_signatures.length > 0) {
        return ['firmware']
      }
      return []
    },
  },
  description: 'Firmware analysis, embedded file extraction, and entropy visualization using binwalk',
  version: '1.0.0',
  configSchema: [
    { envVar: 'BINWALK_PATH', description: 'Path to binwalk binary', required: false, defaultValue: 'binwalk' },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'binwalk',
      target: '$BINWALK_PATH',
      envVar: 'BINWALK_PATH',
      dockerDefault: '/usr/local/bin/binwalk',
      versionFlag: '--help',
      required: false,
      description: 'Binwalk firmware analysis tool',
      dockerInstall: 'cargo install binwalk || pip install binwalk',
      dockerFeature: 'binwalk',
      dockerValidation: ['binwalk --help >/dev/null 2>&1'],
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(firmwareScanToolDefinition, createFirmwareScanHandler(wm, db))
    server.registerTool(firmwareExtractToolDefinition, createFirmwareExtractHandler(wm, db))
    server.registerTool(firmwareEntropyToolDefinition, createFirmwareEntropyHandler(wm, db))

    return ['firmware.scan', 'firmware.extract', 'firmware.entropy']
  },
}

export default firmwarePlugin
