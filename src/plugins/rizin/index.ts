/**
 * Rizin Plugin
 *
 * Rizin reverse engineering framework for binary analysis.
 */

import type { Plugin } from '../sdk.js'
import { rizinAnalyzeToolDefinition, createRizinAnalyzeHandler } from './tools/rizin-analyze.js'

const rizinPlugin: Plugin = {
  id: 'rizin',
  name: 'Rizin',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'reverse-engineering' },
  description: 'Rizin reverse engineering framework for binary analysis',
  version: '1.0.0',
  configSchema: [
    { envVar: 'RIZIN_PATH', description: 'Path to Rizin binary', required: false, defaultValue: '/opt/rizin/bin/rizin' },
  ],
  systemDeps: [
    { type: 'binary', name: 'rizin', target: '$RIZIN_PATH', envVar: 'RIZIN_PATH', dockerDefault: '/opt/rizin/bin/rizin', required: false, description: 'Rizin reverse engineering framework', dockerInstall: 'Download Rizin release to /opt/rizin', dockerFeature: 'rizin', dockerValidation: ['rizin -v >/dev/null 2>&1'], buildArgs: { RIZIN_VERSION: '0.8.2' } },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(rizinAnalyzeToolDefinition, createRizinAnalyzeHandler(wm, db))
    return ['rizin.analyze']
  },
}

export default rizinPlugin
