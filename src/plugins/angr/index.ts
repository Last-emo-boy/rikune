/**
 * angr Plugin
 *
 * Symbolic execution and binary analysis via angr.
 */

import type { Plugin } from '../sdk.js'
import { angrAnalyzeToolDefinition, createAngrAnalyzeHandler } from './tools/angr-analyze.js'

const angrPlugin: Plugin = {
  id: 'angr',
  name: 'angr',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'symbolic-execution' },
  description: 'Symbolic execution and binary analysis via angr',
  version: '1.0.0',
  configSchema: [
    { envVar: 'ANGR_PYTHON', description: 'Python binary with angr installed', required: false, defaultValue: '/opt/angr-venv/bin/python' },
  ],
  systemDeps: [
    { type: 'python-venv', name: 'angr', target: '$ANGR_PYTHON', envVar: 'ANGR_PYTHON', dockerDefault: '/opt/angr-venv/bin/python', required: false, description: 'angr symbolic execution (venv)', dockerInstall: 'python3 -m venv /opt/angr-venv && pip install angr', dockerFeature: 'angr', dockerValidation: ['/opt/angr-venv/bin/python -c "import angr; print(\'✓ angr\')"'], buildArgs: { ANGR_VERSION: '9.2.205' } },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(angrAnalyzeToolDefinition, createAngrAnalyzeHandler(wm, db))
    return ['angr.analyze']
  },
}

export default angrPlugin
