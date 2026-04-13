/**
 * Wine Plugin
 *
 * Wine Windows compatibility layer for running Windows executables.
 */

import type { Plugin } from '../sdk.js'
import { wineRunToolDefinition, createWineRunHandler } from './tools/wine-run.js'

const winePlugin: Plugin = {
  id: 'wine',
  name: 'Wine',
  surfaceRules: { tier: 3, category: 'dynamic-analysis' },
  description: 'Wine Windows compatibility layer for running Windows executables',
  version: '1.0.0',
  configSchema: [
    { envVar: 'WINE_PATH', description: 'Path to Wine binary', required: false, defaultValue: '/usr/bin/wine' },
  ],
  systemDeps: [
    { type: 'binary', name: 'wine', target: '$WINE_PATH', envVar: 'WINE_PATH', dockerDefault: '/usr/bin/wine', required: false, description: 'Wine Windows compatibility layer', dockerInstall: 'apt-get install -y wine wine64', dockerFeature: 'wine', aptPackages: ['wine', 'wine64'], dockerValidation: ['wine --version >/dev/null 2>&1', 'command -v winedbg >/dev/null 2>&1'] },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(wineRunToolDefinition, createWineRunHandler(wm, db))
    return ['wine.run']
  },
}

export default winePlugin
