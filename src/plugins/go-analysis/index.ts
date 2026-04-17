/**
 * Go Analysis Plugin
 *
 * Go binary symbol and type recovery using Mandiant GoReSym.
 */

import type { Plugin } from '../sdk.js'
import { goSymbolsRecoverToolDefinition, createGoSymbolsRecoverHandler } from './tools/go-symbols-recover.js'
import { goTypesListToolDefinition, createGoTypesListHandler } from './tools/go-types-list.js'
import { goBinaryAnalyzeToolDefinition, createGoBinaryAnalyzeHandler } from './tools/go-binary-analyze.js'

const goAnalysisPlugin: Plugin = {
  id: 'go-analysis',
  name: 'Go Analysis',
  executionDomain: 'static',
  surfaceRules: { tier: 2, activateOn: { findings: ['go'] }, category: 'go-analysis' },
  description: 'Go binary symbol and type recovery using Mandiant GoReSym',
  version: '1.0.0',
  configSchema: [
    { envVar: 'GORESYM_PATH', description: 'Path to GoReSym binary', required: false, defaultValue: '/usr/local/bin/GoReSym' },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'GoReSym',
      target: '$GORESYM_PATH',
      envVar: 'GORESYM_PATH',
      dockerDefault: '/usr/local/bin/GoReSym',
      required: false,
      description: 'Mandiant GoReSym — Go binary symbol recovery',
      dockerInstall: 'Download GoReSym release to /usr/local/bin',
      dockerFeature: 'goresym',
      dockerValidation: ['GoReSym -h >/dev/null 2>&1 || true'],
      buildArgs: { GORESYM_VERSION: '3.3' },
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(goSymbolsRecoverToolDefinition, createGoSymbolsRecoverHandler(wm, db))
    server.registerTool(goTypesListToolDefinition, createGoTypesListHandler(wm, db))
    server.registerTool(goBinaryAnalyzeToolDefinition, createGoBinaryAnalyzeHandler(wm, db))

    return ['go.symbols.recover', 'go.types.list', 'go.binary.analyze']
  },
}

export default goAnalysisPlugin
