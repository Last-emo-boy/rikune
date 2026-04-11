/**
 * Graphviz Plugin
 *
 * Graph rendering via Graphviz dot.
 */

import type { Plugin } from '../sdk.js'
import { graphvizRenderToolDefinition, createGraphvizRenderHandler } from './tools/graphviz-render.js'

const graphvizPlugin: Plugin = {
  id: 'graphviz',
  name: 'Graphviz',
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description: 'Graph rendering via Graphviz dot',
  version: '1.0.0',
  configSchema: [
    { envVar: 'GRAPHVIZ_DOT_PATH', description: 'Path to Graphviz dot binary', required: false, defaultValue: '/usr/bin/dot' },
  ],
  systemDeps: [
    { type: 'binary', name: 'dot (Graphviz)', target: '$GRAPHVIZ_DOT_PATH', envVar: 'GRAPHVIZ_DOT_PATH', dockerDefault: '/usr/bin/dot', required: false, description: 'Graphviz graph renderer', dockerInstall: 'apt-get install -y graphviz', dockerFeature: 'graphviz', aptPackages: ['graphviz'], dockerValidation: ['dot -V >/dev/null 2>&1'] },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(graphvizRenderToolDefinition, createGraphvizRenderHandler(wm, db))
    return ['graphviz.render']
  },
}

export default graphvizPlugin
