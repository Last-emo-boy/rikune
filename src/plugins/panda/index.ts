/**
 * PANDA Plugin
 *
 * PANDA record/replay analysis for dynamic binary inspection.
 */

import type { Plugin } from '../sdk.js'
import { pandaInspectToolDefinition, createPandaInspectHandler } from './tools/panda-inspect.js'

const pandaPlugin: Plugin = {
  id: 'panda',
  name: 'PANDA',
  description: 'PANDA record/replay analysis for dynamic binary inspection',
  version: '1.0.0',
  configSchema: [
    { envVar: 'PANDA_PYTHON', description: 'Python binary with PANDA installed', required: false, defaultValue: '/usr/local/bin/python3' },
  ],
  systemDeps: [
    { type: 'python', name: 'pandare', importName: 'pandare', required: false, description: 'PANDA record/replay analysis', dockerInstall: 'pip install pandare', dockerFeature: 'dynamic-python', extraEnv: { PANDA_PYTHON: '/usr/local/bin/python3' } },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(pandaInspectToolDefinition, createPandaInspectHandler(wm, db))
    return ['panda.inspect']
  },
}

export default pandaPlugin
