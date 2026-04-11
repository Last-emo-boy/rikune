/**
 * RetDec Plugin
 *
 * RetDec decompiler for binary-to-C decompilation.
 */

import type { Plugin } from '../sdk.js'
import { retdecDecompileToolDefinition, createRetDecDecompileHandler } from './tools/retdec-decompile.js'

const retdecPlugin: Plugin = {
  id: 'retdec',
  name: 'RetDec',
  surfaceRules: { tier: 3, category: 'reverse-engineering' },
  description: 'RetDec decompiler for binary-to-C decompilation',
  version: '1.0.0',
  configSchema: [
    { envVar: 'RETDEC_PATH', description: 'Path to RetDec decompiler', required: false, defaultValue: '/opt/retdec/bin/retdec-decompiler' },
  ],
  systemDeps: [
    { type: 'file', name: 'retdec', target: '$RETDEC_PATH', envVar: 'RETDEC_PATH', dockerDefault: '/opt/retdec/bin/retdec-decompiler', required: false, description: 'RetDec decompiler', dockerInstall: 'Download RetDec release to /opt/retdec', dockerFeature: 'retdec', dockerValidation: ['retdec-decompiler --help >/dev/null 2>&1', 'retdec-fileinfo --help >/dev/null 2>&1'], extraEnv: { RETDEC_INSTALL_DIR: '/opt/retdec' }, buildArgs: { RETDEC_VERSION: '5.0' } },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(retdecDecompileToolDefinition, createRetDecDecompileHandler(wm, db))
    return ['retdec.decompile']
  },
}

export default retdecPlugin
