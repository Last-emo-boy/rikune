/**
 * Docker Backends Plugin
 *
 * Tools that delegate to Docker-hosted analysis engines:
 * Graphviz, Rizin, YARA-X, UPX, RetDec, angr, Qiling, PANDA, Wine.
 */

import type { Plugin } from '../sdk.js'
import {
  angrAnalyzeToolDefinition, createAngrAnalyzeHandler,
  graphvizRenderToolDefinition, createGraphvizRenderHandler,
  pandaInspectToolDefinition, createPandaInspectHandler,
  qilingInspectToolDefinition, createQilingInspectHandler,
  retdecDecompileToolDefinition, createRetDecDecompileHandler,
  rizinAnalyzeToolDefinition, createRizinAnalyzeHandler,
  upxInspectToolDefinition, createUPXInspectHandler,
  wineRunToolDefinition, createWineRunHandler,
  yaraXScanToolDefinition, createYaraXScanHandler,
} from '../../tools/docker-backend-tools.js'

const dockerBackendsPlugin: Plugin = {
  id: 'docker-backends',
  name: 'Docker Backends',
  description: 'Analysis tools backed by Docker containers (Rizin, RetDec, angr, Qiling, UPX, Graphviz, PANDA, Wine, YARA-X)',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(graphvizRenderToolDefinition, createGraphvizRenderHandler(wm, db))
    server.registerTool(rizinAnalyzeToolDefinition, createRizinAnalyzeHandler(wm, db))
    server.registerTool(yaraXScanToolDefinition, createYaraXScanHandler(wm, db))
    server.registerTool(upxInspectToolDefinition, createUPXInspectHandler(wm, db))
    server.registerTool(retdecDecompileToolDefinition, createRetDecDecompileHandler(wm, db))
    server.registerTool(angrAnalyzeToolDefinition, createAngrAnalyzeHandler(wm, db))
    server.registerTool(qilingInspectToolDefinition, createQilingInspectHandler(wm, db))
    server.registerTool(pandaInspectToolDefinition, createPandaInspectHandler(wm, db))
    server.registerTool(wineRunToolDefinition, createWineRunHandler(wm, db))

    return [
      'graphviz.render', 'rizin.analyze', 'yaraX.scan',
      'upx.inspect', 'retdec.decompile', 'angr.analyze',
      'qiling.inspect', 'panda.inspect', 'wine.run',
    ]
  },
}

export default dockerBackendsPlugin
