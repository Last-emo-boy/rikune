/**
 * Docker Backends Plugin
 *
 * Tools that delegate to Docker-hosted analysis engines:
 * Graphviz, Rizin, YARA-X, UPX, RetDec, angr, Qiling, PANDA, Wine.
 */

import type { Plugin } from '../sdk.js'
import { angrAnalyzeToolDefinition, createAngrAnalyzeHandler } from '../../tools/docker/angr-analyze.js'
import { graphvizRenderToolDefinition, createGraphvizRenderHandler } from '../../tools/docker/graphviz-render.js'
import { pandaInspectToolDefinition, createPandaInspectHandler } from '../../tools/docker/panda-inspect.js'
import { qilingInspectToolDefinition, createQilingInspectHandler } from '../../tools/docker/qiling-inspect.js'
import { retdecDecompileToolDefinition, createRetDecDecompileHandler } from '../../tools/docker/retdec-decompile.js'
import { rizinAnalyzeToolDefinition, createRizinAnalyzeHandler } from '../../tools/docker/rizin-analyze.js'
import { upxInspectToolDefinition, createUPXInspectHandler } from '../../tools/docker/upx-inspect.js'
import { wineRunToolDefinition, createWineRunHandler } from '../../tools/docker/wine-run.js'
import { yaraXScanToolDefinition, createYaraXScanHandler } from '../../tools/docker/yara-x-scan.js'

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
