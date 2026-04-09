/**
 * Docker Backends Plugin
 *
 * Tools that delegate to Docker-hosted analysis engines:
 * Graphviz, Rizin, YARA-X, UPX, RetDec, angr, Qiling, PANDA, Wine.
 */

import type { Plugin } from '../sdk.js'
import { angrAnalyzeToolDefinition, createAngrAnalyzeHandler } from './tools/angr-analyze.js'
import { graphvizRenderToolDefinition, createGraphvizRenderHandler } from './tools/graphviz-render.js'
import { pandaInspectToolDefinition, createPandaInspectHandler } from './tools/panda-inspect.js'
import { qilingInspectToolDefinition, createQilingInspectHandler } from './tools/qiling-inspect.js'
import { retdecDecompileToolDefinition, createRetDecDecompileHandler } from './tools/retdec-decompile.js'
import { rizinAnalyzeToolDefinition, createRizinAnalyzeHandler } from './tools/rizin-analyze.js'
import { upxInspectToolDefinition, createUPXInspectHandler } from './tools/upx-inspect.js'
import { wineRunToolDefinition, createWineRunHandler } from './tools/wine-run.js'
import { yaraXScanToolDefinition, createYaraXScanHandler } from './tools/yara-x-scan.js'

const dockerBackendsPlugin: Plugin = {
  id: 'docker-backends',
  name: 'Docker Backends',
  description: 'Analysis tools backed by Docker containers (Rizin, RetDec, angr, Qiling, UPX, Graphviz, PANDA, Wine, YARA-X)',
  version: '1.0.0',
  configSchema: [
    { envVar: 'GRAPHVIZ_DOT_PATH', description: 'Path to Graphviz dot binary', required: false, defaultValue: '/usr/bin/dot' },
    { envVar: 'RIZIN_PATH', description: 'Path to Rizin binary', required: false, defaultValue: '/opt/rizin/bin/rizin' },
    { envVar: 'UPX_PATH', description: 'Path to UPX binary', required: false, defaultValue: '/usr/local/bin/upx' },
    { envVar: 'RETDEC_PATH', description: 'Path to RetDec decompiler', required: false, defaultValue: '/opt/retdec/bin/retdec-decompiler' },
    { envVar: 'ANGR_PYTHON', description: 'Python binary with angr installed', required: false, defaultValue: '/opt/angr-venv/bin/python' },
    { envVar: 'QILING_PYTHON', description: 'Python binary with Qiling installed', required: false, defaultValue: '/opt/qiling-venv/bin/python' },
    { envVar: 'WINE_PATH', description: 'Path to Wine binary', required: false, defaultValue: '/usr/bin/wine' },
    { envVar: 'PANDA_PYTHON', description: 'Python binary with PANDA installed', required: false, defaultValue: '/usr/local/bin/python3' },
    { envVar: 'YARAX_PYTHON', description: 'Python binary with YARA-X installed', required: false, defaultValue: '/usr/local/bin/python3' },
  ],
  systemDeps: [
    { type: 'binary', name: 'dot (Graphviz)', target: '$GRAPHVIZ_DOT_PATH', envVar: 'GRAPHVIZ_DOT_PATH', dockerDefault: '/usr/bin/dot', required: false, description: 'Graphviz graph renderer', dockerInstall: 'apt-get install -y graphviz', dockerFeature: 'graphviz', aptPackages: ['graphviz'], dockerValidation: ['dot -V >/dev/null 2>&1'] },
    { type: 'binary', name: 'rizin', target: '$RIZIN_PATH', envVar: 'RIZIN_PATH', dockerDefault: '/opt/rizin/bin/rizin', required: false, description: 'Rizin reverse engineering framework', dockerInstall: 'Download Rizin release to /opt/rizin', dockerFeature: 'rizin', dockerValidation: ['rizin -v >/dev/null 2>&1'] },
    { type: 'binary', name: 'upx', target: '$UPX_PATH', envVar: 'UPX_PATH', dockerDefault: '/usr/local/bin/upx', required: false, description: 'UPX packer/unpacker', dockerInstall: 'Download UPX release to /usr/local/bin', dockerFeature: 'upx', dockerValidation: ['upx --version >/dev/null 2>&1'] },
    { type: 'file', name: 'retdec', target: '$RETDEC_PATH', envVar: 'RETDEC_PATH', dockerDefault: '/opt/retdec/bin/retdec-decompiler', required: false, description: 'RetDec decompiler', dockerInstall: 'Download RetDec release to /opt/retdec', dockerFeature: 'retdec', dockerValidation: ['retdec-decompiler --help >/dev/null 2>&1', 'retdec-fileinfo --help >/dev/null 2>&1'] },
    { type: 'python-venv', name: 'angr', target: '$ANGR_PYTHON', envVar: 'ANGR_PYTHON', dockerDefault: '/opt/angr-venv/bin/python', required: false, description: 'angr symbolic execution (venv)', dockerInstall: 'python3 -m venv /opt/angr-venv && pip install angr', dockerFeature: 'angr', dockerValidation: ['/opt/angr-venv/bin/python -c "import angr; print(\'✓ angr\')"'] },
    { type: 'python-venv', name: 'qiling', target: '$QILING_PYTHON', envVar: 'QILING_PYTHON', dockerDefault: '/opt/qiling-venv/bin/python', required: false, description: 'Qiling emulation framework (venv)', dockerInstall: 'python3 -m venv /opt/qiling-venv && pip install qiling', dockerFeature: 'qiling', dockerValidation: ['/opt/qiling-venv/bin/python -c "import qiling; print(\'✓ qiling\')"'] },
    { type: 'binary', name: 'wine', target: '$WINE_PATH', envVar: 'WINE_PATH', dockerDefault: '/usr/bin/wine', required: false, description: 'Wine Windows compatibility layer', dockerInstall: 'apt-get install -y wine wine64', dockerFeature: 'wine', aptPackages: ['wine', 'wine64'], dockerValidation: ['wine --version >/dev/null 2>&1', 'command -v winedbg >/dev/null 2>&1'] },
    { type: 'python', name: 'pandare', importName: 'pandare', required: false, description: 'PANDA record/replay analysis', dockerInstall: 'pip install pandare', dockerFeature: 'dynamic-python' },
    { type: 'python', name: 'yara-x', importName: 'yara_x', required: false, description: 'YARA-X next-gen pattern matching', dockerInstall: 'pip install yara-x', dockerFeature: 'dynamic-python' },
  ],
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
