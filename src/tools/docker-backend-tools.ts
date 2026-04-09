/**
 * Docker Backend Tools — barrel re-export.
 *
 * All tool implementations have been moved to the docker-backends plugin at
 * `src/plugins/docker-backends/tools/`. This file re-exports tool definitions
 * and handler factories for backward compatibility so existing imports
 * continue to work.
 */

// Tool re-exports
export {
  graphvizRenderInputSchema, graphvizRenderOutputSchema,
  graphvizRenderToolDefinition, createGraphvizRenderHandler,
} from '../plugins/docker-backends/tools/graphviz-render.js'

export {
  rizinAnalyzeInputSchema, rizinAnalyzeOutputSchema,
  rizinAnalyzeToolDefinition, createRizinAnalyzeHandler,
} from '../plugins/docker-backends/tools/rizin-analyze.js'

export {
  yaraXScanInputSchema, yaraXScanOutputSchema,
  yaraXScanToolDefinition, createYaraXScanHandler,
} from '../plugins/docker-backends/tools/yara-x-scan.js'

export {
  upxInspectInputSchema, upxInspectOutputSchema,
  upxInspectToolDefinition, createUPXInspectHandler,
} from '../plugins/docker-backends/tools/upx-inspect.js'

export {
  retdecDecompileInputSchema, retdecDecompileOutputSchema,
  retdecDecompileToolDefinition, createRetDecDecompileHandler,
} from '../plugins/docker-backends/tools/retdec-decompile.js'

export {
  angrAnalyzeInputSchema, angrAnalyzeOutputSchema,
  angrAnalyzeToolDefinition, createAngrAnalyzeHandler,
} from '../plugins/docker-backends/tools/angr-analyze.js'

export {
  qilingInspectInputSchema, qilingInspectOutputSchema,
  qilingInspectToolDefinition, createQilingInspectHandler,
} from '../plugins/docker-backends/tools/qiling-inspect.js'

export {
  pandaInspectInputSchema, pandaInspectOutputSchema,
  pandaInspectToolDefinition, createPandaInspectHandler,
} from '../plugins/docker-backends/tools/panda-inspect.js'

export {
  wineRunInputSchema, wineRunOutputSchema,
  wineRunToolDefinition, createWineRunHandler,
} from '../plugins/docker-backends/tools/wine-run.js'