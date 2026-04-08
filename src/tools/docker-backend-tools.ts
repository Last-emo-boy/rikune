/**
 * Docker Backend Tools — barrel re-export.
 *
 * All tool implementations have been split into individual files under
 * `src/tools/docker/`. This file re-exports tool definitions and handler
 * factories for backward compatibility so existing imports continue to work.
 */

// Tool re-exports
export {
  graphvizRenderInputSchema, graphvizRenderOutputSchema,
  graphvizRenderToolDefinition, createGraphvizRenderHandler,
} from './docker/graphviz-render.js'

export {
  rizinAnalyzeInputSchema, rizinAnalyzeOutputSchema,
  rizinAnalyzeToolDefinition, createRizinAnalyzeHandler,
} from './docker/rizin-analyze.js'

export {
  yaraXScanInputSchema, yaraXScanOutputSchema,
  yaraXScanToolDefinition, createYaraXScanHandler,
} from './docker/yara-x-scan.js'

export {
  upxInspectInputSchema, upxInspectOutputSchema,
  upxInspectToolDefinition, createUPXInspectHandler,
} from './docker/upx-inspect.js'

export {
  retdecDecompileInputSchema, retdecDecompileOutputSchema,
  retdecDecompileToolDefinition, createRetDecDecompileHandler,
} from './docker/retdec-decompile.js'

export {
  angrAnalyzeInputSchema, angrAnalyzeOutputSchema,
  angrAnalyzeToolDefinition, createAngrAnalyzeHandler,
} from './docker/angr-analyze.js'

export {
  qilingInspectInputSchema, qilingInspectOutputSchema,
  qilingInspectToolDefinition, createQilingInspectHandler,
} from './docker/qiling-inspect.js'

export {
  pandaInspectInputSchema, pandaInspectOutputSchema,
  pandaInspectToolDefinition, createPandaInspectHandler,
} from './docker/panda-inspect.js'

export {
  wineRunInputSchema, wineRunOutputSchema,
  wineRunToolDefinition, createWineRunHandler,
} from './docker/wine-run.js'