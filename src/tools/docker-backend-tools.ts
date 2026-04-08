/**
 * Docker Backend Tools 鈥?barrel re-export.
 *
 * All tool implementations have been split into individual files under
 * `src/tools/docker/`. This file re-exports everything for backward
 * compatibility so existing imports continue to work.
 */

// Shared types and helpers
export type { CommandResult, PythonJsonResult, SharedBackendDependencies } from './docker/docker-shared.js'
export {
  ArtifactRefSchema, BackendSchema, SharedMetricsSchema,
  normalizeError, stripAnsi, truncateText, safeJsonParse,
  ensureSampleExists, findBackendPreviewEvidence, persistBackendPreviewEvidence,
  persistBackendArtifact, executeCommand, runPythonJson,
  buildStaticSetupRequired, buildDynamicSetupRequired,
  resolveSampleFile, buildMetrics,
} from './docker/docker-shared.js'

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