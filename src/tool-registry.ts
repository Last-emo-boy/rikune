/**
 * Centralised tool / prompt / resource registry.
 *
 * Core tools (sample management, workflows, system health, plugin introspection)
 * are registered here. All other tools are auto-discovered via the plugin system
 * in src/plugins/<id>/index.ts.
 *
 * `index.ts` calls `registerAllTools(server, deps)` once during bootstrap,
 * keeping the entry-point lean and all registration logic in one place.
 */

import fs from 'fs/promises'
import path from 'path'
import { fileURLToPath } from 'url'
import type { MCPServer } from './server.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'
import type { PolicyGuard } from './policy-guard.js'
import type { CacheManager } from './cache-manager.js'
import type { JobQueue } from './job-queue.js'
import type { StorageManager } from './storage/storage-manager.js'
import type { Config } from './config.js'

// ─── Dependency bag passed to every handler factory ────────────────────────
export interface ToolDeps {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  policyGuard: PolicyGuard
  cacheManager: CacheManager
  jobQueue: JobQueue
  storageManager: StorageManager
  config: Config
  server: MCPServer
}

// ─── Prompts ───────────────────────────────────────────────────────────────
import {
  semanticNameReviewPromptDefinition,
  createSemanticNameReviewPromptHandler,
} from './prompts/semantic-name-review.js'
import {
  functionExplanationReviewPromptDefinition,
  createFunctionExplanationReviewPromptHandler,
} from './prompts/function-explanation-review.js'
import {
  moduleReconstructionReviewPromptDefinition,
  createModuleReconstructionReviewPromptHandler,
} from './prompts/module-reconstruction-review.js'

// ─── Core tools ────────────────────────────────────────────────────────────
import { sampleIngestToolDefinition, createSampleIngestHandler } from './tools/sample-ingest.js'
import { sampleRequestUploadToolDefinition, createSampleRequestUploadHandler } from './tools/sample-request-upload.js'
import { sampleProfileGetToolDefinition, createSampleProfileGetHandler } from './tools/sample-profile-get.js'
import { artifactReadToolDefinition, createArtifactReadHandler } from './tools/artifact-read.js'
import { artifactsListToolDefinition, createArtifactsListHandler } from './tools/artifacts-list.js'
import { artifactsDiffToolDefinition, createArtifactsDiffHandler } from './tools/artifacts-diff.js'
import { artifactDownloadToolDefinition, createArtifactDownloadHandler } from './tools/artifact-download.js'

// ─── LLM ───────────────────────────────────────────────────────────────────
import { llmAnalyzeToolDefinition, createLlmAnalyzeHandler } from './llm/llm-analyze.js'

// ─── Workflows ─────────────────────────────────────────────────────────────
import { triageWorkflowToolDefinition, createTriageWorkflowHandler } from './workflows/triage.js'
import { analyzeAutoWorkflowToolDefinition, createAnalyzeAutoWorkflowHandler } from './workflows/analyze-auto.js'
import {
  analyzeWorkflowPromoteToolDefinition,
  analyzeWorkflowStartToolDefinition,
  analyzeWorkflowStatusToolDefinition,
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
  createAnalyzeWorkflowStatusHandler,
} from './workflows/analyze-pipeline.js'
import { reconstructWorkflowToolDefinition, createReconstructWorkflowHandler } from './workflows/reconstruct.js'
import { deepStaticWorkflowToolDefinition, createDeepStaticWorkflowHandler } from './workflows/deep-static.js'
import { functionIndexRecoverWorkflowToolDefinition, createFunctionIndexRecoverWorkflowHandler } from './workflows/function-index-recover.js'
import { semanticNameReviewWorkflowToolDefinition, createSemanticNameReviewWorkflowHandler } from './workflows/semantic-name-review.js'
import { functionExplanationReviewWorkflowToolDefinition, createFunctionExplanationReviewWorkflowHandler } from './workflows/function-explanation-review.js'
import { moduleReconstructionReviewWorkflowToolDefinition, createModuleReconstructionReviewWorkflowHandler } from './workflows/module-reconstruction-review.js'

// ─── Task management & system health ───────────────────────────────────────
import { systemHealthToolDefinition, createSystemHealthHandler } from './tools/system-health.js'
import { systemSetupGuideToolDefinition, createSystemSetupGuideHandler } from './tools/system-setup-guide.js'
import { setupRemediateToolDefinition, createSetupRemediateHandler } from './tools/setup-remediate.js'
import { taskStatusToolDefinition, createTaskStatusHandler } from './tools/task-status.js'
import { taskCancelToolDefinition, createTaskCancelHandler } from './tools/task-cancel.js'
import { taskSweepToolDefinition, createTaskSweepHandler } from './tools/task-sweep.js'

// ─── Utilities ─────────────────────────────────────────────────────────────
import { toolHelpToolDefinition, createToolHelpHandler } from './tools/tool-help.js'

// ─── Plugins ───────────────────────────────────────────────────────────────
// All non-core tools are auto-discovered from src/plugins/<id>/index.ts.
// Enabled/disabled via PLUGINS env var (default: all enabled).
import { loadPlugins, getPluginManager } from './plugins.js'

// ── Plugin utility imports (injected into plugin deps) ────────────────────
import { resolvePrimarySamplePath } from './sample/sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from './artifacts/static-analysis-artifacts.js'
import { resolvePackagePath } from './runtime-paths.js'
import { generateCacheKey } from './cache-manager.js'
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError } from './worker/decompiler-worker.js'
import {
  findBestGhidraAnalysis,
  getGhidraReadiness,
  parseGhidraAnalysisMetadata,
} from './ghidra/ghidra-analysis-status.js'
import { PollingGuidanceSchema, buildPollingGuidance } from './polling-guidance.js'
import { SetupActionSchema, RequiredUserInputSchema } from './setup-guidance.js'
import { logger as serverLogger } from './logger.js'

// ─── Plugin introspection tools ───────────────────────────────────────────
import {
  pluginListToolDefinition, createPluginListHandler,
  pluginEnableToolDefinition, createPluginEnableHandler,
  pluginDisableToolDefinition, createPluginDisableHandler,
} from './tools/plugin-list.js'

// ─── System diagnostics tools ─────────────────────────────────────────────
import {
  configValidateToolDefinition, createConfigValidateHandler,
} from './tools/config-validate.js'

// ─── Async wrapper ─────────────────────────────────────────────────────────
import { createAsyncToolWrapper, LONG_RUNNING_TOOLS } from './async-tool-wrapper.js'

// ============================================================================
// Registration
// ============================================================================

export async function registerAllTools(server: MCPServer, deps: ToolDeps): Promise<void> {
  const {
    workspaceManager, database, policyGuard,
    cacheManager, jobQueue, storageManager, config,
  } = deps

  // ── Prompts ────────────────────────────────────────────────────────────
  server.registerPrompt(semanticNameReviewPromptDefinition, createSemanticNameReviewPromptHandler())
  server.registerPrompt(functionExplanationReviewPromptDefinition, createFunctionExplanationReviewPromptHandler())
  server.registerPrompt(moduleReconstructionReviewPromptDefinition, createModuleReconstructionReviewPromptHandler())

  // ── Core ───────────────────────────────────────────────────────────────
  server.registerTool(sampleIngestToolDefinition, createSampleIngestHandler(workspaceManager, database, policyGuard))
  server.registerTool(sampleRequestUploadToolDefinition, createSampleRequestUploadHandler(database, { apiPort: config.api.port }))
  server.registerTool(sampleProfileGetToolDefinition, createSampleProfileGetHandler(database, workspaceManager))
  server.registerTool(artifactReadToolDefinition, createArtifactReadHandler(workspaceManager, database))
  server.registerTool(artifactsListToolDefinition, createArtifactsListHandler(workspaceManager, database))
  server.registerTool(artifactsDiffToolDefinition, createArtifactsDiffHandler(workspaceManager, database))
  server.registerTool(artifactDownloadToolDefinition, createArtifactDownloadHandler(database, { storageManager, workspaceManager }))

  // ── LLM ────────────────────────────────────────────────────────────────
  server.registerTool(llmAnalyzeToolDefinition, createLlmAnalyzeHandler(server))

  // ── Workflows ──────────────────────────────────────────────────────────
  server.registerTool(triageWorkflowToolDefinition, createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
    analyzeStart: createAnalyzeWorkflowStartHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue),
  }))
  server.registerTool(analyzeWorkflowStartToolDefinition, createAnalyzeWorkflowStartHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(analyzeWorkflowStatusToolDefinition, createAnalyzeWorkflowStatusHandler(database, {}, jobQueue))
  server.registerTool(analyzeWorkflowPromoteToolDefinition, createAnalyzeWorkflowPromoteHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(analyzeAutoWorkflowToolDefinition, createAnalyzeAutoWorkflowHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(reconstructWorkflowToolDefinition, createReconstructWorkflowHandler(workspaceManager, database, cacheManager, undefined, jobQueue))
  server.registerTool(deepStaticWorkflowToolDefinition, createDeepStaticWorkflowHandler(workspaceManager, database, cacheManager, jobQueue))
  server.registerTool(functionIndexRecoverWorkflowToolDefinition, createFunctionIndexRecoverWorkflowHandler(workspaceManager, database, cacheManager))
  server.registerTool(semanticNameReviewWorkflowToolDefinition, createSemanticNameReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))
  server.registerTool(functionExplanationReviewWorkflowToolDefinition, createFunctionExplanationReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))
  server.registerTool(moduleReconstructionReviewWorkflowToolDefinition, createModuleReconstructionReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))

  // ── Task management ─────────────────────────────────────────────────────
  server.registerTool(taskStatusToolDefinition, createTaskStatusHandler(jobQueue, database))
  server.registerTool(taskCancelToolDefinition, createTaskCancelHandler(jobQueue))
  server.registerTool(taskSweepToolDefinition, createTaskSweepHandler(jobQueue, database))

  // ── System health & setup ──────────────────────────────────────────────
  const systemHealthHandler = createSystemHealthHandler(workspaceManager, database, { cacheManager })
  const systemSetupGuideHandler = createSystemSetupGuideHandler()
  server.registerTool(systemHealthToolDefinition, systemHealthHandler)
  server.registerTool(systemSetupGuideToolDefinition, systemSetupGuideHandler)
  server.registerTool(setupRemediateToolDefinition, createSetupRemediateHandler(workspaceManager, database, cacheManager, {
    healthHandler: systemHealthHandler,
    setupGuideHandler: systemSetupGuideHandler,
  }))

  // ── Utilities ──────────────────────────────────────────────────────────
  server.registerTool(toolHelpToolDefinition, createToolHelpHandler(() => server.getToolDefinitions()))

  // ── Plugins ────────────────────────────────────────────────────────────
  const pluginDeps = {
    ...deps,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
    resolvePackagePath,
    generateCacheKey,
    DecompilerWorker,
    getGhidraDiagnostics,
    normalizeGhidraError,
    findBestGhidraAnalysis,
    getGhidraReadiness,
    parseGhidraAnalysisMetadata,
    buildPollingGuidance,
    PollingGuidanceSchema,
    SetupActionSchema,
    RequiredUserInputSchema,
    logger: serverLogger,
  }
  await loadPlugins(server, pluginDeps as any)

  // Wire PluginManager into server for lifecycle hooks
  server.setPluginManager(getPluginManager())

  // ── Plugin introspection tools ─────────────────────────────────────────
  server.registerTool(pluginListToolDefinition, createPluginListHandler(server))
  server.registerTool(pluginEnableToolDefinition, createPluginEnableHandler(server))
  server.registerTool(pluginDisableToolDefinition, createPluginDisableHandler(server))

  // ── System diagnostics tools ───────────────────────────────────────────
  server.registerTool(configValidateToolDefinition, createConfigValidateHandler(server))

  // ══════════════════════════════════════════════════════════════════════════
  // MCP Resources — read-only content exposed to clients
  // ══════════════════════════════════════════════════════════════════════════
  registerScriptResources(server)
}

// ============================================================================
// Script Resources — expose Frida / Ghidra scripts as readable MCP resources
// ============================================================================

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = path.resolve(__dirname, '..')

interface ScriptEntry {
  uri: string
  name: string
  description: string
  mimeType: string
  filePath: string
}

const FRIDA_SCRIPTS: ScriptEntry[] = [
  { uri: 'script://frida/anti_debug_bypass', name: 'Frida: Anti-Debug Bypass', description: 'Bypass common anti-debugging techniques', mimeType: 'application/javascript', filePath: 'frida_scripts/anti_debug_bypass.js' },
  { uri: 'script://frida/api_trace', name: 'Frida: API Trace', description: 'Trace Windows API calls at runtime', mimeType: 'application/javascript', filePath: 'frida_scripts/api_trace.js' },
  { uri: 'script://frida/crypto_finder', name: 'Frida: Crypto Finder', description: 'Detect cryptographic operations at runtime', mimeType: 'application/javascript', filePath: 'frida_scripts/crypto_finder.js' },
  { uri: 'script://frida/file_registry_monitor', name: 'Frida: File/Registry Monitor', description: 'Monitor file and registry access', mimeType: 'application/javascript', filePath: 'frida_scripts/file_registry_monitor.js' },
  { uri: 'script://frida/string_decoder', name: 'Frida: String Decoder', description: 'Decode obfuscated strings at runtime', mimeType: 'application/javascript', filePath: 'frida_scripts/string_decoder.js' },
  { uri: 'script://frida/android_crypto_trace', name: 'Frida: Android Crypto Trace', description: 'Trace Android crypto API calls', mimeType: 'application/javascript', filePath: 'src/plugins/android/scripts/android_crypto_trace.js' },
  { uri: 'script://frida/android_root_bypass', name: 'Frida: Android Root Bypass', description: 'Bypass Android root detection', mimeType: 'application/javascript', filePath: 'src/plugins/android/scripts/android_root_bypass.js' },
  { uri: 'script://frida/android_ssl_bypass', name: 'Frida: Android SSL Bypass', description: 'Bypass Android SSL pinning', mimeType: 'application/javascript', filePath: 'src/plugins/android/scripts/android_ssl_bypass.js' },
]

const GHIDRA_SCRIPTS: ScriptEntry[] = [
  { uri: 'script://ghidra/AnalyzeCrossReferences', name: 'Ghidra: Analyze Cross References', description: 'Extract cross-reference data from Ghidra project', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/AnalyzeCrossReferences.java' },
  { uri: 'script://ghidra/DecompileFunction', name: 'Ghidra: Decompile Function (Java)', description: 'Decompile specific function via Ghidra headless', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/DecompileFunction.java' },
  { uri: 'script://ghidra/ExtractCFG', name: 'Ghidra: Extract CFG (Java)', description: 'Extract control flow graph from Ghidra', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/ExtractCFG.java' },
  { uri: 'script://ghidra/ExtractFunctions', name: 'Ghidra: Extract Functions (Java)', description: 'List all functions from Ghidra project', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/ExtractFunctions.java' },
  { uri: 'script://ghidra/SearchFunctionReferences', name: 'Ghidra: Search Function References', description: 'Search for function references in Ghidra', mimeType: 'text/x-java-source', filePath: 'ghidra_scripts/SearchFunctionReferences.java' },
  { uri: 'script://ghidra/DecompileFunction_py', name: 'Ghidra: Decompile Function (Python)', description: 'Decompile function via Ghidra Python', mimeType: 'text/x-python', filePath: 'ghidra_scripts/DecompileFunction.py' },
  { uri: 'script://ghidra/ExtractCFG_py', name: 'Ghidra: Extract CFG (Python)', description: 'Extract CFG via Ghidra Python', mimeType: 'text/x-python', filePath: 'ghidra_scripts/ExtractCFG.py' },
  { uri: 'script://ghidra/ExtractFunctions_py', name: 'Ghidra: Extract Functions (Python)', description: 'List functions via Ghidra Python', mimeType: 'text/x-python', filePath: 'ghidra_scripts/ExtractFunctions.py' },
]

function registerScriptResources(server: MCPServer): void {
  for (const entry of [...FRIDA_SCRIPTS, ...GHIDRA_SCRIPTS]) {
    const absPath = path.join(PROJECT_ROOT, entry.filePath)
    server.registerResource(
      { uri: entry.uri, name: entry.name, description: entry.description, mimeType: entry.mimeType },
      async () => {
        const text = await fs.readFile(absPath, 'utf8')
        return { uri: entry.uri, mimeType: entry.mimeType, text }
      },
    )
  }
}
