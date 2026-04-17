/**
 * Centralised tool / prompt / resource registry orchestrator.
 *
 * Delegates to domain-specific registration modules under src/core/tool-registry/.
 */

import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { PolicyGuard } from '../policy-guard.js'
import type { CacheManager } from '../cache-manager.js'
import type { JobQueue } from '../job-queue.js'
import type { StorageManager } from '../storage/storage-manager.js'
import type { Config } from '../config.js'
import type { ToolRegistrar, PromptRegistrar, ResourceRegistrar, SamplingClient, PluginManagerSetter } from './registrar.js'

export interface ToolDeps {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  policyGuard: PolicyGuard
  cacheManager: CacheManager
  jobQueue: JobQueue
  storageManager: StorageManager
  config: Config
  server: ToolRegistrar & PromptRegistrar & ResourceRegistrar & SamplingClient & PluginManagerSetter
  runtimeClient?: any
  sandboxDir?: string | null
  resolvePrimarySamplePath?: any
}

import { resolvePrimarySamplePath } from '../sample/sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../artifacts/static-analysis-artifacts.js'
import { resolvePackagePath } from '../runtime-paths.js'
import { generateCacheKey } from '../cache-manager.js'
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError } from '../worker/decompiler-worker.js'
import {
  findBestGhidraAnalysis,
  getGhidraReadiness,
  parseGhidraAnalysisMetadata,
} from '../ghidra/ghidra-analysis-status.js'
import { PollingGuidanceSchema, buildPollingGuidance } from './polling-guidance.js'
import { SetupActionSchema, RequiredUserInputSchema } from '../setup-guidance.js'
import { logger as serverLogger } from '../logger.js'
import { loadPlugins, getPluginManager } from './plugins.js'
import { getToolSurfaceManager } from './tool-surface-manager.js'
import { createAsyncToolWrapper, LONG_RUNNING_TOOLS } from '../async-tool-wrapper.js'

import { registerPrompts } from './tool-registry/prompts.js'
import { registerSampleTools } from './tool-registry/sample-tools.js'
import { registerArtifactTools } from './tool-registry/artifact-tools.js'
import { registerLlmTools } from './tool-registry/llm-tools.js'
import { registerWorkflowTools } from './tool-registry/workflow-tools.js'
import { registerTaskTools } from './tool-registry/task-tools.js'
import { registerSystemTools } from './tool-registry/system-tools.js'
import { registerUtilityTools } from './tool-registry/utility-tools.js'
import { registerPluginTools } from './tool-registry/plugin-tools.js'
import { registerDiagnosticsTools } from './tool-registry/diagnostics-tools.js'
import { registerScriptResources } from './tool-registry/script-resources.js'

export async function registerAllTools(
  server: ToolRegistrar & PromptRegistrar & ResourceRegistrar & SamplingClient & PluginManagerSetter,
  deps: ToolDeps
): Promise<void> {
  registerPrompts(server)
  registerSampleTools(server, deps)
  registerArtifactTools(server, deps)
  registerLlmTools(server)
  registerWorkflowTools(server, deps)
  registerTaskTools(server, deps)
  registerSystemTools(server, deps)
  registerUtilityTools(server)

  const coreToolNames = Array.from(server.getToolDefinitions()).map(d => d.name)
  getToolSurfaceManager().registerCoreTools(coreToolNames)

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
    runtimeClient: deps.runtimeClient ?? null,
    sandboxDir: deps.sandboxDir ?? null,
  }
  await loadPlugins(server, pluginDeps)
  server.setPluginManager(getPluginManager())

  registerPluginTools(server)
  registerDiagnosticsTools(server)

  getToolSurfaceManager().registerCoreTools([
    'plugin_list',
    'plugin_enable',
    'plugin_disable',
    'config_validate',
  ])

  registerScriptResources(server)
}
