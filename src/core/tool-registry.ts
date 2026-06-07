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
import type {
  ToolRegistrar,
  PromptRegistrar,
  ResourceRegistrar,
  SamplingClient,
  PluginManagerSetter,
} from './registrar.js'

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
import {
  DecompilerWorker,
  getGhidraDiagnostics,
  normalizeGhidraError,
} from '../worker/decompiler-worker.js'
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

const CORE_GATEWAY_TOOLS = ['workflow.search', 'workflow.run', 'artifact.read']
const POST_PLUGIN_CORE_TOOLS = [
  'plugin.list',
  'plugin.enable',
  'plugin.disable',
  'system.config.validate',
]

export async function registerAllTools(
  server: ToolRegistrar &
    PromptRegistrar &
    ResourceRegistrar &
    SamplingClient &
    PluginManagerSetter,
  deps: ToolDeps
): Promise<void> {
  registerPrompts(server)
  registerSampleTools(server, deps)
  registerArtifactTools(server, deps)
  registerLlmTools(server)
  registerWorkflowTools(server, deps)
  registerTaskTools(server, deps)
  registerSystemTools(server, deps)
  registerUtilityTools(server, {
    database: deps.database,
    runtimeClient: deps.runtimeClient ?? null,
    runtimeMode: deps.config?.runtime?.mode ?? 'disabled',
  })

  const coreToolNames = Array.from(server.getToolDefinitions()).map((d) => d.name)
  getToolSurfaceManager().registerCoreTools(coreToolNames)
  getToolSurfaceManager().registerGatewayCoreTools(CORE_GATEWAY_TOOLS)

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
    services: {
      workspace: {
        manager: deps.workspaceManager,
        database: deps.database,
        storage: deps.storageManager,
        resolvePrimarySamplePath,
        persistStaticAnalysisJsonArtifact,
      },
      platform: {
        cacheManager: deps.cacheManager,
        jobQueue: deps.jobQueue,
        logger: serverLogger,
        policyGuard: deps.policyGuard,
        resolvePackagePath,
        generateCacheKey,
        server,
      },
      runtime: {
        client: deps.runtimeClient ?? null,
        mode: deps.config?.runtime?.mode ?? 'disabled',
        sandboxDir: deps.sandboxDir ?? null,
        config: deps.config?.runtime ?? {},
      },
      ghidra: {
        DecompilerWorker,
        getDiagnostics: getGhidraDiagnostics,
        normalizeError: normalizeGhidraError,
        findBestAnalysis: findBestGhidraAnalysis,
        getReadiness: getGhidraReadiness,
        parseAnalysisMetadata: parseGhidraAnalysisMetadata,
        buildPollingGuidance,
        PollingGuidanceSchema,
        SetupActionSchema,
        RequiredUserInputSchema,
      },
    },
  }
  await loadPlugins(server, pluginDeps)
  server.setPluginManager(getPluginManager())

  registerPluginTools(server)
  registerDiagnosticsTools(server)

  getToolSurfaceManager().registerCoreTools(POST_PLUGIN_CORE_TOOLS)

  registerScriptResources(server)
}
