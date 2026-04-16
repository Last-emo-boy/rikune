/**
 * Binary Analysis MCP Server
 * Universal reverse-engineering tool surface for PE, ELF, Mach-O, APK/DEX,
 * .NET, and more — exposed as reusable MCP tools for any tool-calling LLM.
 * Entry point
 */

import { MCPServer } from './server.js'
import { loadConfig } from './config.js'
import { WorkspaceManager } from './workspace-manager.js'
import { DatabaseManager } from './database.js'
import { PolicyGuard } from './policy-guard.js'
import { CacheManager } from './cache-manager.js'
import { JobQueue } from './job-queue.js'
import { AnalysisTaskRunner } from './analysis/analysis-task-runner.js'
import { StorageManager } from './storage/storage-manager.js'
import { registerAllTools } from './tool-registry.js'
import { logger } from './logger.js'
import { defaultApiBootstrapper } from './api/default-bootstrapper.js'
import {
  isWindowsSandboxAvailable,
  createSandboxLauncher,
  createRuntimeClient,
  createRuntimeRecovery,
  type RuntimeConnection,
} from './runtime-client/index.js'

// Export public API
export { MCPServer } from './server.js'
export { loadConfig } from './config.js'
export { WorkspaceManager } from './workspace-manager.js'
export * from './types.js'
export { RikuneError, ErrorCode, toRikuneError, isRikuneError } from './errors.js'

async function main() {
  try {
    // Load configuration
    const configPath = process.env.CONFIG_PATH
    const config = loadConfig(configPath)

    // Initialize components
    const workspaceManager = new WorkspaceManager(config.workspace.root)
    const database = new DatabaseManager(config.database.path)
    const policyGuard = new PolicyGuard(config.logging.auditPath)
    const cacheManager = new CacheManager(config.cache.root, database)
    const storageManager = new StorageManager({
      root: config.api.storageRoot,
      maxFileSize: config.api.maxFileSize,
      retentionDays: config.api.retentionDays,
      maxTotalBytes: config.api.maxTotalBytes,
    })
    await storageManager.initialize()
    const jobQueue = new JobQueue(database)
    jobQueue.restoreFromDatabase()
    const analysisTaskRunner = new AnalysisTaskRunner(jobQueue, database, workspaceManager, cacheManager, policyGuard)
    analysisTaskRunner.start()

    // ── Runtime initialization (Analyzer mode) ──
    let runtimeConnection: RuntimeConnection | null = null
    let runtimeClient: ReturnType<typeof createRuntimeClient> | null = null
    let sandboxLauncher: ReturnType<typeof createSandboxLauncher> | null = null

    const recovery = createRuntimeRecovery({ config, runtimeClient, runtimeConnection, sandboxLauncher })

    async function initializeRuntime(): Promise<void> {
      if (config.node.role !== 'analyzer' || config.runtime.mode === 'disabled') {
        return
      }

      // manual mode: connect to a user-managed runtime endpoint (cross-platform)
      if (config.runtime.mode === 'manual') {
        if (!config.runtime.endpoint) {
          logger.warn('Runtime mode is manual but no endpoint is configured; dynamic tools will be unavailable')
          return
        }
        try {
          const healthRes = await fetch(`${config.runtime.endpoint}/health`, { signal: AbortSignal.timeout(10_000) })
          if (!healthRes.ok) {
            logger.warn({ endpoint: config.runtime.endpoint }, 'Configured manual runtime endpoint is not healthy; dynamic tools will be unavailable')
            return
          }
          runtimeClient = createRuntimeClient({
            endpoint: config.runtime.endpoint,
            apiKey: config.runtime.apiKey,
          })
          runtimeClient.recover = async () => false // manual mode cannot auto-recover
          recovery.setRuntimeClient(runtimeClient)
          logger.info({ endpoint: config.runtime.endpoint }, 'Manual runtime connected')
          logger.warn('Dynamic analysis will execute actual samples. Ensure the runtime endpoint is running in an isolated environment.')
        } catch (err) {
          logger.warn({ err, endpoint: config.runtime.endpoint }, 'Failed to connect to manual runtime endpoint; dynamic tools will be unavailable')
        }
        return
      }

      // remote-sandbox mode: ask a Windows Host Agent to launch a sandbox
      if (config.runtime.mode === 'remote-sandbox') {
        if (!config.runtime.hostAgentEndpoint) {
          logger.warn('Runtime mode is remote-sandbox but no hostAgentEndpoint is configured; dynamic tools will be unavailable')
          return
        }
        try {
          const startRes = await fetch(`${config.runtime.hostAgentEndpoint}/sandbox/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...(config.runtime.hostAgentApiKey ? { Authorization: `Bearer ${config.runtime.hostAgentApiKey}` } : {}) },
            body: JSON.stringify({ timeoutMs: config.runtime.healthCheckTimeoutMs }),
            signal: AbortSignal.timeout(60_000),
          })
          if (!startRes.ok) {
            const body = await startRes.text().catch(() => '')
            logger.warn({ status: startRes.status, body }, 'Host agent failed to start sandbox; dynamic tools will be unavailable')
            return
          }
          const startData = (await startRes.json()) as { ok?: boolean; endpoint?: string; sandboxId?: string }
          if (!startData.ok || !startData.endpoint) {
            logger.warn({ startData }, 'Host agent returned an unsuccessful sandbox start; dynamic tools will be unavailable')
            return
          }
          runtimeClient = createRuntimeClient({
            endpoint: startData.endpoint,
            apiKey: config.runtime.apiKey,
          })
          runtimeClient.recover = recovery.recover
          recovery.setRuntimeClient(runtimeClient)
          logger.info({ endpoint: startData.endpoint, sandboxId: startData.sandboxId }, 'Remote-sandbox runtime connected')
          logger.warn('Dynamic analysis will execute actual samples inside the remote Windows Sandbox. Ensure the sandbox is properly isolated.')
        } catch (err) {
          logger.warn({ err, hostAgentEndpoint: config.runtime.hostAgentEndpoint }, 'Failed to connect to host agent; dynamic tools will be unavailable')
        }
        return
      }

      // auto-sandbox mode: only possible on Windows host directly
      if (config.runtime.mode === 'auto-sandbox') {
        if (process.platform !== 'win32') {
          logger.warn('Auto-sandbox mode requires Windows host; dynamic tools will be unavailable on this platform')
          return
        }
        try {
          const available = await isWindowsSandboxAvailable()
          if (!available) {
            logger.warn('Windows Sandbox is not available; dynamic tools will be unavailable')
            return
          }
          if (!sandboxLauncher) {
            sandboxLauncher = createSandboxLauncher()
            recovery.setSandboxLauncher(sandboxLauncher)
          }
          const connection = await sandboxLauncher.launch()
          if (connection) {
            runtimeConnection = connection
            recovery.setRuntimeConnection(runtimeConnection)
            if (!runtimeClient) {
              runtimeClient = createRuntimeClient({
                endpoint: connection.endpoint,
                apiKey: config.runtime.apiKey,
              })
            } else {
              runtimeClient.setEndpoint(connection.endpoint)
            }
            runtimeClient.recover = recovery.recover
            recovery.setRuntimeClient(runtimeClient)
            logger.info({ endpoint: connection.endpoint }, 'Auto-sandbox runtime connected')
            logger.warn('Dynamic analysis will execute actual samples inside Windows Sandbox. Ensure the sandbox is properly isolated.')
            sandboxLauncher.startHealthCheck({
              intervalMs: 30_000,
              unhealthyThreshold: 3,
              async onUnhealthy() {
                logger.warn('Auto-sandbox runtime unhealthy; tearing down and relaunching')
                await recovery.recover()
              },
            })
          } else {
            logger.warn('Auto-sandbox launch timed out or failed')
          }
        } catch (err) {
          logger.warn({ err }, 'Failed to initialize auto-sandbox runtime')
        }
      }
    }

    await initializeRuntime()

    // Create and start MCP server
    const server = new MCPServer(config, {
      workspaceManager,
      database,
      policyGuard,
      storageManager,
      apiBootstrapper: defaultApiBootstrapper,
    })

    // Register all tools & prompts via the centralised registry
    await registerAllTools(server, {
      workspaceManager,
      database,
      policyGuard,
      cacheManager,
      jobQueue,
      storageManager,
      config,
      server,
      runtimeClient,
      sandboxDir: runtimeConnection?.sandboxDir ?? null,
    })

    // Start server
    await server.start()

    // Handle graceful shutdown
    const shutdown = async (signal: string) => {
      server.getLogger().info(`Received ${signal}, shutting down gracefully`)
      if (sandboxLauncher) {
        sandboxLauncher.stopHealthCheck()
        await sandboxLauncher.teardown().catch(() => {})
      }
      analysisTaskRunner.stop()
      await server.stop()
      process.exit(0)
    }

    process.on('SIGINT', () => shutdown('SIGINT'))
    process.on('SIGTERM', () => shutdown('SIGTERM'))
  } catch (error) {
    process.stderr.write(`Failed to start MCP Server: ${error}\n`)
    process.exit(1)
  }
}

main()
