/**
 * Delegating PluginServerInterface — replaces dynamic plugin handlers with
 * remote Runtime RPC calls when running in analyzer mode.
 */

import type { PluginServerInterface, ToolDefinition, WorkerResult, ArtifactRef, RuntimeBackendHint } from '../plugins/sdk.js'
import type { ProgressReporter } from '../streaming-progress.js'
import { randomUUID, createHash } from 'crypto'
import { logger } from '../logger.js'
import fs from 'fs/promises'
import path from 'path'
import {
  mergeSetupActions,
  buildCoreLinuxToolchainSetupActions,
  buildDynamicDependencySetupActions,
  mergeRequiredUserInputs,
  buildDynamicDependencyRequiredUserInputs,
} from '../plugins/docker-shared.js'

export interface RuntimeClientLike {
  execute(
    req: {
      taskId: string
      sampleId: string
      tool: string
      args: Record<string, unknown>
      timeoutMs: number
      sampleInboxPath?: string
      runtimeBackendHint?: RuntimeBackendHint
    },
    opts?: { onProgress?: (progress: number, message?: string) => void },
  ): Promise<any>
  uploadSample(taskId: string, localSamplePath: string, inboxHostDir: string): Promise<void>
  downloadArtifacts(taskId: string, outboxHostDir: string, artifactNames: string[]): Promise<string[]>
  recover?(): Promise<boolean>
}

interface PluginServerWithProgress extends PluginServerInterface {
  getProgressReporter?: (progressToken?: string | number) => ProgressReporter
}

/**
 * Dynamic tools that do NOT require actual sample execution and can stay
 * on the Analyzer node (pure static planning / attribution).
 */
const LOCAL_DYNAMIC_TOOLS = new Set([
  'dynamic.auto_hook',
  'dynamic.trace.attribute',
  'dynamic.dependencies',
  'dynamic.trace.import',
  'dynamic.memory.import',
  'frida.script.generate',
])

export function createDelegatingServer(
  inner: PluginServerWithProgress,
  pluginId: string,
  runtimeClient: RuntimeClientLike | null | undefined,
  workspaceManager: any,
  database: any,
  resolvePrimarySamplePath: any,
  sandboxDir: string | null | undefined,
): PluginServerInterface {
  return {
    registerTool(definition, handler) {
      if (LOCAL_DYNAMIC_TOOLS.has(definition.name)) {
        inner.registerTool(definition, handler)
        return
      }

      const wrapped = async (args: any): Promise<WorkerResult> => {
        if (!runtimeClient) {
          return {
            ok: true,
            data: {
              status: 'setup_required',
              summary: 'Dynamic analysis runtime is not available. Ensure Windows Sandbox is installed and enabled, or configure a manual runtime endpoint.',
              recommended_next_tools: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
            },
            warnings: ['Dynamic analysis runtime is not connected.'],
            setup_actions: mergeSetupActions(
              buildCoreLinuxToolchainSetupActions(),
              buildDynamicDependencySetupActions(),
            ),
            required_user_inputs: mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs()),
          }
        }

        const taskId = randomUUID()
        const sampleId = args?.sample_id as string | undefined
        const progressToken = args?._meta?.progressToken as string | number | undefined
        const progressReporter = inner.getProgressReporter?.(progressToken)

        try {
          if (sampleId && resolvePrimarySamplePath) {
            const resolved = await resolvePrimarySamplePath(workspaceManager, sampleId)
            const inboxHostDir = sandboxDir ? path.join(sandboxDir, 'inbox') : ''
            await runtimeClient.uploadSample(taskId, resolved.samplePath, inboxHostDir)
          }

          const result = await runtimeClient.execute(
            {
              taskId,
              sampleId: sampleId || '',
              tool: definition.name,
              args,
              timeoutMs: 120_000,
              runtimeBackendHint: definition.runtimeBackendHint,
            },
            {
              onProgress: (progress, message) => {
                progressReporter?.report(progress, message).catch(() => {})
              },
            },
          )

          let persistedArtifacts: ArtifactRef[] = []
          if (result.artifactRefs && result.artifactRefs.length > 0 && sampleId && workspaceManager && database) {
            const outboxHostDir = sandboxDir ? path.join(sandboxDir, 'outbox') : ''
            const artifactNames = result.artifactRefs.map((a: any) => path.win32.basename(a.path))
            const downloadedPaths = await runtimeClient.downloadArtifacts(taskId, outboxHostDir, artifactNames)
            persistedArtifacts = await persistRuntimeArtifacts(
              workspaceManager,
              database,
              sampleId,
              taskId,
              definition.name,
              downloadedPaths,
            )
          }

          const baseResult: WorkerResult = result.result ?? { ok: true, data: result }
          if (persistedArtifacts.length > 0) {
            const existing = Array.isArray(baseResult.artifacts) ? baseResult.artifacts : []
            baseResult.artifacts = [...existing, ...persistedArtifacts]
          }
          return baseResult
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err)
          const isNetworkError = /ECONNREFUSED|ECONNRESET|socket hang up|502|503|timeout/i.test(errMsg)

          if (isNetworkError && runtimeClient.recover) {
            logger.warn({ pluginId, tool: definition.name, errMsg }, 'Runtime appears unreachable; attempting recovery')
            try {
              const recovered = await runtimeClient.recover()
              if (recovered) {
                logger.info({ pluginId, tool: definition.name }, 'Runtime recovered; retrying execution')
                const retryResult = await runtimeClient.execute(
                  {
                    taskId,
                    sampleId: sampleId || '',
                    tool: definition.name,
                    args,
                    timeoutMs: 120_000,
                    runtimeBackendHint: definition.runtimeBackendHint,
                  },
                  {
                    onProgress: (progress, message) => {
                      progressReporter?.report(progress, message).catch(() => {})
                    },
                  },
                )
                let persistedArtifacts: ArtifactRef[] = []
                if (retryResult.artifactRefs && retryResult.artifactRefs.length > 0 && sampleId && workspaceManager && database) {
                  const outboxHostDir = sandboxDir ? path.join(sandboxDir, 'outbox') : ''
                  const artifactNames = retryResult.artifactRefs.map((a: any) => path.win32.basename(a.path))
                  const downloadedPaths = await runtimeClient.downloadArtifacts(taskId, outboxHostDir, artifactNames)
                  persistedArtifacts = await persistRuntimeArtifacts(
                    workspaceManager,
                    database,
                    sampleId,
                    taskId,
                    definition.name,
                    downloadedPaths,
                  )
                }
                const baseResult: WorkerResult = retryResult.result ?? { ok: true, data: retryResult }
                if (persistedArtifacts.length > 0) {
                  const existing = Array.isArray(baseResult.artifacts) ? baseResult.artifacts : []
                  baseResult.artifacts = [...existing, ...persistedArtifacts]
                }
                return baseResult
              }
            } catch (recoverErr) {
              logger.error({ pluginId, tool: definition.name, recoverErr }, 'Runtime recovery failed')
            }
          }

          logger.error({ pluginId, tool: definition.name, err }, 'Delegated runtime execution failed')
          return {
            ok: false,
            errors: [`Runtime execution failed: ${errMsg}`],
          }
        }
      }
      inner.registerTool(definition, wrapped)
    },
    unregisterTool(name) {
      inner.unregisterTool(name)
    },
  }
}

async function persistRuntimeArtifacts(
  workspaceManager: any,
  database: any,
  sampleId: string,
  taskId: string,
  toolName: string,
  downloadedPaths: string[],
): Promise<ArtifactRef[]> {
  const persisted: ArtifactRef[] = []
  if (!downloadedPaths || downloadedPaths.length === 0) {
    return persisted
  }

  try {
    const workspace = await workspaceManager.createWorkspace(sampleId)
    const reportDir = path.join(workspace.reports, 'runtime_analysis', sanitizePathSegment(toolName))
    await fs.mkdir(reportDir, { recursive: true })

    for (const srcPath of downloadedPaths) {
      try {
        const basename = path.basename(srcPath)
        const destName = `${taskId}_${basename}`
        const destPath = path.join(reportDir, destName)
        await fs.copyFile(srcPath, destPath)

        const content = await fs.readFile(destPath)
        const sha256 = createHash('sha256').update(content).digest('hex')
        const relativePath = path.relative(workspace.root, destPath).replace(/\\/g, '/')
        const artifactId = randomUUID()
        const createdAt = new Date().toISOString()
        const mime = guessMime(basename)

        database.insertArtifact({
          id: artifactId,
          sample_id: sampleId,
          type: 'runtime_analysis',
          path: relativePath,
          sha256,
          mime,
          created_at: createdAt,
        })

        persisted.push({
          id: artifactId,
          type: 'runtime_analysis',
          path: relativePath,
          sha256,
          mime,
        })
        logger.debug({ sampleId, taskId, tool: toolName, path: relativePath }, 'Persisted runtime artifact')
      } catch (innerErr) {
        logger.warn({ sampleId, taskId, srcPath, err: innerErr }, 'Failed to persist runtime artifact')
      }
    }
  } catch (err) {
    logger.warn({ sampleId, taskId, err }, 'Failed to prepare runtime artifact directory')
  }

  return persisted
}

function sanitizePathSegment(segment: string): string {
  return segment.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 64)
}

function guessMime(filename: string): string {
  const lower = filename.toLowerCase()
  if (lower.endsWith('.json')) return 'application/json'
  if (lower.endsWith('.dmp')) return 'application/octet-stream'
  if (lower.endsWith('.bin')) return 'application/octet-stream'
  if (lower.endsWith('.txt')) return 'text/plain'
  if (lower.endsWith('.log')) return 'text/plain'
  if (lower.endsWith('.html')) return 'text/html'
  if (lower.endsWith('.png')) return 'image/png'
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg'
  return 'application/octet-stream'
}
