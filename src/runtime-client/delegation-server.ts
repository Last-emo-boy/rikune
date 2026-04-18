/**
 * Delegating PluginServerInterface — replaces dynamic plugin handlers with
 * remote Runtime RPC calls when running in analyzer mode.
 */

import { createHash, randomUUID } from 'crypto'
import type { PluginServerInterface, ToolDefinition, WorkerResult, ArtifactRef, RuntimeBackendHint } from '../plugins/sdk.js'
import {
  RuntimeDelegationFailureDataSchema,
  type RuntimeDelegationFailureCategory,
  type WorkerResult as CoreWorkerResult,
} from '../types.js'
import type { RuntimeBackendCapability, RuntimeBackendHintValidationResult } from './runtime-client.js'
import type { ProgressReporter } from '../streaming-progress.js'
import { logger } from '../logger.js'
import { resolveRuntimeSidecarUploads, type RuntimeSidecarUpload } from './sidecar-staging.js'
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
  uploadSample(
    taskId: string,
    localSamplePath: string,
    inboxHostDir: string,
    options?: { sidecars?: RuntimeSidecarUpload[]; preserveFilename?: boolean },
  ): Promise<void>
  downloadArtifacts(taskId: string, outboxHostDir: string, artifactNames: string[]): Promise<string[]>
  getCapabilities?(options?: { forceRefresh?: boolean }): Promise<RuntimeBackendCapability[] | null>
  validateRuntimeBackendHint?(
    hint: RuntimeBackendHint,
    options?: { forceRefresh?: boolean },
  ): Promise<RuntimeBackendHintValidationResult>
  getEndpoint?(): string
  recover?(options?: { forceRefreshCapabilities?: boolean }): Promise<boolean>
}

export interface RuntimeDelegatedToolHandlerOptions {
  definition: ToolDefinition
  pluginId: string
  runtimeClient: RuntimeClientLike | null | undefined
  workspaceManager: any
  database: any
  resolvePrimarySamplePath: any
  sandboxDir?: string | null
  getProgressReporter?: (progressToken?: string | number) => ProgressReporter
}

interface PluginServerWithProgress extends PluginServerInterface {
  getProgressReporter?: (progressToken?: string | number) => ProgressReporter
}

type RuntimeExecuteResponseLike = Awaited<ReturnType<RuntimeClientLike['execute']>>

interface RuntimeDelegationGuidance {
  recommendedNextTools: string[]
  nextActions: string[]
}

function buildRuntimeDelegationGuidance(
  definition: ToolDefinition,
  category: RuntimeDelegationFailureCategory,
): RuntimeDelegationGuidance {
  switch (definition.name) {
    case 'sandbox.execute':
      return {
        recommendedNextTools: ['dynamic.dependencies', 'system.health', 'workflow.analyze.start'],
        nextActions: [
          category === 'unsupported_runtime_backend_hint'
            ? 'Connect a runtime that advertises inline/executeSandboxExecute support before retrying sandbox execution.'
            : 'Verify dynamic-analysis runtime availability and dependency readiness before retrying sandbox execution.',
          'Use workflow.analyze.start to continue staged triage without live execution while runtime support is unavailable.',
        ],
      }
    case 'managed.safe_run':
      return {
        recommendedNextTools: ['dynamic.dependencies', 'system.health', 'sample.profile.get'],
        nextActions: [
          'Verify .NET sandbox prerequisites and runtime connectivity before retrying managed.safe_run.',
          'Use sample.profile.get to continue static triage if managed execution is temporarily unavailable.',
        ],
      }
    case 'wine.run':
      return {
        recommendedNextTools: ['wine.env', 'dynamic.dependencies', 'system.health'],
        nextActions: [
          'Inspect Wine and winedbg readiness before retrying Wine-backed execution.',
          'Re-run only after a runtime with the required Wine execution support is connected.',
        ],
      }
    case 'frida.runtime.instrument':
      return {
        recommendedNextTools: ['frida.script.generate', 'dynamic.dependencies', 'system.health'],
        nextActions: [
          'Verify Frida runtime dependencies and reconnect a compatible runtime before retrying instrumentation.',
          'Use frida.script.generate to prepare instrumentation logic while runtime support is unavailable.',
        ],
      }
    case 'debug.session.start':
      return {
        recommendedNextTools: ['sample.profile.get', 'dynamic.dependencies', 'system.health'],
        nextActions: [
          'Confirm debugger prerequisites and runtime connectivity before starting a debug session.',
          'Use sample.profile.get to confirm the sample format while runtime debugging support is unavailable.',
        ],
      }
    default:
      return {
        recommendedNextTools: ['dynamic.dependencies', 'system.health', 'workflow.analyze.start'],
        nextActions: [
          'Inspect runtime dependency health and reconnect a compatible runtime endpoint before retrying.',
        ],
      }
  }
}

function buildRuntimeFailureResult(
  definition: ToolDefinition,
  category: RuntimeDelegationFailureCategory,
  params: {
    summary: string
    errors?: string[]
    warnings?: string[]
    runtimeEndpoint?: string | null
    runtimeBackendHint?: RuntimeBackendHint
    availableRuntimeBackends?: RuntimeBackendCapability[]
    setupActions?: unknown[]
    requiredUserInputs?: unknown[]
    ok?: boolean
  },
): CoreWorkerResult {
  const guidance = buildRuntimeDelegationGuidance(definition, category)
  const runtimeEndpoint = params.runtimeEndpoint ?? null
  const runtimeBackendHint = params.runtimeBackendHint ?? definition.runtimeBackendHint
  const availableRuntimeBackends = params.availableRuntimeBackends ?? []

  const failureData = RuntimeDelegationFailureDataSchema.parse({
    status:
      category === 'runtime_unavailable' || category === 'unsupported_runtime_backend_hint'
        ? 'setup_required'
        : 'failed',
    failure_category: category,
    summary: params.summary,
    recommended_next_tools: guidance.recommendedNextTools,
    next_actions: guidance.nextActions,
    runtime_endpoint: runtimeEndpoint,
    ...(runtimeBackendHint ? { required_runtime_backend_hint: runtimeBackendHint } : {}),
    available_runtime_backends: availableRuntimeBackends,
  })

  return {
    ok: params.ok ?? false,
    data: failureData,
    errors: params.errors,
    warnings: params.warnings,
    setup_actions: params.setupActions,
    required_user_inputs: params.requiredUserInputs,
  }
}

function normalizeRuntimeExecuteResponse(
  definition: ToolDefinition,
  result: RuntimeExecuteResponseLike,
  runtimeEndpoint?: string | null,
): CoreWorkerResult {
  if (result?.result) {
    return result.result
  }

  const runtimeErrors = Array.isArray(result?.errors)
    ? result.errors.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
    : []

  if (runtimeErrors.some((entry) => entry.startsWith('Unsupported runtime backend hint:'))) {
    return buildRuntimeFailureResult(definition, 'unsupported_runtime_backend_hint', {
      summary: `Runtime does not advertise the backend required by ${definition.name}.`,
      errors: runtimeErrors,
      runtimeEndpoint,
      availableRuntimeBackends: Array.isArray(result?.capabilities) ? result.capabilities : [],
    })
  }

  if (result?.ok === false || runtimeErrors.length > 0) {
    return buildRuntimeFailureResult(definition, 'tool_specific_execution_failed', {
      summary: `${definition.name} failed while executing on the runtime node.`,
      errors: runtimeErrors.length > 0 ? runtimeErrors : ['Runtime execution failed without a result payload.'],
      runtimeEndpoint,
      availableRuntimeBackends: Array.isArray(result?.capabilities) ? result.capabilities : [],
    })
  }

  return { ok: true, data: result }
}

function buildUnsupportedRuntimeBackendHintResult(
  definition: ToolDefinition,
  validation: RuntimeBackendHintValidationResult,
  runtimeEndpoint?: string | null,
): CoreWorkerResult {
  const runtimeBackendHint = definition.runtimeBackendHint
  const hintSummary = runtimeBackendHint ? `${runtimeBackendHint.type}/${runtimeBackendHint.handler}` : 'unknown'

  return buildRuntimeFailureResult(definition, 'unsupported_runtime_backend_hint', {
    summary: `Runtime does not advertise support for backend hint ${hintSummary} required by tool ${definition.name}.`,
    errors: [`Runtime does not advertise support for backend hint ${hintSummary} required by tool ${definition.name}.`],
    runtimeEndpoint,
    runtimeBackendHint,
    availableRuntimeBackends: validation.capabilities ?? [],
  })
}

function buildRuntimeUnavailableResult(
  definition: ToolDefinition,
  runtimeEndpoint?: string | null,
): CoreWorkerResult {
  return buildRuntimeFailureResult(definition, 'runtime_unavailable', {
    ok: true,
    summary:
      'Dynamic analysis runtime is not available. Ensure Windows Sandbox is installed and enabled, or configure a manual runtime endpoint.',
    warnings: ['Dynamic analysis runtime is not connected.'],
    runtimeEndpoint,
    setupActions: mergeSetupActions(
      buildCoreLinuxToolchainSetupActions(),
      buildDynamicDependencySetupActions(),
    ),
    requiredUserInputs: mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs()),
  })
}

export function createRuntimeDelegatedToolHandler(
  options: RuntimeDelegatedToolHandlerOptions,
): (args: any) => Promise<CoreWorkerResult> {
  let registeredHandler: ((args: any) => Promise<CoreWorkerResult>) | null = null
  const server = {
    registerTool(_definition: ToolDefinition, handler: (args: any) => Promise<CoreWorkerResult>) {
      registeredHandler = handler
    },
    unregisterTool() {},
    getToolDefinitions() {
      return []
    },
    registerPrompt() {},
    getPromptDefinitions() {
      return []
    },
    registerResource() {},
    getClientCapabilities() {
      return undefined
    },
    getClientVersion() {
      return undefined
    },
    async createMessage() {
      throw new Error('Runtime delegation helper does not support sampling')
    },
    getProgressReporter: options.getProgressReporter,
  } as unknown as PluginServerWithProgress

  createDelegatingServer(
    server,
    options.pluginId,
    options.runtimeClient,
    options.workspaceManager,
    options.database,
    options.resolvePrimarySamplePath,
    options.sandboxDir ?? null,
  ).registerTool(options.definition, async () =>
    buildRuntimeUnavailableResult(
      options.definition,
      options.runtimeClient?.getEndpoint?.() ?? null,
    ),
  )

  if (!registeredHandler) {
    throw new Error(`Failed to create runtime delegated handler for ${options.definition.name}`)
  }
  return registeredHandler
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
  'runtime.debug.session.start',
  'runtime.debug.session.status',
  'runtime.debug.session.stop',
  'runtime.debug.command',
  'dynamic.runtime.status',
  'runtime.hyperv.control',
  'frida.script.generate',
])

function readBooleanArg(args: any, key: string, defaultValue: boolean): boolean {
  if (!args || typeof args !== 'object' || !(key in args)) {
    return defaultValue
  }
  return args[key] !== false
}

function readNumberArg(args: any, key: string, defaultValue: number): number {
  if (!args || typeof args !== 'object') {
    return defaultValue
  }
  const value = Number(args[key])
  return Number.isFinite(value) && value > 0 ? value : defaultValue
}

async function buildRuntimeUploadOptions(
  definition: ToolDefinition,
  args: any,
  samplePath: string,
): Promise<{ sidecars: RuntimeSidecarUpload[]; warnings: string[] }> {
  const autoDefault = definition.name === 'dynamic.behavior.capture' || definition.name === 'sandbox.execute'
  return resolveRuntimeSidecarUploads(samplePath, {
    sidecarPaths: args?.sidecar_paths,
    autoStageSidecars: readBooleanArg(args, 'auto_stage_sidecars', autoDefault),
    maxSidecars: readNumberArg(args, 'max_sidecars', 32),
    maxTotalBytes: readNumberArg(args, 'sidecar_max_total_bytes', 128 * 1024 * 1024),
  })
}

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
        const runtimeEndpoint = runtimeClient?.getEndpoint?.() ?? null
        if (!runtimeClient) {
          return buildRuntimeUnavailableResult(definition, runtimeEndpoint)
        }

        const taskId = randomUUID()
        const sampleId = args?.sample_id as string | undefined
        const progressToken = args?._meta?.progressToken as string | number | undefined
        const progressReporter = inner.getProgressReporter?.(progressToken)
        const runtimeBackendHint = definition.runtimeBackendHint
        let stagedUpload: {
          samplePath: string
          inboxHostDir: string
          sidecars: RuntimeSidecarUpload[]
        } | null = null

        try {
          if (runtimeBackendHint && runtimeClient.validateRuntimeBackendHint) {
            const validation = await runtimeClient.validateRuntimeBackendHint(runtimeBackendHint)
            if (validation.supported === false) {
              return buildUnsupportedRuntimeBackendHintResult(definition, validation, runtimeEndpoint)
            }
          }

          if (sampleId && resolvePrimarySamplePath) {
            const resolved = await resolvePrimarySamplePath(workspaceManager, sampleId)
            const inboxHostDir = sandboxDir ? path.join(sandboxDir, 'inbox') : ''
            const uploadOptions = await buildRuntimeUploadOptions(definition, args, resolved.samplePath)
            for (const warning of uploadOptions.warnings) {
              logger.warn({ pluginId, tool: definition.name, warning }, 'Runtime sidecar staging warning')
            }
            stagedUpload = {
              samplePath: resolved.samplePath,
              inboxHostDir,
              sidecars: uploadOptions.sidecars,
            }
            await runtimeClient.uploadSample(taskId, resolved.samplePath, inboxHostDir, {
              preserveFilename: true,
              sidecars: uploadOptions.sidecars,
            })
          }

          const result = await runtimeClient.execute(
            {
              taskId,
              sampleId: sampleId || '',
              tool: definition.name,
              args,
              timeoutMs: 120_000,
              runtimeBackendHint,
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

          const baseResult = normalizeRuntimeExecuteResponse(definition, result, runtimeEndpoint)
          if (persistedArtifacts.length > 0) {
            const existing = Array.isArray(baseResult.artifacts) ? baseResult.artifacts : []
            baseResult.artifacts = [...existing, ...persistedArtifacts]
          }
          return baseResult
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err)
          const isHostAgentSandboxStartFailure =
            err instanceof Error && err.name === 'HostAgentSandboxStartError'
          const isNetworkError =
            !isHostAgentSandboxStartFailure &&
            /ECONNREFUSED|ECONNRESET|socket hang up|502|503|AbortError|TimeoutError|UND_ERR|fetch failed/i.test(errMsg)

          if (isNetworkError && runtimeClient.recover) {
            logger.warn({ pluginId, tool: definition.name, errMsg }, 'Runtime appears unreachable; attempting recovery')
            try {
              const recovered = await runtimeClient.recover({ forceRefreshCapabilities: true })
              if (recovered) {
                const recoveredRuntimeEndpoint = runtimeClient.getEndpoint?.() ?? runtimeEndpoint
                logger.info({ pluginId, tool: definition.name, endpoint: recoveredRuntimeEndpoint }, 'Runtime recovered; retrying execution')
                if (stagedUpload) {
                  await runtimeClient.uploadSample(taskId, stagedUpload.samplePath, stagedUpload.inboxHostDir, {
                    preserveFilename: true,
                    sidecars: stagedUpload.sidecars,
                  })
                }
                const retryResult = await runtimeClient.execute(
                  {
                    taskId,
                    sampleId: sampleId || '',
                    tool: definition.name,
                    args,
                    timeoutMs: 120_000,
                    runtimeBackendHint,
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
                const baseResult = normalizeRuntimeExecuteResponse(definition, retryResult, recoveredRuntimeEndpoint)
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
          return buildRuntimeFailureResult(definition, isNetworkError ? 'runtime_recovery_failed' : 'tool_specific_execution_failed', {
            summary: isHostAgentSandboxStartFailure
              ? 'Windows Host Agent could not start the Windows Sandbox runtime.'
              : isNetworkError
                ? `Runtime became unreachable while executing ${definition.name} and automatic recovery did not restore service.`
                : `Delegated runtime execution failed for ${definition.name}.`,
            errors: [`Runtime execution failed: ${errMsg}`],
            runtimeEndpoint,
          })
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
        const artifactType = inferRuntimeArtifactType(toolName, basename)

        database.insertArtifact({
          id: artifactId,
          sample_id: sampleId,
          type: artifactType,
          path: relativePath,
          sha256,
          mime,
          created_at: createdAt,
        })

        persisted.push({
          id: artifactId,
          type: artifactType,
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

function inferRuntimeArtifactType(toolName: string, filename: string): string {
  const lowerName = filename.toLowerCase()
  if (toolName === 'dynamic.behavior.capture' && lowerName.endsWith('.json')) {
    return 'dynamic_trace_json'
  }
  if (toolName === 'sandbox.execute' && lowerName.endsWith('.json')) {
    return 'sandbox_trace_json'
  }
  return 'runtime_analysis'
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
