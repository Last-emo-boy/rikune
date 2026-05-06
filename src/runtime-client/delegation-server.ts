/**
 * Delegating PluginServerInterface — replaces dynamic plugin handlers with
 * remote Runtime RPC calls when running in analyzer mode.
 */

import { createHash, randomUUID } from 'crypto'
import type {
  PluginServerInterface,
  ToolDefinition,
  WorkerResult,
  ArtifactRef,
  ToolRuntimeContract,
} from '../plugins/sdk.js'
import {
  buildRuntimeArtifactControlPlaneMetadata,
  RuntimeDelegationFailureDataSchema,
  inferRuntimeArtifactType,
  type RuntimeDelegationFailureCategory,
  type WorkerResult as CoreWorkerResult,
} from '../types.js'
import type { RuntimeBackendCapability, RuntimeContractValidationResult } from './runtime-client.js'
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
import { isExplicitLocalDynamicTool } from './dynamic-tool-policy.js'

export interface RuntimeClientLike {
  execute(
    req: {
      taskId: string
      sampleId: string
      tool: string
      args: Record<string, unknown>
      timeoutMs: number
      sampleInboxPath?: string
      runtime?: ToolRuntimeContract
    },
    opts?: { onProgress?: (progress: number, message?: string) => void }
  ): Promise<any>
  uploadSample(
    taskId: string,
    localSamplePath: string,
    inboxHostDir: string,
    options?: { sidecars?: RuntimeSidecarUpload[]; preserveFilename?: boolean }
  ): Promise<void>
  downloadArtifacts(
    taskId: string,
    outboxHostDir: string,
    artifactNames: string[]
  ): Promise<string[]>
  getCapabilities?(options?: { forceRefresh?: boolean }): Promise<RuntimeBackendCapability[] | null>
  validateRuntimeContract?(
    contract: ToolRuntimeContract,
    options?: { forceRefresh?: boolean }
  ): Promise<RuntimeContractValidationResult>
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

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function buildRuntimeDelegationGuidance(
  definition: ToolDefinition,
  category: RuntimeDelegationFailureCategory
): RuntimeDelegationGuidance {
  switch (definition.name) {
    case 'sandbox.execute':
      return {
        recommendedNextTools: uniqueStrings([
          'dynamic.runtime.status',
          'dynamic.dependencies',
          'system.health',
          'workflow.analyze.start',
        ]),
        nextActions: [
          category === 'runtime_recovery_failed'
            ? 'Call dynamic.runtime.status to check Host Agent health, Runtime Node health, advertised capabilities, and whether Sandbox/Hyper-V has an active runtime endpoint.'
            : category === 'unsupported_runtime_contract'
              ? 'Connect a Runtime Node that advertises inline/executeSandboxExecute support before retrying live sandbox execution.'
              : 'Verify dynamic-analysis runtime availability and dependency readiness before retrying live sandbox execution.',
          'Start Windows Host Agent in the logged-on user session for Windows Sandbox/Hyper-V work, or configure RUNTIME_HOST_AGENT_ENDPOINT to a reachable Host Agent.',
          'Use workflow.analyze.start to continue staged triage without live execution while runtime support is unavailable.',
        ],
      }
    case 'managed.safe_run':
      return {
        recommendedNextTools: uniqueStrings([
          'dynamic.runtime.status',
          'dynamic.dependencies',
          'system.health',
          'sample.profile.get',
        ]),
        nextActions: [
          'Verify .NET sandbox prerequisites and runtime connectivity before retrying managed.safe_run.',
          'Use sample.profile.get to continue static triage if managed execution is temporarily unavailable.',
        ],
      }
    case 'wine.run':
      return {
        recommendedNextTools: uniqueStrings([
          'dynamic.runtime.status',
          'wine.env',
          'dynamic.dependencies',
          'system.health',
        ]),
        nextActions: [
          'Inspect Wine and winedbg readiness before retrying Wine-backed execution.',
          'Re-run only after a runtime with the required Wine execution support is connected.',
        ],
      }
    case 'frida.runtime.instrument':
      return {
        recommendedNextTools: uniqueStrings([
          'dynamic.runtime.status',
          'frida.script.generate',
          'dynamic.dependencies',
          'system.health',
        ]),
        nextActions: [
          'Call dynamic.runtime.status to confirm the Runtime Node advertises Frida support before retrying instrumentation.',
          'Verify Frida runtime dependencies and reconnect a compatible runtime before retrying instrumentation.',
          'Use frida.script.generate to prepare instrumentation logic while runtime support is unavailable.',
        ],
      }
    case 'debug.session.start':
      return {
        recommendedNextTools: uniqueStrings([
          'dynamic.runtime.status',
          'sample.profile.get',
          'dynamic.dependencies',
          'system.health',
        ]),
        nextActions: [
          'Confirm debugger prerequisites and runtime connectivity before starting a debug session.',
          'Use sample.profile.get to confirm the sample format while runtime debugging support is unavailable.',
        ],
      }
    default:
      return {
        recommendedNextTools: uniqueStrings([
          'dynamic.runtime.status',
          'dynamic.dependencies',
          'system.health',
          'workflow.analyze.start',
        ]),
        nextActions: [
          'Call dynamic.runtime.status to identify whether the Host Agent, Runtime Node endpoint, or advertised backend capability is missing.',
          'Inspect runtime dependency health and reconnect a compatible runtime endpoint before retrying.',
        ],
      }
  }
}

function buildRuntimeDiagnostic(params: {
  category: RuntimeDelegationFailureCategory
  definition: ToolDefinition
  runtimeEndpoint?: string | null
  availableRuntimeBackends: RuntimeBackendCapability[]
}) {
  const hasEndpoint = Boolean(params.runtimeEndpoint)
  const requiredContract = params.definition.runtime
  const matchingBackend =
    requiredContract &&
    params.availableRuntimeBackends.some(
      (backend) =>
        backend.type === requiredContract.type && backend.handler === requiredContract.handler
    )

  return {
    runtime_endpoint_configured: hasEndpoint,
    runtime_endpoint: params.runtimeEndpoint ?? null,
    required_backend: requiredContract || null,
    required_backend_advertised: Boolean(matchingBackend),
    available_backend_count: params.availableRuntimeBackends.length,
    likely_missing_plane:
      params.category === 'unsupported_runtime_contract'
        ? 'runtime_node_capability'
        : !hasEndpoint
          ? 'runtime_endpoint'
          : params.category === 'runtime_recovery_failed'
            ? 'host_agent_or_runtime_node'
            : 'tool_backend',
    live_execution_note:
      'MCP connection and dynamic planning do not imply live Windows Sandbox execution. Use dynamic.runtime.status before sandbox.execute when live execution is required.',
  }
}

function classifyRuntimePlane(
  category: RuntimeDelegationFailureCategory,
  runtimeEndpoint: string | null,
  availableRuntimeBackends: RuntimeBackendCapability[]
): 'runtime_endpoint' | 'host_agent' | 'runtime_node' | 'runtime_capability' | 'tool_backend' {
  if (category === 'unsupported_runtime_contract') {
    return 'runtime_capability'
  }
  if (!runtimeEndpoint) {
    return 'runtime_endpoint'
  }
  if (category === 'runtime_recovery_failed') {
    return availableRuntimeBackends.length > 0 ? 'host_agent' : 'runtime_node'
  }
  if (category === 'runtime_unavailable') {
    return 'runtime_node'
  }
  return 'tool_backend'
}

function buildFailureExecutionSemantics(params: {
  definition: ToolDefinition
  runtime?: ToolRuntimeContract
  summary: string
}) {
  const runtime = params.runtime ?? params.definition.runtime
  const requestedMode =
    runtime?.modes?.find((mode) => mode === 'live_sandbox' || mode === 'live_hyperv') ??
    runtime?.modes?.[0] ??
    (params.definition.name === 'sandbox.execute' ? 'live_sandbox' : 'manual_runtime')

  return {
    requested_mode: requestedMode,
    actual_mode: 'plan_only',
    backend: runtime ? `${runtime.type}/${runtime.handler}` : params.definition.name,
    live_execution: false,
    reason: params.summary,
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
    runtime?: ToolRuntimeContract
    availableRuntimeBackends?: RuntimeBackendCapability[]
    setupActions?: unknown[]
    requiredUserInputs?: unknown[]
    ok?: boolean
  }
): CoreWorkerResult {
  const guidance = buildRuntimeDelegationGuidance(definition, category)
  const runtimeEndpoint = params.runtimeEndpoint ?? null
  const runtime = params.runtime ?? definition.runtime
  const availableRuntimeBackends = params.availableRuntimeBackends ?? []
  const runtimePlane = classifyRuntimePlane(category, runtimeEndpoint, availableRuntimeBackends)

  const failureData = RuntimeDelegationFailureDataSchema.parse({
    status:
      category === 'runtime_unavailable' || category === 'unsupported_runtime_contract'
        ? 'setup_required'
        : 'failed',
    failure_category: category,
    summary: params.summary,
    runtime_plane: runtimePlane,
    execution_semantics: buildFailureExecutionSemantics({
      definition,
      runtime,
      summary: params.summary,
    }),
    recommended_next_tools: guidance.recommendedNextTools,
    next_actions: guidance.nextActions,
    runtime_endpoint: runtimeEndpoint,
    ...(runtime ? { required_runtime_contract: runtime } : {}),
    available_runtime_backends: availableRuntimeBackends,
  })

  return {
    ok: params.ok ?? false,
    data: {
      ...failureData,
      runtime_diagnostic: buildRuntimeDiagnostic({
        category,
        definition,
        runtimeEndpoint,
        availableRuntimeBackends,
      }),
    },
    errors: params.errors,
    warnings: params.warnings,
    setup_actions: params.setupActions,
    required_user_inputs: params.requiredUserInputs,
  }
}

function normalizeRuntimeExecuteResponse(
  definition: ToolDefinition,
  result: RuntimeExecuteResponseLike,
  runtimeEndpoint?: string | null
): CoreWorkerResult {
  if (result?.result) {
    return result.result
  }

  const runtimeErrors = Array.isArray(result?.errors)
    ? result.errors.filter(
        (entry): entry is string => typeof entry === 'string' && entry.trim().length > 0
      )
    : []

  if (runtimeErrors.some((entry) => entry.startsWith('Unsupported runtime contract:'))) {
    return buildRuntimeFailureResult(definition, 'unsupported_runtime_contract', {
      summary: `Runtime does not advertise the backend required by ${definition.name}.`,
      errors: runtimeErrors,
      runtimeEndpoint,
      availableRuntimeBackends: Array.isArray(result?.capabilities) ? result.capabilities : [],
    })
  }

  if (result?.ok === false || runtimeErrors.length > 0) {
    return buildRuntimeFailureResult(definition, 'tool_specific_execution_failed', {
      summary: `${definition.name} failed while executing on the runtime node.`,
      errors:
        runtimeErrors.length > 0
          ? runtimeErrors
          : ['Runtime execution failed without a result payload.'],
      runtimeEndpoint,
      availableRuntimeBackends: Array.isArray(result?.capabilities) ? result.capabilities : [],
    })
  }

  return { ok: true, data: result }
}

function buildUnsupportedToolRuntimeContractResult(
  definition: ToolDefinition,
  validation: RuntimeContractValidationResult,
  runtimeEndpoint?: string | null
): CoreWorkerResult {
  const runtime = definition.runtime
  const contractSummary = runtime ? `${runtime.type}/${runtime.handler}` : 'unknown'

  return buildRuntimeFailureResult(definition, 'unsupported_runtime_contract', {
    summary: `Runtime does not advertise support for runtime contract ${contractSummary} required by tool ${definition.name}.`,
    errors: [
      `Runtime does not advertise support for runtime contract ${contractSummary} required by tool ${definition.name}.`,
    ],
    runtimeEndpoint,
    runtime,
    availableRuntimeBackends: validation.capabilities ?? [],
  })
}

function buildRuntimeUnavailableResult(
  definition: ToolDefinition,
  runtimeEndpoint?: string | null
): CoreWorkerResult {
  return buildRuntimeFailureResult(definition, 'runtime_unavailable', {
    ok: true,
    summary:
      'Dynamic analysis runtime is not available. Ensure Windows Sandbox is installed and enabled, or configure a manual runtime endpoint.',
    warnings: ['Dynamic analysis runtime is not connected.'],
    runtimeEndpoint,
    setupActions: mergeSetupActions(
      buildCoreLinuxToolchainSetupActions(),
      buildDynamicDependencySetupActions()
    ),
    requiredUserInputs: mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs()),
  })
}

export function createRuntimeDelegatedToolHandler(
  options: RuntimeDelegatedToolHandlerOptions
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
    options.sandboxDir ?? null
  ).registerTool(options.definition, async () =>
    buildRuntimeUnavailableResult(
      options.definition,
      options.runtimeClient?.getEndpoint?.() ?? null
    )
  )

  if (!registeredHandler) {
    throw new Error(`Failed to create runtime delegated handler for ${options.definition.name}`)
  }
  return registeredHandler
}

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
  samplePath: string
): Promise<{ sidecars: RuntimeSidecarUpload[]; warnings: string[] }> {
  const autoDefault =
    definition.name === 'dynamic.behavior.capture' || definition.name === 'sandbox.execute'
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
  sandboxDir: string | null | undefined
): PluginServerInterface {
  return {
    registerTool(definition, handler) {
      const runtime = definition.runtime
      if (!runtime || isExplicitLocalDynamicTool(definition.name)) {
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
        let stagedUpload: {
          samplePath: string
          inboxHostDir: string
          sidecars: RuntimeSidecarUpload[]
        } | null = null

        try {
          if (runtime && runtimeClient.validateRuntimeContract) {
            const validation = await runtimeClient.validateRuntimeContract(runtime)
            if (validation.supported === false) {
              return buildUnsupportedToolRuntimeContractResult(
                definition,
                validation,
                runtimeEndpoint
              )
            }
          }

          if (sampleId && resolvePrimarySamplePath) {
            const resolved = await resolvePrimarySamplePath(workspaceManager, sampleId)
            const inboxHostDir = sandboxDir ? path.join(sandboxDir, 'inbox') : ''
            const uploadOptions = await buildRuntimeUploadOptions(
              definition,
              args,
              resolved.samplePath
            )
            for (const warning of uploadOptions.warnings) {
              logger.warn(
                { pluginId, tool: definition.name, warning },
                'Runtime sidecar staging warning'
              )
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
              runtime,
            },
            {
              onProgress: (progress, message) => {
                progressReporter?.report(progress, message).catch(() => {})
              },
            }
          )

          let persistedArtifacts: ArtifactRef[] = []
          if (
            result.artifactRefs &&
            result.artifactRefs.length > 0 &&
            sampleId &&
            workspaceManager &&
            database
          ) {
            const outboxHostDir = sandboxDir ? path.join(sandboxDir, 'outbox') : ''
            const artifactNames = result.artifactRefs.map((a: any) => path.win32.basename(a.path))
            const downloadedPaths = await runtimeClient.downloadArtifacts(
              taskId,
              outboxHostDir,
              artifactNames
            )
            persistedArtifacts = await persistRuntimeArtifacts(
              workspaceManager,
              database,
              sampleId,
              taskId,
              definition.name,
              args,
              downloadedPaths
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
            /ECONNREFUSED|ECONNRESET|socket hang up|502|503|AbortError|TimeoutError|UND_ERR|fetch failed/i.test(
              errMsg
            )

          if (isNetworkError && runtimeClient.recover) {
            logger.warn(
              { pluginId, tool: definition.name, errMsg },
              'Runtime appears unreachable; attempting recovery'
            )
            try {
              const recovered = await runtimeClient.recover({ forceRefreshCapabilities: true })
              if (recovered) {
                const recoveredRuntimeEndpoint = runtimeClient.getEndpoint?.() ?? runtimeEndpoint
                logger.info(
                  { pluginId, tool: definition.name, endpoint: recoveredRuntimeEndpoint },
                  'Runtime recovered; retrying execution'
                )
                if (stagedUpload) {
                  await runtimeClient.uploadSample(
                    taskId,
                    stagedUpload.samplePath,
                    stagedUpload.inboxHostDir,
                    {
                      preserveFilename: true,
                      sidecars: stagedUpload.sidecars,
                    }
                  )
                }
                const retryResult = await runtimeClient.execute(
                  {
                    taskId,
                    sampleId: sampleId || '',
                    tool: definition.name,
                    args,
                    timeoutMs: 120_000,
                    runtime,
                  },
                  {
                    onProgress: (progress, message) => {
                      progressReporter?.report(progress, message).catch(() => {})
                    },
                  }
                )
                let persistedArtifacts: ArtifactRef[] = []
                if (
                  retryResult.artifactRefs &&
                  retryResult.artifactRefs.length > 0 &&
                  sampleId &&
                  workspaceManager &&
                  database
                ) {
                  const outboxHostDir = sandboxDir ? path.join(sandboxDir, 'outbox') : ''
                  const artifactNames = retryResult.artifactRefs.map((a: any) =>
                    path.win32.basename(a.path)
                  )
                  const downloadedPaths = await runtimeClient.downloadArtifacts(
                    taskId,
                    outboxHostDir,
                    artifactNames
                  )
                  persistedArtifacts = await persistRuntimeArtifacts(
                    workspaceManager,
                    database,
                    sampleId,
                    taskId,
                    definition.name,
                    args,
                    downloadedPaths
                  )
                }
                const baseResult = normalizeRuntimeExecuteResponse(
                  definition,
                  retryResult,
                  recoveredRuntimeEndpoint
                )
                if (persistedArtifacts.length > 0) {
                  const existing = Array.isArray(baseResult.artifacts) ? baseResult.artifacts : []
                  baseResult.artifacts = [...existing, ...persistedArtifacts]
                }
                return baseResult
              }
            } catch (recoverErr) {
              logger.error(
                { pluginId, tool: definition.name, recoverErr },
                'Runtime recovery failed'
              )
            }
          }

          logger.error(
            { pluginId, tool: definition.name, err },
            'Delegated runtime execution failed'
          )
          return buildRuntimeFailureResult(
            definition,
            isNetworkError ? 'runtime_recovery_failed' : 'tool_specific_execution_failed',
            {
              summary: isHostAgentSandboxStartFailure
                ? 'Windows Host Agent could not start the Windows Sandbox runtime.'
                : isNetworkError
                  ? `Runtime became unreachable while executing ${definition.name} and automatic recovery did not restore service.`
                  : `Delegated runtime execution failed for ${definition.name}.`,
              errors: [`Runtime execution failed: ${errMsg}`],
              runtimeEndpoint,
            }
          )
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
  args: Record<string, unknown>,
  downloadedPaths: string[]
): Promise<ArtifactRef[]> {
  const persisted: ArtifactRef[] = []
  if (!downloadedPaths || downloadedPaths.length === 0) {
    return persisted
  }

  try {
    const workspace = await workspaceManager.createWorkspace(sampleId)
    const effectiveToolName = resolveEffectiveRuntimeToolName(toolName, args)
    const reportDir = path.join(
      workspace.reports,
      'runtime_analysis',
      sanitizePathSegment(effectiveToolName)
    )
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
        const artifactType = inferRuntimeArtifactType(effectiveToolName, basename)

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
          metadata: buildRuntimeArtifactControlPlaneMetadata({
            artifactType,
            sourceRuntimeTool: toolName,
            effectiveRuntimeTool: effectiveToolName,
            runtimeTaskId: taskId,
          }),
        })
        logger.debug(
          { sampleId, taskId, tool: toolName, path: relativePath },
          'Persisted runtime artifact'
        )
      } catch (innerErr) {
        logger.warn(
          { sampleId, taskId, srcPath, err: innerErr },
          'Failed to persist runtime artifact'
        )
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

function resolveEffectiveRuntimeToolName(toolName: string, args: Record<string, unknown>): string {
  if (toolName !== 'runtime.debug.command') {
    return toolName
  }

  const delegatedTool = args.tool
  return typeof delegatedTool === 'string' && delegatedTool.trim().length > 0
    ? delegatedTool
    : toolName
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
