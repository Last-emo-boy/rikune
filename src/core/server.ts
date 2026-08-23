/**
 * MCP Server implementation
 * Implements the Model Context Protocol with JSON-RPC 2.0 message handling
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  type CallToolResult,
  type ClientCapabilities,
  CompleteRequestSchema,
  type CreateMessageRequest,
  type CreateMessageResult,
  type CreateMessageResultWithTools,
  type ElicitResult,
  GetPromptRequestSchema,
  type Implementation,
  type LoggingLevel,
  type LoggingMessageNotification,
  ListPromptsRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  SetLevelRequestSchema,
  SubscribeRequestSchema,
  UnsubscribeRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'
import pino from 'pino'
import { createProgressReporter, type ProgressReporter } from '../streaming-progress.js'
import type { PluginManager } from './plugins.js'
import type { Config } from '../config.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { PolicyGuard } from '../policy-guard.js'
import type { StorageManager } from '../storage/storage-manager.js'
import type { ToolDefinition, PromptDefinition } from '../types.js'
import type {
  ElicitationClient,
  ResourceRegistrar,
  SamplingClient,
  PluginManagerSetter,
  ToolRegistrar,
  PromptRegistrar,
} from './registrar.js'
import { FileServer } from '../api/file-server.js'
import { createSampleFinalizationService } from '../sample/sample-finalization.js'
import { getToolSurfaceManager } from './tool-surface-manager.js'
import { MCPRegistry } from './mcp-registry.js'
import { ToolExecutor } from './tool-executor.js'
import type { ApiBootstrapper } from '../api/api-bootstrapper.js'
import { RIKUNE_VERSION } from '../version.js'

interface MCPServerDependencies {
  workspaceManager?: WorkspaceManager
  database?: DatabaseManager
  policyGuard?: PolicyGuard
  storageManager?: StorageManager
  apiBootstrapper?: ApiBootstrapper
}

/**
 * MCP Server class implementing the Model Context Protocol
 */
export class MCPServer
  implements
    ToolRegistrar,
    PromptRegistrar,
    ResourceRegistrar,
    SamplingClient,
    ElicitationClient,
    PluginManagerSetter
{
  private server: Server
  private logger: pino.Logger
  private config: Config
  private httpFileServer: { stop: () => Promise<void> } | null = null
  private dependencies: MCPServerDependencies
  private pluginManager: PluginManager | null = null
  private registry: MCPRegistry
  private executor: ToolExecutor
  private clientLogLevel: LoggingLevel | null = null
  /**
   * Whether the MCP client has sent the `initialized` notification,
   * completing the MCP handshake. List-changed notifications are only
   * sent after this becomes true to avoid sending to an unready client.
   */
  private clientInitialized = false

  constructor(config: Config, dependencies: MCPServerDependencies = {}) {
    // Create logger that writes to stderr to avoid interfering with MCP protocol on stdout
    const destination = pino.destination({ dest: 2, sync: false }) // fd 2 = stderr

    this.config = config
    this.logger = pino(
      {
        level: config.logging.level,
      },
      destination
    )

    this.dependencies = dependencies
    this.registry = new MCPRegistry(this.logger)
    this.executor = new ToolExecutor(this.logger)

    // Initialize MCP SDK server
    this.server = new Server(
      {
        name: 'rikune',
        version: RIKUNE_VERSION,
        title: 'Rikune Reverse Analysis Platform',
      },
      {
        capabilities: {
          tools: { listChanged: true },
          prompts: {},
          resources: { listChanged: true, subscribe: true },
          completions: {},
          logging: {},
        },
        instructions:
          'Rikune is a reverse-analysis MCP platform. Use workflow_search for capability discovery, ' +
          'workflow_run for analyzer execution (request_upload → start → status → promote), ' +
          'and artifact_read for persisted evidence. Do not call low-level analyzer tools directly.',
      }
    )

    // Track MCP handshake completion: the SDK fires `oninitialized` when
    // the client sends `notifications/initialized`. We gate list-changed
    // notifications on this flag to avoid notifying an unready client.
    this.server.oninitialized = () => {
      this.clientInitialized = true
      this.logger.debug('MCP client handshake completed (initialized received)')
    }

    this.setupHandlers()
    this.logger.info('MCP Server initialized')
  }

  /**
   * Setup MCP protocol handlers
   */
  private setupHandlers(): void {
    // Handle tools/list request
    this.server.setRequestHandler(ListToolsRequestSchema, async (request) => {
      this.logger.debug('Handling tools/list request')
      const cursor = request.params?.cursor
      return await this.listTools(cursor)
    })

    this.server.setRequestHandler(ListPromptsRequestSchema, async (request) => {
      this.logger.debug('Handling prompts/list request')
      const cursor = request.params?.cursor
      return await this.listPrompts(cursor)
    })

    this.server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      this.logger.debug({ prompt: request.params.name }, 'Handling prompts/get request')
      return await this.getPrompt(request.params.name, request.params.arguments || {})
    })

    // Handle tools/call request
    this.server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      this.logger.debug({ tool: request.params.name }, 'Handling tools/call request')
      const progressToken = request.params._meta?.progressToken
      const result = await this.callTool(
        request.params.name,
        request.params.arguments || {},
        progressToken,
        extra?.signal
      )
      return result
    })

    // Handle resources/list request
    this.server.setRequestHandler(ListResourcesRequestSchema, async (request) => {
      this.logger.debug('Handling resources/list request')
      const cursor = request.params?.cursor
      return await this.listResources(cursor)
    })

    // Handle resources/read request
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const uri = request.params.uri
      this.logger.debug({ uri }, 'Handling resources/read request')
      const handler = this.registry.getResourceHandler(uri)
      if (!handler) {
        throw new Error(`Resource not found: ${uri}`)
      }
      const content = await handler()
      return { contents: [content] }
    })

    // Handle resources/templates/list request (with cursor pagination)
    this.server.setRequestHandler(ListResourceTemplatesRequestSchema, async (request) => {
      const cursor = request.params?.cursor
      this.logger.debug({ cursor: cursor ?? null }, 'Handling resources/templates/list request')
      const { resourceTemplates, nextCursor } = await this.registry.listResourceTemplates(cursor)
      return {
        resourceTemplates,
        ...(nextCursor ? { nextCursor } : {}),
      }
    })

    // Handle resources/subscribe request
    this.server.setRequestHandler(SubscribeRequestSchema, async (request) => {
      const uri = request.params.uri
      this.logger.debug({ uri }, 'Handling resources/subscribe request')
      this.registry.subscribeToResource(uri)
      return {}
    })

    // Handle resources/unsubscribe request
    this.server.setRequestHandler(UnsubscribeRequestSchema, async (request) => {
      const uri = request.params.uri
      this.logger.debug({ uri }, 'Handling resources/unsubscribe request')
      this.registry.unsubscribeFromResource(uri)
      return {}
    })

    // Handle completion/complete request
    this.server.setRequestHandler(CompleteRequestSchema, async (request) => {
      const { ref, argument, context } = request.params
      this.logger.debug({ ref, argument }, 'Handling completion/complete request')

      let key: string
      if (ref.type === 'ref/prompt') {
        key = `prompt:${ref.name}:${argument.name}`
      } else {
        key = `resource:${ref.uri}`
      }

      const provider = this.registry.getCompletionProvider(key)
      if (!provider) {
        return { completion: { values: [], total: 0, hasMore: false } }
      }

      const values = await provider(
        argument.value,
        context?.arguments as Record<string, unknown> | undefined
      )
      return {
        completion: {
          values: values.slice(0, 100),
          total: values.length,
          hasMore: values.length > 100,
        },
      }
    })

    // Handle logging/setLevel request
    this.server.setRequestHandler(SetLevelRequestSchema, async (request) => {
      const level = request.params.level
      this.logger.debug({ level }, 'Setting client log level')
      this.clientLogLevel = level
      return {}
    })
  }

  /**
   * Minimum log level below which messages should not be forwarded to the
   * client. When the client has not called logging/setLevel, all levels
   * are forwarded (null = no filter).
   */
  private static readonly LOG_LEVEL_ORDER: LoggingLevel[] = [
    'debug',
    'info',
    'notice',
    'warning',
    'error',
    'critical',
    'alert',
    'emergency',
  ]

  private shouldForwardLogLevel(level: LoggingLevel): boolean {
    if (!this.clientLogLevel) return true
    const minIdx = MCPServer.LOG_LEVEL_ORDER.indexOf(this.clientLogLevel)
    const msgIdx = MCPServer.LOG_LEVEL_ORDER.indexOf(level)
    if (minIdx === -1 || msgIdx === -1) return true
    return msgIdx >= minIdx
  }

  /**
   * Send a log message notification to the connected client.
   * Respects the minimum log level configured by the client via logging/setLevel.
   */
  public async sendLogMessage(level: LoggingLevel, data: unknown, logger?: string): Promise<void> {
    if (!this.shouldForwardLogLevel(level)) return
    const params: LoggingMessageNotification['params'] = {
      level,
      data: data as any,
    }
    if (logger) {
      params.logger = logger
    }
    await this.server.sendLoggingMessage(params)
  }

  /**
   * Register a tool with its definition and handler
   */
  public registerTool(definition: ToolDefinition, handler: any): void {
    this.registry.registerTool(definition, handler)
  }

  /**
   * Unregister a tool by its canonical name (used by plugin hot-unload).
   */
  public unregisterTool(canonicalName: string): void {
    this.registry.unregisterTool(canonicalName)
  }

  /**
   * Register a prompt with its definition and handler
   */
  public registerPrompt(definition: PromptDefinition, handler: any): void {
    this.registry.registerPrompt(definition, handler)
  }

  /**
   * Register an MCP resource (read-only content exposed to clients).
   */
  public registerResource(
    meta: {
      uri: string
      name: string
      title?: string
      description?: string
      mimeType?: string
      size?: number
      annotations?: {
        audience?: Array<'user' | 'assistant'>
        priority?: number
        lastModified?: string
      }
    },
    handler: () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>
  ): void {
    this.registry.registerResource(meta, handler)
  }

  /**
   * Register a resource template (parameterized URI per MCP spec).
   */
  public registerResourceTemplate(meta: {
    uriTemplate: string
    name: string
    title?: string
    description?: string
    mimeType?: string
    annotations?: {
      audience?: Array<'user' | 'assistant'>
      priority?: number
      lastModified?: string
    }
  }): void {
    this.registry.registerResourceTemplate(meta)
  }

  /**
   * Register a completion provider (MCP completion/complete handler).
   */
  public registerCompletionProvider(
    key: string,
    provider: (value: string, context?: Record<string, unknown>) => Promise<string[]>
  ): void {
    this.registry.registerCompletionProvider(key, provider)
  }

  /**
   * Get a registered completion provider by key.
   */
  public getCompletionProvider(
    key: string
  ): ((value: string, context?: Record<string, unknown>) => Promise<string[]>) | undefined {
    return this.registry.getCompletionProvider(key)
  }

  /**
   * Inject the PluginManager reference so callTool can fire lifecycle hooks.
   */
  public setPluginManager(mgr: PluginManager): void {
    this.pluginManager = mgr

    // Wire progressive surface notification so clients refresh their tool list.
    // Only notify after the MCP handshake is complete; sending a notification
    // to a client that hasn't sent `initialized` is a protocol violation.
    const surface = getToolSurfaceManager()
    surface.setNotifyCallback(() => {
      if (!this.clientInitialized) return
      // sendToolListChanged() returns a Promise; catch rejections to avoid
      // unhandled promise rejection (sync try/catch only catches sync throws).
      this.server.sendToolListChanged().catch((e) => {
        this.logger.debug({ err: e }, 'Tool list change notification failed (best-effort)')
      })
    })
  }

  public getProgressReporter(progressToken?: string | number): ProgressReporter {
    return createProgressReporter(this.server, progressToken)
  }

  public getToolDefinitions(): ToolDefinition[] {
    return this.registry.getToolDefinitions()
  }

  public getToolDefinition(name: string): ToolDefinition | undefined {
    return this.registry.getToolDefinition(name)
  }

  public getPromptDefinitions(): PromptDefinition[] {
    return this.registry.getPromptDefinitions()
  }

  public getPromptDefinition(name: string): PromptDefinition | undefined {
    return this.registry.getPromptDefinition(name)
  }

  /**
   * List all available tools (MCP protocol method) with optional cursor pagination.
   * When cursor is omitted, all visible tools are returned without a nextCursor
   * (backwards compatible). When cursor is provided, a page of tools is returned
   * with a nextCursor if more tools remain.
   */
  public async listTools(cursor?: string): Promise<{ tools: any[]; nextCursor?: string }> {
    const surface = getToolSurfaceManager()
    const visibleSet = surface.isEnabled() ? surface.getVisibleToolNames() : null
    return this.registry.listTools(visibleSet, cursor)
  }

  /**
   * List all available prompts (MCP protocol method) with optional cursor pagination.
   */
  public async listPrompts(cursor?: string): Promise<{ prompts: any[]; nextCursor?: string }> {
    return this.registry.listPrompts(cursor)
  }

  /**
   * List all registered resources (MCP protocol method) with optional cursor pagination.
   */
  public async listResources(cursor?: string): Promise<{ resources: any[]; nextCursor?: string }> {
    return this.registry.listResources(cursor)
  }

  /**
   * List all registered resource templates (MCP protocol method)
   */
  public getResourceTemplates(): any[] {
    return this.registry.getResourceTemplates()
  }

  /**
   * Subscribe to resource change notifications (MCP protocol method).
   */
  public async subscribeToResource(uri: string): Promise<void> {
    this.registry.subscribeToResource(uri)
  }

  /**
   * Unsubscribe from resource change notifications.
   */
  public async unsubscribeFromResource(uri: string): Promise<void> {
    this.registry.unsubscribeFromResource(uri)
  }

  /**
   * Notify subscribed clients that a resource has changed.
   * Only sends the notification if a client has previously subscribed
   * to the given URI via resources/subscribe.
   */
  public async notifyResourceUpdated(uri: string): Promise<void> {
    if (!this.clientInitialized) return
    if (!this.registry.isSubscribedToResource(uri)) return
    await this.server.sendResourceUpdated({ uri })
  }

  /**
   * Notify clients that the list of available resources has changed.
   * Only sent after the MCP handshake is complete.
   */
  public async notifyResourceListChanged(): Promise<void> {
    if (!this.clientInitialized) return
    await this.server.sendResourceListChanged()
  }

  /**
   * Call a tool by name with arguments (MCP protocol method)
   */
  public async callTool(
    name: string,
    args: unknown,
    progressToken?: string | number,
    signal?: AbortSignal
  ): Promise<CallToolResult> {
    return this.executor.executeTool(name, args, {
      registry: this.registry,
      pluginRuntime: this.pluginManager ?? undefined,
      logger: this.logger,
      signal,
    })
  }

  /**
   * Resolve a prompt by name and arguments (MCP protocol method)
   */
  public async getPrompt(name: string, args: Record<string, unknown>): Promise<any> {
    return this.registry.getPrompt(name, args)
  }

  /**
   * Start the MCP server with stdio transport
   */
  public async start(): Promise<void> {
    this.logger.info('Starting MCP Server with stdio transport')

    const transport = new StdioServerTransport()
    await this.server.connect(transport)

    this.logger.info('MCP Server started and listening on stdio')

    // Start HTTP File Server if enabled
    if (this.config.api?.enabled) {
      try {
        await this.startHttpFileServer()
      } catch (error) {
        this.logger.error('Failed to start HTTP File Server: ' + JSON.stringify(error))
      }
    }
  }

  /**
   * Start HTTP File Server
   */
  private async startHttpFileServer(): Promise<void> {
    const workspaceManager =
      this.dependencies.workspaceManager ||
      new (await import('../workspace-manager.js')).WorkspaceManager(this.config.workspace.root)
    const database =
      this.dependencies.database ||
      new (await import('../database.js')).DatabaseManager(this.config.database.path)
    const policyGuard =
      this.dependencies.policyGuard ||
      new (await import('../policy-guard.js')).PolicyGuard(this.config.logging.auditPath)
    const storageManager =
      this.dependencies.storageManager ||
      new (await import('../storage/storage-manager.js')).StorageManager({
        root: this.config.api.storageRoot,
        maxFileSize: this.config.api.maxFileSize,
        retentionDays: this.config.api.retentionDays,
      })

    await storageManager.initialize()

    const finalizationService = createSampleFinalizationService(
      workspaceManager,
      database,
      policyGuard
    )

    const fileServer = new FileServer(
      {
        port: this.config.api.port || 18080,
        apiKey: this.config.api.apiKey,
        maxFileSize: this.config.api.maxFileSize || 500 * 1024 * 1024,
      },
      {
        storageManager,
        database,
        workspaceManager,
        finalizationService,
      }
    )

    await this.dependencies.apiBootstrapper?.bootstrap({
      server: this,
      database,
      workspaceManager,
      storageManager,
      fileServer,
    })

    await fileServer.start()
    this.httpFileServer = fileServer
    this.logger.info(`HTTP File Server started on port ${fileServer.getPort()}`)
    this.logger.info(`Dashboard available at http://localhost:${fileServer.getPort()}/dashboard`)
  }

  /**
   * Stop the MCP server
   */
  public async stop(): Promise<void> {
    this.logger.info('Stopping MCP Server')
    if (this.httpFileServer) {
      await this.httpFileServer.stop()
      this.httpFileServer = null
    }
    await this.server.close()
    this.logger.info('MCP Server stopped')
  }

  /**
   * Get server instance for testing
   */
  public getServer(): Server {
    return this.server
  }

  /**
   * Get the server info (name, version, title) advertised in the initialize
   * response.
   */
  public getServerInfo(): { name: string; version: string; title?: string } {
    // SDK stores serverInfo as a private field; access via the same pattern
    // used by getClientVersion/getClientCapabilities.
    return (
      this.server as unknown as { _serverInfo: { name: string; version: string; title?: string } }
    )._serverInfo
  }

  /**
   * Get the server instructions advertised in the initialize response.
   */
  public getInstructions(): string | undefined {
    return (this.server as unknown as { _instructions?: string })._instructions
  }

  /**
   * Get connected client capabilities after MCP initialization.
   */
  public getClientCapabilities(): ClientCapabilities | undefined {
    return this.server.getClientCapabilities()
  }

  /**
   * Get connected client implementation info after MCP initialization.
   */
  public getClientVersion(): Implementation | undefined {
    return this.server.getClientVersion()
  }

  /**
   * Whether the connected MCP client advertised sampling support.
   */
  public supportsSampling(): boolean {
    return Boolean(this.getClientCapabilities()?.sampling)
  }

  /**
   * Request client-mediated MCP sampling from the connected client.
   * Throws if the connected client did not advertise sampling support.
   */
  public async createMessage(
    params: CreateMessageRequest['params']
  ): Promise<CreateMessageResult | CreateMessageResultWithTools> {
    if (!this.supportsSampling()) {
      throw new Error(
        'Client does not support sampling; cannot create message. ' +
          'The connected MCP client did not advertise sampling capability.'
      )
    }
    return this.server.createMessage(params)
  }

  /**
   * Whether the connected MCP client advertised elicitation support.
   */
  public supportsElicitation(): boolean {
    return Boolean(this.getClientCapabilities()?.elicitation)
  }

  /**
   * Request additional information from the user via client-mediated elicitation.
   * Returns the user's action (accept/decline/cancel) and content if accepted.
   */
  public async elicit(params: Record<string, unknown>): Promise<ElicitResult> {
    if (!this.supportsElicitation()) {
      return { action: 'decline' }
    }
    return await this.server.elicitInput(params as any)
  }

  /**
   * Get logger instance
   */
  public getLogger(): pino.Logger {
    return this.logger
  }

  /**
   * Whether the MCP client has completed the handshake by sending the
   * `initialized` notification.
   */
  public isClientInitialized(): boolean {
    return this.clientInitialized
  }
}
