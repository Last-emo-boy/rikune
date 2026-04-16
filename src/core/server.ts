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
  type CreateMessageRequest,
  type CreateMessageResult,
  type CreateMessageResultWithTools,
  GetPromptRequestSchema,
  type Implementation,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
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
import { FileServer } from '../api/file-server.js'
import { createSampleFinalizationService } from '../sample/sample-finalization.js'
import { getToolSurfaceManager } from './tool-surface-manager.js'
import { MCPRegistry } from './mcp-registry.js'
import { ToolExecutor } from './tool-executor.js'
import type { ApiBootstrapper } from '../api/api-bootstrapper.js'
import type { ToolRegistrar, PromptRegistrar, ResourceRegistrar, SamplingClient, PluginManagerSetter } from './registrar.js'

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
export class MCPServer implements ToolRegistrar, PromptRegistrar, ResourceRegistrar, SamplingClient, PluginManagerSetter {
  private server: Server
  private logger: pino.Logger
  private config: Config
  private httpFileServer: { stop: () => Promise<void> } | null = null
  private dependencies: MCPServerDependencies
  private pluginManager: PluginManager | null = null
  private registry: MCPRegistry
  private executor: ToolExecutor

  constructor(config: Config, dependencies: MCPServerDependencies = {}) {
    // Create logger that writes to stderr to avoid interfering with MCP protocol on stdout
    const destination = pino.destination({ dest: 2, sync: false }) // fd 2 = stderr

    this.config = config
    this.logger = pino({
      level: config.logging.level,
    }, destination)

    this.dependencies = dependencies
    this.registry = new MCPRegistry(this.logger)
    this.executor = new ToolExecutor(this.logger)

    // Initialize MCP SDK server
    this.server = new Server(
      {
        name: 'rikune',
        version: '1.0.0-beta.3',
      },
      {
        capabilities: {
          tools: {},
          prompts: {},
          resources: {},
        },
      }
    )

    this.setupHandlers()
    this.logger.info('MCP Server initialized')
  }

  /**
   * Setup MCP protocol handlers
   */
  private setupHandlers(): void {
    // Handle tools/list request
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      this.logger.debug('Handling tools/list request')
      return {
        tools: await this.listTools(),
      }
    })

    this.server.setRequestHandler(ListPromptsRequestSchema, async () => {
      this.logger.debug('Handling prompts/list request')
      return {
        prompts: await this.listPrompts(),
      }
    })

    this.server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      this.logger.debug({ prompt: request.params.name }, 'Handling prompts/get request')
      return (await this.getPrompt(request.params.name, request.params.arguments || {})) as any
    })

    // Handle tools/call request
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      this.logger.debug({ tool: request.params.name }, 'Handling tools/call request')
      const progressToken = request.params._meta?.progressToken
      const result = await this.callTool(request.params.name, request.params.arguments || {}, progressToken)
      return result
    })

    // Handle resources/list request
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      this.logger.debug('Handling resources/list request')
      return {
        resources: this.registry.getResources(),
      }
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
    meta: { uri: string; name: string; description?: string; mimeType?: string },
    handler: () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>,
  ): void {
    this.registry.registerResource(meta, handler)
  }

  /**
   * Inject the PluginManager reference so callTool can fire lifecycle hooks.
   */
  public setPluginManager(mgr: PluginManager): void {
    this.pluginManager = mgr

    // Wire progressive surface notification so clients refresh their tool list
    const surface = getToolSurfaceManager()
    surface.setNotifyCallback(() => {
      try {
        this.server.sendToolListChanged()
      } catch (e) { this.logger.debug({ err: e }, 'Tool list change notification failed (best-effort)') }
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
   * List all available tools (MCP protocol method)
   */
  public async listTools(): Promise<any[]> {
    const surface = getToolSurfaceManager()
    const visibleSet = surface.isEnabled() ? surface.getVisibleToolNames() : null
    return this.registry.listTools(visibleSet)
  }

  /**
   * List all available prompts (MCP protocol method)
   */
  public async listPrompts(): Promise<any[]> {
    return this.registry.listPrompts()
  }

  /**
   * Call a tool by name with arguments (MCP protocol method)
   */
  public async callTool(name: string, args: unknown, progressToken?: string | number): Promise<CallToolResult> {
    return this.executor.executeTool(name, args, {
      registry: this.registry,
      pluginRuntime: this.pluginManager ?? undefined,
      logger: this.logger,
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
   */
  public async createMessage(
    params: CreateMessageRequest['params']
  ): Promise<CreateMessageResult | CreateMessageResultWithTools> {
    return this.server.createMessage(params)
  }

  /**
   * Get logger instance
   */
  public getLogger(): pino.Logger {
    return this.logger
  }
}
