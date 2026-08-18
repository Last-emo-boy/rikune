/**
 * MCP Registry — centralized registration of tools, prompts, and resources.
 */

import type { Tool, Prompt, TextContent } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import type pino from 'pino'
import type {
  ToolDefinition,
  ToolAnnotations,
  ToolArgs,
  WorkerResult,
  PromptDefinition,
  PromptArgs,
  PromptResult,
} from '../types.js'
import { zodToJsonSchema } from './zod-schema-converter.js'
import { toTransportToolName, buildToolNameMappings } from './tool-name-normalization.js'

type ToolHandler = (args: ToolArgs) => Promise<WorkerResult | ToolResult>
type PromptHandler = (args: PromptArgs) => Promise<PromptResult>

/**
 * Tool result function type - can return either WorkerResult or ToolResult
 */
type ToolResult = {
  content: TextContent[]
  structuredContent?: Record<string, unknown>
  isError?: boolean
}

/**
 * Derive MCP tool annotations from an explicit definition or from the tool's
 * runtime policy / worker backend contract. Explicit annotations always win;
 * derived hints are only added when the tool does not provide its own.
 *
 * Mapping:
 *   passiveByDefault / noMutation  → readOnlyHint: true
 *   !noMutation                    → destructiveHint: true
 *   noLiveExecution && !noMutation → idempotentHint: true (re-runs are safe)
 *   !noNetwork                     → openWorldHint: true
 */
function deriveToolAnnotations(definition: ToolDefinition): ToolAnnotations | undefined {
  const explicit = definition.annotations
  const policy = definition.runtimePolicy
  const worker = definition.workerBackend
  const derivedPolicy = policy ?? worker?.policy

  if (!derivedPolicy) {
    return explicit
  }

  const derived: ToolAnnotations = {}
  if (derivedPolicy.passiveByDefault || derivedPolicy.noMutation) {
    derived.readOnlyHint = true
  } else {
    derived.destructiveHint = true
  }
  if (derivedPolicy.noLiveExecution && derivedPolicy.noMutation) {
    derived.idempotentHint = true
  }
  if (derivedPolicy.noNetwork === false) {
    derived.openWorldHint = true
  }

  // Explicit annotations take precedence over derived hints.
  if (!explicit) {
    return derived
  }
  return {
    ...derived,
    ...explicit,
  }
}

export class MCPRegistry {
  private logger: pino.Logger
  private tools: Map<string, ToolDefinition>
  private canonicalToolDefinitions: Map<string, ToolDefinition>
  private toolAliases: Map<string, string>
  private handlers: Map<string, ToolHandler>
  private prompts: Map<string, PromptDefinition>
  private promptHandlers: Map<string, PromptHandler>
  private resources: Map<
    string,
    { uri: string; name: string; description?: string; mimeType?: string }
  >
  private resourceHandlers: Map<
    string,
    () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>
  >
  private resourceTemplates: Map<
    string,
    {
      uriTemplate: string
      name: string
      description?: string
      mimeType?: string
    }
  >
  private completionProviders: Map<
    string,
    (value: string, context?: Record<string, unknown>) => Promise<string[]>
  >
  private resourceSubscriptions: Set<string>

  /**
   * Tool names that are sample-ingestion entry points themselves and should
   * NOT receive the "upload first" prerequisite hint.
   */
  private static readonly SAMPLE_ENTRY_TOOLS = new Set([
    'sample.request_upload',
    'sample.ingest',
    'sample.profile.get',
    'workflow.search',
    'workflow.run',
    'artifact.read',
    'tool.help',
  ])

  private static readonly SAMPLE_PREREQUISITE_HINT =
    '\n\nPrerequisite: before calling this tool you MUST obtain a sample_id. ' +
    'Call workflow.run action=request_upload first to get an upload URL, POST the file bytes to that URL, ' +
    'then use the returned sample_id with workflow.run action=start. ' +
    'If the file is already on the server filesystem, use workflow.search to find the hidden sample.ingest compatibility path.'

  constructor(logger: pino.Logger) {
    this.logger = logger
    this.tools = new Map()
    this.canonicalToolDefinitions = new Map()
    this.toolAliases = new Map()
    this.handlers = new Map()
    this.prompts = new Map()
    this.promptHandlers = new Map()
    this.resources = new Map()
    this.resourceHandlers = new Map()
    this.resourceTemplates = new Map()
    this.completionProviders = new Map()
    this.resourceSubscriptions = new Set()
  }

  /**
   * Register a tool with its definition and handler
   */
  registerTool(definition: ToolDefinition, handler: ToolHandler): void {
    const canonicalName = definition.name
    const transportName = toTransportToolName(canonicalName)
    const existingTransport = this.tools.get(transportName)

    if (this.canonicalToolDefinitions.has(canonicalName)) {
      throw new Error(`Tool already registered: ${canonicalName}`)
    }

    if (existingTransport) {
      throw new Error(`Tool name collision while registering ${canonicalName} as ${transportName}`)
    }

    this.logger.info({ tool: canonicalName, transport_tool: transportName }, 'Registering tool')
    this.canonicalToolDefinitions.set(canonicalName, definition)
    this.tools.set(transportName, { ...definition, canonicalName, name: transportName })
    this.toolAliases.set(canonicalName, transportName)
    this.toolAliases.set(transportName, transportName)
    this.handlers.set(transportName, handler)
  }

  /**
   * Unregister a tool by its canonical name (used by plugin hot-unload).
   */
  unregisterTool(canonicalName: string): void {
    const transportName = this.toolAliases.get(canonicalName)
    if (!transportName) return
    this.logger.info({ tool: canonicalName }, 'Unregistering tool')
    this.canonicalToolDefinitions.delete(canonicalName)
    this.tools.delete(transportName)
    this.toolAliases.delete(canonicalName)
    this.toolAliases.delete(transportName)
    this.handlers.delete(transportName)
  }

  /**
   * Register a prompt with its definition and handler
   */
  registerPrompt(definition: PromptDefinition, handler: PromptHandler): void {
    this.logger.info({ prompt: definition.name }, 'Registering prompt')
    this.prompts.set(definition.name, definition)
    this.promptHandlers.set(definition.name, handler)
  }

  /**
   * Register an MCP resource (read-only content exposed to clients).
   */
  registerResource(
    meta: { uri: string; name: string; description?: string; mimeType?: string },
    handler: () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>
  ): void {
    this.logger.info({ resource: meta.uri }, 'Registering resource')
    this.resources.set(meta.uri, meta)
    this.resourceHandlers.set(meta.uri, handler)
  }

  /**
   * Register a resource template (parameterized URI template per MCP spec).
   */
  registerResourceTemplate(meta: {
    uriTemplate: string
    name: string
    description?: string
    mimeType?: string
  }): void {
    this.logger.info({ template: meta.uriTemplate }, 'Registering resource template')
    this.resourceTemplates.set(meta.uriTemplate, meta)
  }

  /**
   * Register a completion provider for a prompt argument or resource URI.
   * The key format: `prompt:{name}:{arg}` or `resource:{uri}`.
   */
  registerCompletionProvider(
    key: string,
    provider: (value: string, context?: Record<string, unknown>) => Promise<string[]>
  ): void {
    this.logger.debug({ key }, 'Registering completion provider')
    this.completionProviders.set(key, provider)
  }

  getCompletionProvider(
    key: string
  ): ((value: string, context?: Record<string, unknown>) => Promise<string[]>) | undefined {
    return this.completionProviders.get(key)
  }

  subscribeToResource(uri: string): void {
    this.resourceSubscriptions.add(uri)
  }

  unsubscribeFromResource(uri: string): void {
    this.resourceSubscriptions.delete(uri)
  }

  isSubscribedToResource(uri: string): boolean {
    return this.resourceSubscriptions.has(uri)
  }

  getResourceSubscriptions(): string[] {
    return Array.from(this.resourceSubscriptions)
  }

  /**
   * Default page size for paginated tools/list responses.
   * When no cursor is supplied, all visible tools are returned (backwards
   * compatible). When a cursor is supplied, results are paged.
   */
  static readonly TOOL_PAGE_SIZE = 100

  /**
   * List all available tools (MCP protocol method) with optional cursor pagination.
   *
   * When cursor is omitted, all visible tools are returned without a nextCursor
   * (backwards compatible with non-paginating clients). When a cursor is
   * provided, a page of tools is returned with a nextCursor if more remain.
   */
  async listTools(
    visibleSet?: Set<string> | null,
    cursor?: string
  ): Promise<{ tools: Tool[]; nextCursor?: string }> {
    const allTools: Tool[] = []

    // Collect the full sorted tool set first so cursor pagination is stable
    // across calls. Map iteration order is insertion order; sort by transport
    // name for deterministic pagination.
    const sortedNames = [...this.tools.keys()].sort()

    for (const name of sortedNames) {
      const definition = this.tools.get(name)
      if (!definition) continue
      // Progressive surface filtering — skip tools not currently visible
      const canonicalName = definition.canonicalName || definition.name
      if (visibleSet && visibleSet.size > 0 && !visibleSet.has(canonicalName)) {
        continue
      }
      // Convert Zod schema to JSON Schema format for MCP protocol
      const inputSchema = zodToJsonSchema(definition.inputSchema)
      const outputSchema = definition.outputSchema
        ? zodToJsonSchema(definition.outputSchema)
        : undefined

      // Derive MCP tool annotations from explicit definition or runtime policy.
      const annotations = deriveToolAnnotations(definition)

      // Append prerequisite hint for tools that require a sample_id input
      const needsHint =
        !MCPRegistry.SAMPLE_ENTRY_TOOLS.has(canonicalName) &&
        this.inputRequiresSampleId(definition.inputSchema)
      const description = needsHint
        ? definition.description + MCPRegistry.SAMPLE_PREREQUISITE_HINT
        : definition.description

      allTools.push({
        name,
        description,
        inputSchema: inputSchema as Tool['inputSchema'],
        ...(outputSchema ? { outputSchema: outputSchema as Tool['outputSchema'] } : {}),
        ...(annotations ? { annotations } : {}),
      })
    }

    // No cursor → return everything (backwards compatible).
    if (cursor === undefined || cursor === null) {
      this.logger.debug({ count: allTools.length }, 'Listed tools (unpaginated)')
      return { tools: allTools }
    }

    // Cursor is an opaque base64-encoded offset into the sorted tool list.
    const offset = MCPRegistry.decodeOffsetCursor(cursor, 'tools/list')
    const pageSize = MCPRegistry.TOOL_PAGE_SIZE
    const page = allTools.slice(offset, offset + pageSize)
    const nextOffset = offset + pageSize
    const nextCursor = nextOffset < allTools.length ? MCPRegistry.encodeOffsetCursor(nextOffset) : undefined

    this.logger.debug(
      { count: page.length, offset, total: allTools.length, hasNext: !!nextCursor },
      'Listed tools (paginated)'
    )
    return { tools: page, nextCursor }
  }

  private static encodeOffsetCursor(offset: number): string {
    return Buffer.from(`offset=${offset}`).toString('base64url')
  }

  private static decodeOffsetCursor(cursor: string, method: string): number {
    try {
      const decoded = Buffer.from(cursor, 'base64url').toString('utf8')
      const match = decoded.match(/^offset=(\d+)$/)
      if (match) {
        const offset = parseInt(match[1], 10)
        if (Number.isFinite(offset) && offset >= 0) {
          return offset
        }
      }
    } catch {
      // fall through to error below
    }
    throw new Error(`Invalid ${method} cursor: ${cursor}`)
  }

  /**
   * List all available prompts (MCP protocol method) with optional cursor pagination.
   * Same backwards-compatible pagination model as listTools.
   */
  async listPrompts(cursor?: string): Promise<{ prompts: Prompt[]; nextCursor?: string }> {
    const prompts: Prompt[] = []

    const sortedNames = [...this.prompts.keys()].sort()
    for (const name of sortedNames) {
      const definition = this.prompts.get(name)
      if (!definition) continue
      prompts.push({
        name,
        title: definition.title,
        description: definition.description,
        arguments: definition.arguments?.map((item) => ({
          name: item.name,
          description: item.description,
          required: item.required,
        })),
      })
    }

    if (cursor === undefined || cursor === null) {
      this.logger.debug({ count: prompts.length }, 'Listed prompts (unpaginated)')
      return { prompts }
    }

    const offset = MCPRegistry.decodeOffsetCursor(cursor, 'prompts/list')
    const pageSize = MCPRegistry.TOOL_PAGE_SIZE
    const page = prompts.slice(offset, offset + pageSize)
    const nextOffset = offset + pageSize
    const nextCursor = nextOffset < prompts.length ? MCPRegistry.encodeOffsetCursor(nextOffset) : undefined

    this.logger.debug(
      { count: page.length, offset, total: prompts.length, hasNext: !!nextCursor },
      'Listed prompts (paginated)'
    )
    return { prompts: page, nextCursor }
  }

  /**
   * Resolve a prompt by name and arguments (MCP protocol method)
   */
  async getPrompt(name: string, args: Record<string, unknown>): Promise<PromptResult> {
    const definition = this.prompts.get(name)
    if (!definition) {
      throw new Error(`Prompt not found: ${name}`)
    }

    const handler = this.promptHandlers.get(name)
    if (!handler) {
      throw new Error(`Handler not found for prompt: ${name}`)
    }

    const validatedArgs = this.validatePromptArgs(definition, args)
    return handler(validatedArgs)
  }

  getToolDefinitions(): ToolDefinition[] {
    return Array.from(this.canonicalToolDefinitions.values())
  }

  getToolDefinition(name: string): ToolDefinition | undefined {
    const transportName = this.resolveToolName(name)
    if (!transportName) {
      return undefined
    }

    const definition = this.tools.get(transportName)
    if (!definition) {
      return undefined
    }

    return this.canonicalToolDefinitions.get(definition.canonicalName || definition.name)
  }

  getPromptDefinitions(): PromptDefinition[] {
    return Array.from(this.prompts.values())
  }

  getPromptDefinition(name: string): PromptDefinition | undefined {
    return this.prompts.get(name)
  }

  resolveToolName(name: string): string | undefined {
    return this.toolAliases.get(name)
  }

  getToolNameMappings(): Array<[string, string]> {
    return buildToolNameMappings(this.canonicalToolDefinitions.keys())
  }

  getHandler(resolvedName: string): ToolHandler | undefined {
    return this.handlers.get(resolvedName)
  }

  getToolDefinitionByTransportName(transportName: string): ToolDefinition | undefined {
    return this.tools.get(transportName)
  }

  getResourceHandler(
    uri: string
  ): (() => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>) | undefined {
    return this.resourceHandlers.get(uri)
  }

  async listResources(cursor?: string): Promise<{ resources: Array<{ uri: string; name: string; description?: string; mimeType?: string }>; nextCursor?: string }> {
    const resources = Array.from(this.resources.values())
    if (cursor === undefined || cursor === null) {
      return { resources }
    }
    const offset = MCPRegistry.decodeOffsetCursor(cursor, 'resources/list')
    const pageSize = MCPRegistry.TOOL_PAGE_SIZE
    const page = resources.slice(offset, offset + pageSize)
    const nextOffset = offset + pageSize
    const nextCursor = nextOffset < resources.length ? MCPRegistry.encodeOffsetCursor(nextOffset) : undefined
    return { resources: page, nextCursor }
  }

  getResources(): Array<{ uri: string; name: string; description?: string; mimeType?: string }> {
    return Array.from(this.resources.values())
  }

  getResourceTemplates(): Array<{
    uriTemplate: string
    name: string
    description?: string
    mimeType?: string
  }> {
    return Array.from(this.resourceTemplates.values())
  }

  /**
   * Detect whether a Zod schema is an object that contains a `sample_id`
   * (or `sample_id_a` / `sample_id_b`) required input field.
   */
  private inputRequiresSampleId(schema: z.ZodTypeAny): boolean {
    if (!(schema instanceof z.ZodObject)) return false
    const shape = schema.shape as Record<string, z.ZodTypeAny>
    return Object.keys(shape).some(
      (k) => k === 'sample_id' || k === 'sample_id_a' || k === 'sample_id_b'
    )
  }

  private validatePromptArgs(
    definition: PromptDefinition,
    args: Record<string, unknown>
  ): PromptArgs {
    const validated: PromptArgs = {}
    const provided = args || {}

    for (const [key, value] of Object.entries(provided)) {
      if (value === undefined || value === null) {
        continue
      }
      validated[key] = String(value)
    }

    for (const item of definition.arguments || []) {
      if (item.required && (!validated[item.name] || validated[item.name].trim().length === 0)) {
        throw new Error(`Missing required prompt argument: ${item.name}`)
      }
    }

    return validated
  }
}
