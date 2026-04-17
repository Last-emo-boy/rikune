/**
 * MCP Registry — centralized registration of tools, prompts, and resources.
 */

import type { Tool, Prompt, TextContent } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import type pino from 'pino'
import type {
  ToolDefinition,
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
type ToolResult = { content: TextContent[]; structuredContent?: Record<string, unknown>; isError?: boolean }

export class MCPRegistry {
  private logger: pino.Logger
  private tools: Map<string, ToolDefinition>
  private canonicalToolDefinitions: Map<string, ToolDefinition>
  private toolAliases: Map<string, string>
  private handlers: Map<string, ToolHandler>
  private prompts: Map<string, PromptDefinition>
  private promptHandlers: Map<string, PromptHandler>
  private resources: Map<string, { uri: string; name: string; description?: string; mimeType?: string }>
  private resourceHandlers: Map<string, () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>>

  /**
   * Tool names that are sample-ingestion entry points themselves and should
   * NOT receive the "upload first" prerequisite hint.
   */
  private static readonly SAMPLE_ENTRY_TOOLS = new Set([
    'sample.request_upload',
    'sample.ingest',
    'sample.profile.get',
    'tool.help',
  ])

  private static readonly SAMPLE_PREREQUISITE_HINT =
    '\n\nPrerequisite: before calling this tool you MUST obtain a sample_id. ' +
    'Call sample.request_upload first to get an upload URL, POST the file bytes to that URL, ' +
    'then use the returned sample_id. ' +
    'If the file is already on the server filesystem, use sample.ingest(path) instead.'

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
  }

  /**
   * Register a tool with its definition and handler
   */
  registerTool(definition: ToolDefinition, handler: ToolHandler): void {
    const canonicalName = definition.name
    const transportName = toTransportToolName(canonicalName)
    const existingTransport = this.tools.get(transportName)

    if (existingTransport && existingTransport.canonicalName !== canonicalName) {
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
    handler: () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>,
  ): void {
    this.logger.info({ resource: meta.uri }, 'Registering resource')
    this.resources.set(meta.uri, meta)
    this.resourceHandlers.set(meta.uri, handler)
  }

  /**
   * List all available tools (MCP protocol method)
   */
  async listTools(visibleSet?: Set<string> | null): Promise<Tool[]> {
    const tools: Tool[] = []

    for (const [name, definition] of this.tools.entries()) {
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

      // Append prerequisite hint for tools that require a sample_id input
      const needsHint =
        !MCPRegistry.SAMPLE_ENTRY_TOOLS.has(canonicalName) &&
        this.inputRequiresSampleId(definition.inputSchema)
      const description = needsHint
        ? definition.description + MCPRegistry.SAMPLE_PREREQUISITE_HINT
        : definition.description

      tools.push({
        name,
        description,
        inputSchema: inputSchema as Tool['inputSchema'],
        ...(outputSchema ? { outputSchema: outputSchema as Tool['outputSchema'] } : {}),
      })
    }

    this.logger.debug({ count: tools.length }, 'Listed tools')
    return tools
  }

  /**
   * List all available prompts (MCP protocol method)
   */
  async listPrompts(): Promise<Prompt[]> {
    const prompts: Prompt[] = []

    for (const [name, definition] of this.prompts.entries()) {
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

    this.logger.debug({ count: prompts.length }, 'Listed prompts')
    return prompts
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

  getResourceHandler(uri: string): (() => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>) | undefined {
    return this.resourceHandlers.get(uri)
  }

  getResources(): Array<{ uri: string; name: string; description?: string; mimeType?: string }> {
    return Array.from(this.resources.values())
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
