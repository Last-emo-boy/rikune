/**
 * Tool Executor — tool call execution pipeline.
 */

import type { CallToolResult, TextContent } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import type pino from 'pino'
import type { ToolArgs, WorkerResult } from '../types.js'
import { generateSchemaExample } from './zod-schema-converter.js'
import { guardResponseSize } from './response-guard.js'
import {
  rewriteToolReferencesInValue,
  rewriteToolReferencesInText,
} from './tool-name-normalization.js'
import { getToolSurfaceManager } from './tool-surface-manager.js'
import type { MCPRegistry } from './mcp-registry.js'

export interface PluginRuntimeLike {
  fireHook(
    phase: 'before' | 'after' | 'error',
    toolName: string,
    args: Record<string, unknown>,
    extra?: { elapsedMs?: number; error?: unknown }
  ): Promise<void>
}

export interface ExecuteToolOptions {
  registry: MCPRegistry
  pluginRuntime?: PluginRuntimeLike
  logger: pino.Logger
}

/**
 * Tool result function type - can return either WorkerResult or ToolResult
 */
type ToolResult = { content: TextContent[]; structuredContent?: Record<string, unknown>; isError?: boolean }

export class ToolExecutor {
  private logger: pino.Logger

  constructor(logger: pino.Logger) {
    this.logger = logger
  }

  async executeTool(
    name: string,
    args: unknown,
    options: ExecuteToolOptions
  ): Promise<CallToolResult> {
    const { registry, pluginRuntime } = options
    const startTime = Date.now()
    this.logger.info({ tool: name, args }, 'Calling tool')

    try {
      const resolvedName = registry.resolveToolName(name)

      // Check if tool exists
      const definition = resolvedName ? registry.getToolDefinitionByTransportName(resolvedName) : undefined
      if (!definition) {
        throw new Error(`Tool not found: ${name}`)
      }

      // Validate input arguments
      const validatedArgs = this.validateArgs(definition.inputSchema, args)

      // Get handler
      const handler = registry.getHandler(resolvedName)
      if (!handler) {
        throw new Error(`Handler not found for tool: ${name}`)
      }

      // Fire plugin before-hook (best effort, non-blocking on failure)
      const canonicalName = definition.canonicalName || definition.name
      if (pluginRuntime) {
        await pluginRuntime.fireHook('before', canonicalName, validatedArgs as Record<string, unknown>)
      }

      // Execute handler
      const result = await handler(validatedArgs)

      const elapsed = Date.now() - startTime

      // Fire plugin after-hook
      if (pluginRuntime) {
        await pluginRuntime.fireHook('after', canonicalName, validatedArgs as Record<string, unknown>, { elapsedMs: elapsed })
      }

      // Progressive surface — scan result for activation signals
      try {
        const surface = getToolSurfaceManager()
        if (surface.isEnabled()) {
          const workerData = 'content' in result ? undefined : result
          if (workerData) surface.processToolResult(canonicalName, workerData)
        }
      } catch (e) { this.logger.debug({ err: e }, 'Surface expansion failed (best-effort)') }

      // Check if result is ToolResult or WorkerResult
      if ('content' in result) {
        // It's a ToolResult - use directly
        const structuredContent = this.normalizeStructuredContent(
          this.rewriteToolReferences(result.structuredContent, registry),
          definition.outputSchema
        )
        this.logger.info({ tool: name, elapsed, isError: result.isError }, 'Tool execution completed')
        return guardResponseSize({
          content: this.rewriteTextContentItems(result.content as TextContent[], registry) as any,
          structuredContent,
          isError: result.isError
        }, this.logger)
      } else {
        // It's a WorkerResult - convert to ToolResult
        this.logger.info({ tool: name, elapsed, ok: result.ok }, 'Tool execution completed')
        return guardResponseSize(this.workerResultToToolResult(result, definition.outputSchema, registry), this.logger)
      }
    } catch (error) {
      const elapsed = Date.now() - startTime
      this.logger.error({ tool: name, elapsed, error }, 'Tool execution failed')

      // Fire plugin error-hook
      if (pluginRuntime) {
        await pluginRuntime.fireHook('error', name, (args ?? {}) as Record<string, unknown>, { error }).catch(() => {})
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              ok: false,
              errors: [(error as Error).message],
            }),
          },
        ],
        isError: true,
      }
    }
  }

  /**
   * Validate tool arguments against schema
   * Provides clear error messages with field paths and validation details
   */
  private validateArgs(schema: z.ZodTypeAny, args: unknown): ToolArgs {
    try {
      return schema.parse(args) as ToolArgs
    } catch (error) {
      if (error instanceof z.ZodError) {
        // Build detailed validation error message
        const errorDetails = error.errors.map((e) => {
          const path = e.path.length > 0 ? e.path.join('.') : 'root'
          return `  - ${path}: ${e.message}`
        })

        // Generate example based on schema
        const example = generateSchemaExample(schema)
        const exampleStr = example ? `\n\nExample:\n${JSON.stringify(example, null, 2)}` : ''

        throw new Error(
          `Invalid arguments:\n${errorDetails.join('\n')}${exampleStr}`
        )
      }
      throw error
    }
  }

  /**
   * Convert worker result to MCP tool result
   */
  private workerResultToToolResult(result: WorkerResult, outputSchema: z.ZodTypeAny | undefined, registry: MCPRegistry): CallToolResult {
    const content: TextContent[] = []
    const structuredPayload = this.rewriteToolReferences<Record<string, unknown>>({
      ok: result.ok,
      ...(result.data !== undefined ? { data: result.data } : {}),
      ...(result.warnings !== undefined ? { warnings: result.warnings } : {}),
      ...(result.errors !== undefined ? { errors: result.errors } : {}),
      ...(result.artifacts !== undefined ? { artifacts: result.artifacts } : {}),
      ...(result.metrics !== undefined ? { metrics: result.metrics } : {}),
      ...(result.setup_actions !== undefined ? { setup_actions: result.setup_actions } : {}),
      ...(result.required_user_inputs !== undefined
        ? { required_user_inputs: result.required_user_inputs }
        : {}),
    }, registry)

    // Add text representation
    content.push({
      type: 'text',
      text: JSON.stringify(structuredPayload),
    })

    return {
      content,
      structuredContent: this.normalizeStructuredContent(structuredPayload, outputSchema),
      isError: !result.ok,
    }
  }

  private normalizeStructuredContent(
    structuredContent: Record<string, unknown> | undefined,
    outputSchema?: z.ZodTypeAny
  ): Record<string, unknown> | undefined {
    if (!structuredContent) {
      return undefined
    }

    if (!outputSchema) {
      return structuredContent
    }

    const parsed = outputSchema.safeParse(structuredContent)
    if (!parsed.success || !parsed.data || typeof parsed.data !== 'object' || Array.isArray(parsed.data)) {
      this.logger.warn(
        {
          issues: parsed.success ? undefined : parsed.error.issues,
        },
        'Structured content did not validate against output schema; returning raw content'
      )
      // Return raw content instead of undefined to avoid MCP SDK error:
      // "Tool has an output schema but did not return structured content"
      return structuredContent
    }

    return parsed.data as Record<string, unknown>
  }

  private rewriteToolReferences<T>(value: T, registry: MCPRegistry): T {
    return rewriteToolReferencesInValue(value, registry.getToolNameMappings())
  }

  private rewriteTextContentItems(content: TextContent[], registry: MCPRegistry): TextContent[] {
    const mappings = registry.getToolNameMappings()
    return content.map((item) => {
      if ('text' in item && typeof item.text === 'string') {
        return {
          ...item,
          text: rewriteToolReferencesInText(item.text, mappings),
        }
      }

      return item
    })
  }
}
