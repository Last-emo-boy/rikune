import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'

const TOOL_NAME = 'tool.help'

const ToolFieldSchema = z.object({
  path: z.string(),
  type: z.string(),
  required: z.boolean(),
  nullable: z.boolean(),
  description: z.string().nullable(),
  help_hint: z.string().nullable().optional(),
  default_value: z.any().optional(),
  enum_values: z.array(z.string()).optional(),
})

const ToolSchemaSummarySchema = z.object({
  field_count: z.number().int().nonnegative(),
  fields: z.array(ToolFieldSchema),
})

export const toolHelpInputSchema = z.object({
  tool_name: z.string().optional().describe('Optional exact tool name for a detailed schema/help lookup'),
  include_output_schema: z
    .boolean()
    .default(true)
    .describe('Include output schema field help when the tool defines one'),
  include_fields: z
    .boolean()
    .default(true)
    .describe('When false, only return name/description counts without flattened field help'),
})

export const toolHelpOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    count: z.number().int().nonnegative(),
    tools: z.array(
      z.object({
        name: z.string(),
        description: z.string(),
        usage_notes: z.array(z.string()).optional(),
        input: ToolSchemaSummarySchema.optional(),
        output: ToolSchemaSummarySchema.optional(),
      })
    ),
  }),
  errors: z.array(z.string()).optional(),
})

export const toolHelpToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Query normalized schema/help for registered MCP tools, including enum values, defaults, and field descriptions.',
  inputSchema: toolHelpInputSchema,
  outputSchema: toolHelpOutputSchema,
}

type FieldSummary = z.infer<typeof ToolFieldSchema>

function unwrapSchema(
  schema: z.ZodTypeAny
): {
  schema: z.ZodTypeAny
  required: boolean
  nullable: boolean
  defaultValue?: unknown
} {
  let current = schema
  let required = true
  let nullable = false
  let defaultValue: unknown

  while (true) {
    if (current instanceof z.ZodOptional) {
      required = false
      current = current._def.innerType
      continue
    }
    if (current instanceof z.ZodDefault) {
      required = false
      try {
        defaultValue = current._def.defaultValue()
      } catch {
        defaultValue = undefined
      }
      current = current._def.innerType
      continue
    }
    if (current instanceof z.ZodNullable) {
      nullable = true
      current = current._def.innerType
      continue
    }
    if (current instanceof z.ZodCatch) {
      current = current._def.innerType
      continue
    }
    if (current instanceof z.ZodEffects) {
      current = current._def.schema
      continue
    }
    if (current instanceof z.ZodBranded) {
      current = current._def.type
      continue
    }
    if (current instanceof z.ZodReadonly) {
      current = current._def.innerType
      continue
    }
    break
  }

  return {
    schema: current,
    required,
    nullable,
    defaultValue,
  }
}

function describeSchemaType(schema: z.ZodTypeAny): string {
  if (schema instanceof z.ZodString) return 'string'
  if (schema instanceof z.ZodNumber) return 'number'
  if (schema instanceof z.ZodBoolean) return 'boolean'
  if (schema instanceof z.ZodEnum) return 'enum'
  if (schema instanceof z.ZodLiteral) return 'literal'
  if (schema instanceof z.ZodObject) return 'object'
  if (schema instanceof z.ZodArray) {
    const itemInfo = unwrapSchema(schema._def.type)
    return `array<${describeSchemaType(itemInfo.schema)}>`
  }
  if (schema instanceof z.ZodUnion) return 'union'
  if (schema instanceof z.ZodTuple) return 'tuple'
  return 'unknown'
}

function collectSchemaFields(schema: z.ZodTypeAny, prefix = '', toolName?: string): FieldSummary[] {
  const info = unwrapSchema(schema)
  const current = info.schema

  if (current instanceof z.ZodObject) {
    const shape = current.shape as Record<string, z.ZodTypeAny>
    return Object.entries(shape).flatMap(([key, value]) =>
      collectSchemaFields(value, prefix ? `${prefix}.${key}` : key, toolName)
    )
  }

  const field: FieldSummary = {
    path: prefix || '$',
    type: describeSchemaType(current),
    required: info.required,
    nullable: info.nullable,
    description: schema.description || current.description || null,
    help_hint: buildFieldHelpHint(prefix || '$', toolName),
  }

  if (info.defaultValue !== undefined) {
    field.default_value = info.defaultValue
  }
  if (current instanceof z.ZodEnum) {
    field.enum_values = [...current._def.values]
  } else if (current instanceof z.ZodLiteral) {
    field.enum_values = [String(current._def.value)]
  }

  return [field]
}

function buildFieldHelpHint(path: string, toolName?: string): string | null {
  if (toolName === 'sample.ingest') {
    if (path === 'path') {
      return 'Preferred for local files. Pass an absolute path when the MCP client can read the same filesystem as the MCP server.'
    }
    if (path === 'bytes_b64') {
      return 'Fallback only. Use this when the MCP client cannot read the local file path directly, such as remote or browser-hosted clients.'
    }
    if (path === 'filename') {
      return 'Optional display/original filename. Useful when ingesting from bytes_b64 because there is no source path-derived filename.'
    }
  }

  if (path === 'evidence_scope') {
    return 'Controls runtime evidence selection only. Use session for one runtime import/replay lineage, latest for the newest artifact window, all to aggregate historical runtime evidence.'
  }
  if (path === 'evidence_session_tag') {
    return 'Required when evidence_scope=session. You can also pass it with all/latest to narrow runtime evidence to one named session.'
  }
  if (path === 'semantic_scope') {
    return 'Controls semantic naming/explanation artifact selection only. Use session to consume one naming or explanation review pass, latest for the newest semantic artifact window, all to aggregate historical semantic artifacts.'
  }
  if (path === 'semantic_session_tag') {
    return 'Required when semantic_scope=session. Usually set this to the naming or explanation review session_tag you want reconstruct/export/report to consume.'
  }
  if (path === 'session_tag') {
    return 'Session tag groups newly created artifacts so later MCP calls can select this exact review/export/import session.'
  }
  if (path === 'path_prefix') {
    return 'Use this to narrow artifact tools to one export directory such as reports/reconstruct/<session>.'
  }
  return null
}

function buildUsageNotes(definition: ToolDefinition): string[] {
  const notes: string[] = []
  const inputFields = buildSchemaSummary(definition.inputSchema, definition.name).fields.map((item) => item.path)

  const hasEvidenceScope = inputFields.includes('evidence_scope')
  const hasSemanticScope = inputFields.includes('semantic_scope')
  const hasSessionTag = inputFields.includes('session_tag')

  if (hasEvidenceScope && hasSemanticScope) {
    notes.push(
      'This tool separates runtime evidence scope from semantic artifact scope. Set both when you need fully reproducible session-only results.'
    )
  } else if (hasEvidenceScope) {
    notes.push(
      'This tool consumes runtime evidence artifacts. Prefer evidence_scope=session plus evidence_session_tag for one replay/import session.'
    )
  }

  if (hasSemanticScope) {
    notes.push(
      'This tool consumes naming/explanation artifacts. Prefer semantic_scope=session plus semantic_session_tag to avoid mixing historical LLM outputs.'
    )
  }

  if (hasSessionTag) {
    notes.push(
      'session_tag labels newly created artifacts. Reuse that tag in later semantic_scope=session or artifacts.diff calls.'
    )
  }

  if (definition.name === 'artifacts.list') {
    notes.push(
      'Use session_tag, path_prefix, or latest_only to narrow artifact views before reading or diffing files.'
    )
  }

  if (definition.name === 'artifacts.diff') {
    notes.push(
      'Diff two session_tag values after export, naming review, explanation review, or runtime import to see what changed between analysis rounds.'
    )
  }

  if (definition.name === 'tool.help') {
    notes.push(
      'Query this tool first when an MCP client needs exact enum values, defaults, or scope/session usage guidance before calling another tool.'
    )
  }

  if (definition.name === 'sample.ingest') {
    notes.push(
      'Prefer path for local files. Use bytes_b64 only when the MCP client cannot access the same local filesystem as the MCP server.'
    )
    notes.push(
      'When both path and bytes_b64 are provided, path wins. Passing an absolute file path is the most reliable option for local VS Code/Copilot clients.'
    )
  }

  return notes
}

function buildSchemaSummary(schema: z.ZodTypeAny, toolName?: string): z.infer<typeof ToolSchemaSummarySchema> {
  const fields = collectSchemaFields(schema, '', toolName)
  return {
    field_count: fields.length,
    fields,
  }
}

export function createToolHelpHandler(
  getDefinitions: () => ToolDefinition[]
): (args: ToolArgs) => Promise<WorkerResult> {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    try {
      const input = toolHelpInputSchema.parse(args)
      const definitions = getDefinitions()
      const filtered = input.tool_name
        ? definitions.filter((item) => item.name === input.tool_name)
        : definitions

      if (input.tool_name && filtered.length === 0) {
        return {
          ok: false,
          errors: [`Tool not found: ${input.tool_name}`],
        }
      }

      return {
        ok: true,
        data: {
          count: filtered.length,
          tools: filtered.map((definition) => ({
            name: definition.name,
            description: definition.description,
            usage_notes: buildUsageNotes(definition),
            input: input.include_fields
              ? buildSchemaSummary(definition.inputSchema, definition.name)
              : undefined,
            output:
              input.include_fields && input.include_output_schema && definition.outputSchema
                ? buildSchemaSummary(definition.outputSchema, definition.name)
                : undefined,
          })),
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
      }
    }
  }
}
