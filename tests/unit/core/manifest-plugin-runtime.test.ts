import { beforeEach, describe, expect, jest, test } from '@jest/globals'
import pino from 'pino'
import {
  defineManifestPlugin,
  manifestJsonSchemaToZod,
  ok,
} from '../../../packages/plugin-sdk/src/index.js'
import { MCPRegistry } from '../../../src/core/mcp-registry.js'
import { ToolExecutor } from '../../../src/core/tool-executor.js'
import { getToolSurfaceManager } from '../../../src/core/tool-surface-manager.js'
import { zodToJsonSchema } from '../../../src/core/zod-schema-converter.js'

const logger = pino({ level: 'silent' })

function resetSurfaceForTest(): void {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

describe('manifest plugin runtime schema compatibility', () => {
  let registry: MCPRegistry
  let executor: ToolExecutor

  beforeEach(() => {
    registry = new MCPRegistry(logger)
    executor = new ToolExecutor(logger)
    resetSurfaceForTest()
  })

  test('lists and enforces manifest JSON input/output schemas through the core pipeline', async () => {
    const handler = jest.fn(async (args: Record<string, unknown>) => ok({ echoed: args.message }))
    const plugin = defineManifestPlugin(
      {
        id: 'manifest-runtime',
        name: 'Manifest Runtime',
        tools: [
          {
            name: 'manifest_runtime.echo',
            description: 'Echo a required message',
            inputSchema: {
              type: 'object',
              properties: {
                message: { type: 'string', minLength: 1 },
              },
              required: ['message'],
              additionalProperties: false,
            },
            outputSchema: {
              type: 'object',
              properties: {
                ok: { type: 'boolean' },
                data: {
                  type: 'object',
                  properties: {
                    echoed: { type: 'string' },
                  },
                  required: ['echoed'],
                  additionalProperties: false,
                },
              },
              required: ['ok', 'data'],
              additionalProperties: false,
            },
          },
        ],
      },
      {
        'manifest_runtime.echo': handler,
      }
    )

    plugin.register?.(registry as any, {})

    const { tools: listed } = await registry.listTools()
    expect(listed).toHaveLength(1)
    expect(listed[0]).toMatchObject({
      name: 'manifest_runtime_echo',
      inputSchema: {
        type: 'object',
        properties: {
          message: { type: 'string', minLength: 1 },
        },
        required: ['message'],
        additionalProperties: false,
      },
      outputSchema: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          data: {
            type: 'object',
            properties: {
              echoed: { type: 'string' },
            },
            required: ['echoed'],
            additionalProperties: false,
          },
        },
        required: ['ok', 'data'],
        additionalProperties: false,
      },
    })

    const missingRequired = await executor.executeTool(
      'manifest_runtime_echo',
      {},
      { registry, logger }
    )
    expect(missingRequired.isError).toBe(true)
    expect(JSON.parse((missingRequired.content[0] as any).text).errors[0]).toContain(
      'Invalid arguments'
    )
    expect(handler).not.toHaveBeenCalled()

    const valid = await executor.executeTool(
      'manifest_runtime_echo',
      { message: 'hello' },
      { registry, logger }
    )
    expect(valid.isError).toBe(false)
    expect(valid.structuredContent).toEqual({
      ok: true,
      data: { echoed: 'hello' },
    })
    expect(handler).toHaveBeenCalledWith({ message: 'hello' }, expect.anything(), undefined)
  })

  test('accepts boolean manifest schemas and preserves null/never semantics in tools/list', async () => {
    const plugin = defineManifestPlugin(
      {
        id: 'manifest-primitives',
        name: 'Manifest Primitives',
        tools: [
          {
            name: 'manifest_primitives.null',
            description: 'Null output',
            inputSchema: true,
            outputSchema: { type: 'null' },
          },
          {
            name: 'manifest_primitives.never',
            description: 'Never input',
            inputSchema: false,
          },
        ],
      },
      {
        'manifest_primitives.null': async () => ok(null),
        'manifest_primitives.never': async () => ok({}),
      }
    )

    plugin.register?.(registry as any, {})
    const { tools: listed } = await registry.listTools()
    expect(listed).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'manifest_primitives_null',
          inputSchema: {},
          outputSchema: { type: 'null' },
        }),
        expect.objectContaining({
          name: 'manifest_primitives_never',
          inputSchema: { not: {} },
        }),
      ])
    )
  })

  test('requires unconstrained required properties and rejects unsupported validation keywords', () => {
    const schema = manifestJsonSchemaToZod({
      type: 'object',
      required: ['token'],
      additionalProperties: true,
    })

    expect(schema.safeParse({ token: 1 }).success).toBe(true)
    expect(schema.safeParse({}).success).toBe(false)
    expect(() => manifestJsonSchemaToZod({ type: 'array', uniqueItems: true })).toThrow(
      /uniqueItems.*not supported/
    )
  })

  test('combines const, enum, and anyOf with sibling constraints', () => {
    const constSchema = manifestJsonSchemaToZod({ const: 1, type: 'number', minimum: 2 })
    expect(constSchema.safeParse(1).success).toBe(false)

    const enumSchema = manifestJsonSchemaToZod({
      type: 'string',
      enum: [1, 'ok'],
      minLength: 2,
    })
    expect(enumSchema.safeParse(1).success).toBe(false)
    expect(enumSchema.safeParse('x').success).toBe(false)
    expect(enumSchema.safeParse('ok').success).toBe(true)

    const anyOfSchema = manifestJsonSchemaToZod({
      type: 'object',
      required: ['kind'],
      anyOf: [
        { type: 'object', properties: { kind: { const: 'a' } } },
        { type: 'object', properties: { kind: { const: 'b' } } },
      ],
    })
    expect(anyOfSchema.safeParse({}).success).toBe(false)
    expect(anyOfSchema.safeParse({ kind: 'c' }).success).toBe(false)
    expect(anyOfSchema.safeParse({ kind: 'a' }).success).toBe(true)
  })

  test('fails fast for type-specific validation keywords without an explicit type', () => {
    for (const schema of [
      { minLength: 3 },
      { minimum: 0 },
      { minItems: 1 },
      { properties: { name: { type: 'string' } } },
    ]) {
      expect(() => manifestJsonSchemaToZod(schema)).toThrow(/require an explicit 'type'/)
    }
  })

  test('preserves conjunctive manifest constraints in tools/list schemas', () => {
    const zodSchema = manifestJsonSchemaToZod({
      type: 'string',
      const: 'ok',
      minLength: 2,
    })

    const jsonSchema = zodToJsonSchema(zodSchema)
    expect(jsonSchema.allOf).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ const: 'ok' }),
        expect.objectContaining({ type: 'string', minLength: 2 }),
      ])
    )
  })
})
