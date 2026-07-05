/**
 * Unit tests for core/tool-executor.ts
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { z } from 'zod'
import pino from 'pino'
import { MCPRegistry } from '../../../src/core/mcp-registry.js'
import { ToolExecutor } from '../../../src/core/tool-executor.js'
import { getToolSurfaceManager } from '../../../src/core/tool-surface-manager.js'
import type { WorkerResult } from '../../../src/types.js'

const logger = pino({ level: 'silent' })

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

describe('ToolExecutor', () => {
  let registry: MCPRegistry
  let executor: ToolExecutor

  beforeEach(() => {
    registry = new MCPRegistry(logger)
    executor = new ToolExecutor(logger)
    resetSurfaceForTest()
  })

  function makeToolDef(name: string, schema: z.ZodTypeAny = z.object({})) {
    return {
      name,
      canonicalName: name,
      description: `Tool ${name}`,
      inputSchema: schema,
    } as any
  }

  test('should execute tool and return WorkerResult as ToolResult', async () => {
    const handler = async (): Promise<WorkerResult> => ({ ok: true, data: { result: 42 } })
    registry.registerTool(makeToolDef('test.tool', z.object({ input: z.string() })), handler)

    const result = await executor.executeTool('test_tool', { input: 'hello' }, { registry, logger })

    expect(result.isError).toBe(false)
    const text = (result.content[0] as any).text
    expect(JSON.parse(text)).toMatchObject({ ok: true, data: { result: 42 } })
  })

  test('should validate args and throw structured error on bad input', async () => {
    registry.registerTool(makeToolDef('test.tool', z.object({ count: z.number() })), async () => ({
      ok: true,
    }))

    const result = await executor.executeTool(
      'test_tool',
      { count: 'not-a-number' },
      { registry, logger }
    )

    expect(result.isError).toBe(true)
    const text = (result.content[0] as any).text
    expect(JSON.parse(text).errors[0]).toMatch(/Invalid arguments/)
  })

  test('should return error when tool not found', async () => {
    const result = await executor.executeTool('missing_tool', {}, { registry, logger })
    expect(result.isError).toBe(true)
    const text = (result.content[0] as any).text
    expect(JSON.parse(text).errors[0]).toMatch(/Tool not found/)
  })

  test('should fire plugin before/after hooks', async () => {
    const beforeHook = jest.fn().mockResolvedValue(undefined)
    const afterHook = jest.fn().mockResolvedValue(undefined)
    const pluginRuntime = {
      fireHook: jest.fn().mockImplementation((phase) => {
        if (phase === 'before') return beforeHook()
        if (phase === 'after') return afterHook()
      }),
    }

    registry.registerTool(makeToolDef('test.tool'), async () => ({ ok: true }))
    await executor.executeTool('test_tool', {}, { registry, pluginRuntime, logger })

    expect(pluginRuntime.fireHook).toHaveBeenCalledWith('before', 'test.tool', expect.anything())
    expect(pluginRuntime.fireHook).toHaveBeenCalledWith(
      'after',
      'test.tool',
      expect.anything(),
      expect.objectContaining({ elapsedMs: expect.any(Number) })
    )
  })

  test('should fire error hook on handler failure', async () => {
    const pluginRuntime = { fireHook: jest.fn().mockResolvedValue(undefined) }
    registry.registerTool(makeToolDef('test.tool'), async () => {
      throw new Error('handler boom')
    })

    const result = await executor.executeTool('test_tool', {}, { registry, pluginRuntime, logger })

    expect(result.isError).toBe(true)
    expect(pluginRuntime.fireHook).toHaveBeenCalledWith(
      'error',
      'test_tool',
      expect.anything(),
      expect.objectContaining({ error: expect.any(Error) })
    )
  })

  test('should pass through ToolResult directly', async () => {
    registry.registerTool(
      makeToolDef('test.tool'),
      async () =>
        ({
          content: [{ type: 'text', text: 'hello' }],
          isError: false,
        }) as any
    )

    const result = await executor.executeTool('test_tool', {}, { registry, logger })
    expect(result.content[0]).toMatchObject({ type: 'text', text: 'hello' })
  })

  test('should expand progressive surface from ToolResult structuredContent', async () => {
    const surface = getToolSurfaceManager()
    surface.registerGatewayCoreTools(['test.tool'])
    surface.registerCoreTools(['workflow.analyze.start'])

    registry.registerTool(
      makeToolDef('test.tool'),
      async () =>
        ({
          content: [{ type: 'text', text: 'ready' }],
          structuredContent: {
            data: { recommended_next_tools: ['workflow.analyze.start'] },
          },
          isError: false,
        }) as any
    )

    expect(surface.isToolVisible('workflow.analyze.start')).toBe(false)

    const result = await executor.executeTool('test_tool', {}, { registry, logger })

    expect(result.isError).toBe(false)
    expect(surface.isToolVisible('workflow.analyze.start')).toBe(true)
  })

  test('should block registered tools hidden by the progressive surface', async () => {
    registry.registerTool(makeToolDef('workflow.analyze.start'), async () => ({ ok: true }))
    getToolSurfaceManager().registerCoreTools(['workflow.analyze.start'])
    getToolSurfaceManager().registerGatewayCoreTools(['tools.discover'])

    const result = await executor.executeTool('workflow_analyze_start', {}, { registry, logger })

    expect(result.isError).toBe(true)
    const text = (result.content[0] as any).text
    expect(JSON.parse(text).errors[0]).toContain(
      'Use workflow.search query="workflow.analyze.start"'
    )
  })
})
