import { describe, expect, jest, test } from '@jest/globals'
import {
  createToolReadinessHandler,
  toolReadinessToolDefinition,
} from '../../src/tools/tool-readiness.js'
import type { ToolDefinition } from '../../src/types.js'

function createPluginManagerMock() {
  return {
    getPluginForTool: jest.fn((toolName: string) =>
      toolName === 'dynamic.runtime.status' ? 'dynamic' : undefined
    ),
    getStatuses: jest.fn(() => [
      {
        id: 'dynamic',
        status: 'loaded',
        executionDomain: 'dynamic',
        reasonCode: null,
        statusDetail: 'loaded',
      },
    ]),
  }
}

describe('tool.readiness', () => {
  test('exports stable tool metadata', () => {
    expect(toolReadinessToolDefinition.name).toBe('tool.readiness')
    expect(toolReadinessToolDefinition.description).toMatch(/runtime backend/i)
  })

  test('returns local ready for tools without runtime contracts', async () => {
    const handler = createToolReadinessHandler(
      () =>
        [
          {
            name: 'dynamic.runtime.status',
            description: 'status',
            inputSchema: {},
          },
        ] as ToolDefinition[],
      createPluginManagerMock as any
    )

    const result = await handler({ tool_name: 'dynamic.runtime.status', force_refresh: false })

    expect(result.ok).toBe(true)
    expect((result.data as any)?.readiness).toBe('ready')
    expect((result.data as any)?.execution_path).toBe('local')
    expect((result.data as any)?.plugin).toEqual(
      expect.objectContaining({ id: 'dynamic', status: 'loaded' })
    )
  })

  test('stays passive for remote-sandbox tools when no runtime endpoint is attached', async () => {
    const handler = createToolReadinessHandler(
      () =>
        [
          {
            name: 'sandbox.execute',
            description: 'run sample',
            inputSchema: {},
            runtime: { type: 'inline', handler: 'executeSandboxExecute' },
          },
        ] as ToolDefinition[],
      createPluginManagerMock as any,
      {
        runtimeMode: 'remote-sandbox',
        runtimeClient: {
          getEndpoint: jest.fn(() => ''),
          validateRuntimeContract: jest.fn(),
        },
      }
    )

    const result = await handler({ tool_name: 'sandbox.execute', force_refresh: false })

    expect(result.ok).toBe(false)
    expect((result.data as any)?.readiness).toBe('runtime_not_started')
    expect((result.data as any)?.runtime?.endpoint).toBeNull()
    expect((result.data as any)?.recommended_next_tools).toEqual(
      expect.arrayContaining(['dynamic.runtime.status', 'runtime.debug.session.start'])
    )
  })

  test('returns ready when runtime advertises the required contract', async () => {
    const validateRuntimeContract = jest.fn().mockResolvedValue({
      supported: true,
      capability: { type: 'python-worker', handler: 'frida_worker.py' },
      capabilities: [{ type: 'python-worker', handler: 'frida_worker.py' }],
    })
    const handler = createToolReadinessHandler(
      () =>
        [
          {
            name: 'frida.runtime.instrument',
            description: 'frida',
            inputSchema: {},
            runtime: { type: 'python-worker', handler: 'frida_worker.py' },
          },
        ] as ToolDefinition[],
      createPluginManagerMock as any,
      {
        runtimeMode: 'manual_runtime',
        runtimeClient: {
          getEndpoint: () => 'http://127.0.0.1:4010',
          validateRuntimeContract,
        },
      }
    )

    const result = await handler({ tool_name: 'frida.runtime.instrument', force_refresh: true })

    expect(result.ok).toBe(true)
    expect((result.data as any)?.readiness).toBe('ready')
    expect(validateRuntimeContract).toHaveBeenCalledWith(
      { type: 'python-worker', handler: 'frida_worker.py' },
      { forceRefresh: true }
    )
  })

  test('reports capability missing when runtime is reachable but does not advertise the backend', async () => {
    const handler = createToolReadinessHandler(
      () =>
        [
          {
            name: 'frida.runtime.instrument',
            description: 'frida',
            inputSchema: {},
            runtime: { type: 'python-worker', handler: 'frida_worker.py' },
          },
        ] as ToolDefinition[],
      createPluginManagerMock as any,
      {
        runtimeMode: 'manual_runtime',
        runtimeClient: {
          getEndpoint: () => 'http://127.0.0.1:4010',
          validateRuntimeContract: async () => ({
            supported: false,
            capabilities: [{ type: 'spawn', handler: 'native.sample.execute' }],
          }),
        },
      }
    )

    const result = await handler({ tool_name: 'frida.runtime.instrument', force_refresh: false })

    expect(result.ok).toBe(false)
    expect((result.data as any)?.readiness).toBe('runtime_capability_missing')
    expect((result.data as any)?.runtime?.available_runtime_backends).toEqual([
      { type: 'spawn', handler: 'native.sample.execute' },
    ])
  })
})
