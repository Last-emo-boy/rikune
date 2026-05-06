import { describe, expect, jest, test } from '@jest/globals'
import {
  createToolReadinessHandler,
  toolReadinessToolDefinition,
} from '../../src/tools/tool-readiness.js'
import type { ToolDefinition } from '../../src/types.js'

function createPluginManagerMock() {
  return {
    getPluginForTool: jest.fn((toolName: string) =>
      toolName === 'dynamic.runtime.status' ||
      toolName === 'behavior.capture' ||
      toolName === 'task.status'
        ? toolName === 'task.status'
          ? 'workflow'
          : 'dynamic'
        : undefined
    ),
    getStatuses: jest.fn(() => [
      {
        id: 'dynamic',
        status: 'loaded',
        executionDomain: 'dynamic',
        reasonCode: null,
        statusDetail: 'loaded',
      },
      {
        id: 'workflow',
        status: 'loaded',
        executionDomain: 'static',
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
            name: 'tool.help',
            description: 'help',
            inputSchema: {},
          },
        ] as ToolDefinition[],
      createPluginManagerMock as any
    )

    const result = await handler({ tool_name: 'tool.help', force_refresh: false })

    expect(result.ok).toBe(true)
    expect((result.data as any)?.readiness).toBe('ready')
    expect((result.data as any)?.result_mode).toBe('tool_readiness')
    expect((result.data as any)?.execution_path).toBe('local')
    expect((result.data as any)?.runtime_plane).toBe('local_tool')
    expect((result.data as any)?.tool_surface_role).toBe('primary')
    expect((result.data as any)?.preferred_primary_tools).toEqual([])
    expect((result.data as any)?.required_runtime_contract).toBeNull()
    expect((result.data as any)?.available_runtime_backends).toEqual([])
    expect((result.data as any)?.execution_semantics).toEqual(
      expect.objectContaining({
        readiness_probe: 'passive',
        actual_mode: 'local',
        live_execution: false,
        target_requires_delegated_runtime: false,
      })
    )
    expect((result.data as any)?.plugin).toBeNull()
  })

  test('explains local dynamic control-plane readiness without implying live execution', async () => {
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
    expect((result.data as any)?.runtime_plane).toBe('local_control_plane')
    expect((result.data as any)?.local_dynamic_policy).toBe('control-plane')
    expect((result.data as any)?.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'local',
        live_execution: false,
        local_dynamic_policy: 'control-plane',
      })
    )
    expect((result.data as any)?.next_actions?.[0]).toMatch(/control-plane/i)
  })

  test('adds primary-surface guidance for compatibility tools', async () => {
    const handler = createToolReadinessHandler(
      () =>
        [
          {
            name: 'task.status',
            description: 'raw job status',
            inputSchema: {},
          },
        ] as ToolDefinition[],
      createPluginManagerMock as any
    )

    const result = await handler({ tool_name: 'task.status', force_refresh: false })

    expect(result.ok).toBe(true)
    expect((result.data as any)?.tool_surface_role).toBe('compatibility')
    expect((result.data as any)?.preferred_primary_tools).toEqual(['workflow.analyze.status'])
    expect((result.data as any)?.recommended_next_tools).toEqual(
      expect.arrayContaining(['workflow.analyze.status', 'tool.help', 'plugin.list'])
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
    expect((result.data as any)?.result_mode).toBe('tool_readiness')
    expect((result.data as any)?.runtime_plane).toBe('runtime_endpoint')
    expect((result.data as any)?.required_runtime_contract).toEqual({
      type: 'inline',
      handler: 'executeSandboxExecute',
    })
    expect((result.data as any)?.available_runtime_backends).toEqual([])
    expect((result.data as any)?.execution_semantics).toEqual(
      expect.objectContaining({
        readiness_probe: 'passive',
        actual_mode: 'plan_only',
        execution_path: 'delegated',
        live_execution: false,
        target_requires_delegated_runtime: true,
      })
    )
    expect((result.data as any)?.runtime?.endpoint).toBeNull()
    expect((result.data as any)?.recommended_next_tools).toEqual(
      expect.arrayContaining(['dynamic.runtime.status', 'runtime.debug.session.start'])
    )
  })

  test('treats behavior.capture as runtime-delegated after migration', async () => {
    const handler = createToolReadinessHandler(
      () =>
        [
          {
            name: 'behavior.capture',
            description: 'behavior capture',
            inputSchema: {},
            runtime: { type: 'inline', handler: 'executeBehaviorCapture' },
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

    const result = await handler({ tool_name: 'behavior.capture', force_refresh: false })

    expect(result.ok).toBe(false)
    expect(result.warnings).not.toEqual(
      expect.arrayContaining([expect.stringMatching(/not runtime-delegated yet/i)])
    )
    expect((result.data as any)?.readiness).toBe('runtime_not_started')
    expect((result.data as any)?.execution_path).toBe('delegated')
    expect((result.data as any)?.required_runtime_contract).toEqual({
      type: 'inline',
      handler: 'executeBehaviorCapture',
    })
  })

  test('treats runtime deobfuscation tools as runtime-delegated', async () => {
    const handler = createToolReadinessHandler(
      () =>
        [
          {
            name: 'deobf.strings',
            description: 'runtime strings',
            inputSchema: {},
            runtime: {
              type: 'python-worker',
              handler: 'src/plugins/runtime-deobfuscate/workers/deobfuscate_worker.py',
            },
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

    const result = await handler({ tool_name: 'deobf.strings', force_refresh: false })

    expect(result.ok).toBe(false)
    expect(result.warnings).not.toEqual(
      expect.arrayContaining([expect.stringMatching(/not runtime-delegated yet/i)])
    )
    expect((result.data as any)?.readiness).toBe('runtime_not_started')
    expect((result.data as any)?.execution_path).toBe('delegated')
    expect((result.data as any)?.required_runtime_contract).toEqual({
      type: 'python-worker',
      handler: 'src/plugins/runtime-deobfuscate/workers/deobfuscate_worker.py',
    })
  })

  test('treats managed.fake_c2 as runtime-delegated after migration', async () => {
    const handler = createToolReadinessHandler(
      () =>
        [
          {
            name: 'managed.fake_c2',
            description: 'fake c2',
            inputSchema: {},
            runtime: {
              type: 'python-worker',
              handler: 'src/plugins/managed-fake-c2/workers/managed_fake_c2_worker.py',
            },
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

    const result = await handler({ tool_name: 'managed.fake_c2', force_refresh: false })

    expect(result.ok).toBe(false)
    expect(result.warnings).not.toEqual(
      expect.arrayContaining([expect.stringMatching(/not runtime-delegated yet/i)])
    )
    expect((result.data as any)?.readiness).toBe('runtime_not_started')
    expect((result.data as any)?.execution_path).toBe('delegated')
    expect((result.data as any)?.required_runtime_contract).toEqual({
      type: 'python-worker',
      handler: 'src/plugins/managed-fake-c2/workers/managed_fake_c2_worker.py',
    })
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
    expect((result.data as any)?.runtime_plane).toBe('runtime_capability')
    expect((result.data as any)?.required_runtime_contract).toEqual({
      type: 'python-worker',
      handler: 'frida_worker.py',
    })
    expect((result.data as any)?.available_runtime_backends).toEqual([
      { type: 'python-worker', handler: 'frida_worker.py' },
    ])
    expect((result.data as any)?.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'delegated_ready',
        backend: 'python-worker/frida_worker.py',
        live_execution: false,
      })
    )
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
    expect((result.data as any)?.runtime_plane).toBe('runtime_capability')
    expect((result.data as any)?.available_runtime_backends).toEqual([
      { type: 'spawn', handler: 'native.sample.execute' },
    ])
    expect((result.data as any)?.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'plan_only',
        backend: 'python-worker/frida_worker.py',
        target_requires_delegated_runtime: true,
      })
    )
    expect((result.data as any)?.runtime?.available_runtime_backends).toEqual([
      { type: 'spawn', handler: 'native.sample.execute' },
    ])
  })

  test('returns contract metadata for unknown tools', async () => {
    const handler = createToolReadinessHandler(
      () => [] as ToolDefinition[],
      createPluginManagerMock as any
    )

    const result = await handler({ tool_name: 'missing.tool', force_refresh: false })

    expect(result.ok).toBe(false)
    expect((result.data as any)?.result_mode).toBe('tool_readiness')
    expect((result.data as any)?.readiness).toBe('unknown_tool')
    expect((result.data as any)?.runtime_plane).toBe('tool_registry')
    expect((result.data as any)?.preferred_primary_tools).toEqual([])
    expect((result.data as any)?.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'not_registered',
        live_execution: false,
      })
    )
  })
})
