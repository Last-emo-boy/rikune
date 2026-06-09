import { describe, expect, jest, test } from '@jest/globals'
import qilingPlugin from '../../src/plugins/qiling/index.js'
import {
  createQilingInspectHandler,
  qilingInspectToolDefinition,
} from '../../src/plugins/qiling/tools/qiling-inspect.js'

function availableQilingBackend() {
  return {
    available: true,
    source: 'test',
    path: 'python',
    version: 'qiling-test',
    checked_candidates: ['python'],
    error: null,
  }
}

describe('qiling.inspect', () => {
  test('reports setup_required without running Qiling when backend is unavailable', async () => {
    const runPythonJson = jest.fn()
    const handler = createQilingInspectHandler(
      {} as any,
      {
        findSample: jest.fn(() => ({ id: 'sha256:test' })),
      } as any,
      {
        resolveBackends: () =>
          ({
            qiling: {
              available: false,
              source: null,
              path: null,
              version: null,
              checked_candidates: [],
              error: 'qiling missing',
            },
          }) as any,
        runPythonJson,
      }
    )

    const result = await handler({ sample_id: 'sha256:test', operation: 'preflight' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('setup_required')
    expect(data.result_mode).toBe('qiling_readiness_profile')
    expect(data.backend.available).toBe(false)
    expect(data.readiness).toEqual(
      expect.objectContaining({
        backend_available: false,
        rootfs_configured: false,
        rootfs_exists: false,
      })
    )
    expect(data.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'plan_only',
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
        backend_probe_started: false,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['dynamic.dependencies', 'tool.readiness'])
    )
    expect(data.recommended_next_tools).not.toContain('artifact.read')
    expect(data.recommended_next_tools).not.toContain('sandbox.execute')
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        readiness_probe_only: true,
        backend_available: false,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
      })
    )
    expect(result.warnings).toEqual(expect.arrayContaining(['qiling missing']))
    expect(runPythonJson).not.toHaveBeenCalled()
  })

  test('declares qiling readiness search profile and workflow metadata', () => {
    const recipe = qilingInspectToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'qiling.rootfs-readiness-profile'
    )

    expect(qilingInspectToolDefinition.name).toBe('qiling.inspect')
    expect(qilingInspectToolDefinition.outputSchema).toBeDefined()
    expect(qilingInspectToolDefinition.runtime?.handler).toBe('executeQilingInspect')
    expect(qilingPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'readiness-profile',
        'runtime-plan',
        'workflow-handoff',
        'qiling-rootfs-readiness',
      ])
    )
    expect(qilingPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'disabled',
      })
    )
    expect(qilingInspectToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['elf', 'pe', 'macho', 'shellcode', 'firmware']),
        runtimes: expect.arrayContaining(['qiling', 'unicorn']),
        safety: expect.arrayContaining([
          'passive',
          'requires_isolation',
          'no_sample_execution_by_default',
          'no_network_by_default',
          'backend_readiness_probe_only',
        ]),
        capabilities: expect.arrayContaining([
          'readiness-profile',
          'emulation-plan',
          'workflow-handoff',
        ]),
      })
    )
    expect(qilingInspectToolDefinition.artifacts).toBeUndefined()
    expect(qilingInspectToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'runtime-readiness',
        }),
        expect.objectContaining({
          category: 'rootfs',
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['qiling.inspect'],
        nextTools: expect.arrayContaining([
          'linux.runtime.plan',
          'dynamic.dependencies',
          'tool.readiness',
        ]),
        safety: expect.arrayContaining(['passive', 'no_network_by_default']),
      })
    )
    expect(recipe?.producesArtifacts).toBeUndefined()
    expect(qilingInspectToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'disabled',
      })
    )
  })

  test('returns readiness envelope when rootfs is missing without recommending live execution', async () => {
    const runPythonJson = jest.fn(async () => ({
      stdout: '',
      stderr: '',
      parsed: {
        qiling_version: '1.4.6',
        rootfs_configured: true,
        rootfs_exists: false,
        rootfs_path: 'C:/missing-rootfs',
        system32_path: 'C:/missing-rootfs/Windows/System32',
        kernel32_present: false,
      },
    }))
    const handler = createQilingInspectHandler(
      {} as any,
      {
        findSample: jest.fn(() => ({ id: 'sha256:test' })),
      } as any,
      {
        resolveBackends: () =>
          ({
            qiling: availableQilingBackend(),
          }) as any,
        runPythonJson,
      }
    )

    const result = await handler({ sample_id: 'sha256:test', operation: 'rootfs_probe' })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.status).toBe('setup_required')
    expect(data.result_mode).toBe('qiling_readiness_profile')
    expect(data.readiness).toEqual(
      expect.objectContaining({
        backend_available: true,
        rootfs_configured: true,
        rootfs_exists: false,
        windows_rootfs_kernel32_present: false,
      })
    )
    expect(data.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'plan_only',
        backend_probe_started: true,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
        runtime_started_by_tool: false,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['linux.runtime.plan', 'dynamic.toolkit.status', 'tool.readiness'])
    )
    expect(data.recommended_next_tools).not.toContain('sandbox.execute')
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
        runtime_started_by_tool: false,
        network_accessed_by_tool: false,
      })
    )
    expect(result.setup_actions).toBeDefined()
    expect(runPythonJson).toHaveBeenCalledTimes(1)
    const payload = runPythonJson.mock.calls[0]?.[2] as Record<string, unknown>
    expect(Object.keys(payload).sort()).toEqual(['rootfs'])
    expect(payload).not.toHaveProperty('sample_id')
    expect(payload).not.toHaveProperty('sample_path')
    expect(payload).not.toHaveProperty('path')
    expect(payload).not.toHaveProperty('argv')
    expect(payload).not.toHaveProperty('command')
  })

  test('does not treat an incomplete Windows rootfs as execution-ready', async () => {
    const runPythonJson = jest.fn(async () => ({
      stdout: '',
      stderr: '',
      parsed: {
        qiling_version: '1.4.6',
        rootfs_configured: true,
        rootfs_exists: true,
        rootfs_path: 'C:/qiling-rootfs',
        system32_path: 'C:/qiling-rootfs/Windows/System32',
        kernel32_present: false,
      },
    }))
    const handler = createQilingInspectHandler(
      {} as any,
      {
        findSample: jest.fn(() => ({ id: 'sha256:test' })),
      } as any,
      {
        resolveBackends: () =>
          ({
            qiling: availableQilingBackend(),
          }) as any,
        runPythonJson,
      }
    )

    const result = await handler({ sample_id: 'sha256:test' })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.status).toBe('setup_required')
    expect(data.readiness).toEqual(
      expect.objectContaining({
        backend_available: true,
        rootfs_configured: true,
        rootfs_exists: true,
        windows_rootfs_kernel32_present: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        rootfs_readiness_sufficient: false,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'opt-in-emulation-planning',
          priority: 'blocked',
        }),
      ])
    )
  })

  test('returns ready planner envelope when backend and rootfs are configured', async () => {
    const runPythonJson = jest.fn(async () => ({
      stdout: '',
      stderr: '',
      parsed: {
        qiling_version: '1.4.6',
        rootfs_configured: true,
        rootfs_exists: true,
        rootfs_path: 'C:/qiling-rootfs',
        system32_path: 'C:/qiling-rootfs/Windows/System32',
        kernel32_present: true,
      },
    }))
    const handler = createQilingInspectHandler(
      {} as any,
      {
        findSample: jest.fn(() => ({ id: 'sha256:test' })),
      } as any,
      {
        resolveBackends: () =>
          ({
            qiling: availableQilingBackend(),
          }) as any,
        runPythonJson,
      }
    )

    const result = await handler({ sample_id: 'sha256:test' })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.status).toBe('ready')
    expect(data.readiness.rootfs_exists).toBe(true)
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        rootfs_readiness_sufficient: true,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
        recommended_live_execution_tools: [],
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'opt-in-emulation-planning',
          priority: 'medium',
          next_tools: expect.arrayContaining(['linux.runtime.plan', 'windows.runtime.plan']),
        }),
      ])
    )
    expect(data.recommended_next_tools).not.toContain('sandbox.execute')
    expect(result.setup_actions).toBeUndefined()
  })

  test('keeps passive envelope when backend probe throws', async () => {
    const runPythonJson = jest.fn(async () => {
      throw new Error('probe failed')
    })
    const handler = createQilingInspectHandler(
      {} as any,
      {
        findSample: jest.fn(() => ({ id: 'sha256:test' })),
      } as any,
      {
        resolveBackends: () =>
          ({
            qiling: availableQilingBackend(),
          }) as any,
        runPythonJson,
      }
    )

    const result = await handler({ sample_id: 'sha256:test' })
    const data = result.data as any

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining(['probe failed']))
    expect(data.result_mode).toBe('qiling_readiness_profile')
    expect(data.status).toBe('setup_required')
    expect(data.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'plan_only',
        live_execution: false,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
        runtime_started_by_tool: false,
        backend_probe_started: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        readiness_probe_only: true,
        sample_executed_by_tool: false,
        emulation_started_by_tool: false,
      })
    )
  })
})
