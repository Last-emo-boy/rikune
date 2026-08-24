import { beforeEach, describe, expect, jest, test } from '@jest/globals'
import { createTraceConditionHandler, traceConditionInputSchema } from '../../src/plugins/static-triage/tools/trace-condition.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'
import type { CacheManager } from '../../src/cache-manager.js'

describe('trace.condition tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>

  beforeEach(() => {
    mockWorkspaceManager = {} as unknown as jest.Mocked<WorkspaceManager>
    mockDatabase = {
      findSample: jest.fn(),
      findArtifactsByType: jest.fn().mockReturnValue([]),
    } as unknown as jest.Mocked<DatabaseManager>
    mockCacheManager = {} as unknown as jest.Mocked<CacheManager>
  })

  test('should validate bounded condition expressions', () => {
    const result = traceConditionInputSchema.safeParse({
      sample_id: 'sha256:test',
      condition: {
        logic: 'all',
        predicates: [
          {
            source: 'register',
            operator: 'eq',
            value: 16,
          },
        ],
      },
    })

    expect(result.success).toBe(false)
  })

  test('should build a bounded normalized trace plan and cap capture scope', async () => {
    mockDatabase.findSample.mockReturnValue({
      id: 'sha256:test',
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    } as any)

    const handler = createTraceConditionHandler(mockWorkspaceManager, mockDatabase, mockCacheManager, {
      breakpointSmart: async () => ({
        ok: true,
        data: {
          recommended_breakpoints: [
            {
              kind: 'api_call',
              api: 'CryptEncrypt',
              module: 'advapi32.dll',
              reason: 'CryptEncrypt is a likely crypto transition point',
              confidence: 0.82,
              context_capture: ['rcx', 'rdx', 'return_value'],
              evidence_sources: ['pe.imports.extract:import'],
              dynamic_support: true,
            },
          ],
        },
      }),
      dynamicDependencies: async () => ({
        ok: true,
        data: {
          available_components: [],
          components: {
            frida: { available: false },
            worker: { available: false },
          },
          setup_actions: [{ id: 'install_frida', kind: 'pip_install', required: true, title: 'Install Frida', summary: 'Install Frida' }],
        },
      }),
    })

    const result = await handler({
      sample_id: 'sha256:test',
      persist_artifact: false,
      reuse_cached: false,
      condition: {
        logic: 'all',
        predicates: [
          {
            source: 'buffer_length',
            argument_index: 0,
            operator: 'gte',
            value: 32,
          },
        ],
      },
      capture: {
        registers: ['rcx', 'rdx'],
        arguments: [0, 1],
        include_return_value: true,
        stack_bytes: 128,
        memory_slices: [
          {
            source: 'argument',
            argument_index: 0,
            max_bytes: 256,
            label: 'buffer0',
          },
        ],
      },
      max_memory_bytes: 96,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('setup_required')
    expect(data.normalized_plan.runtime_mapping.recommended_tool).toBe('frida.runtime.instrument')
    expect(data.normalized_plan.capture.stack_bytes).toBeLessThanOrEqual(96)
    expect(data.runtime_readiness.ready).toBe(false)
    expect(data.condition_summary).toContain('buffer_length[0]')
    expect(result.warnings?.some((item) => item.includes('reduced'))).toBe(true)
  })

  test('forwards cancellation into breakpoint and runtime readiness handlers', async () => {
    mockDatabase.findSample.mockReturnValue({
      id: 'sha256:test',
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    } as any)
    let resolveStarted!: (signal: AbortSignal) => void
    const started = new Promise<AbortSignal>((resolve) => {
      resolveStarted = resolve
    })
    let resolveTeardown!: () => void
    const teardown = new Promise<void>((resolve) => {
      resolveTeardown = resolve
    })
    const breakpointSmart = jest.fn(async () => ({
      ok: true,
      data: {
        recommended_breakpoints: [
          {
            kind: 'api_call',
            api: 'CryptEncrypt',
            module: 'advapi32.dll',
            reason: 'crypto transition',
            confidence: 0.82,
            context_capture: ['rcx', 'rdx'],
            evidence_sources: ['test'],
            dynamic_support: true,
          },
        ],
      },
    }))
    const dynamicDependencies = jest.fn(async (_args, signal?: AbortSignal) => {
      if (!signal) throw new Error('missing AbortSignal')
      resolveStarted(signal)
      await new Promise<void>((resolve) => {
        signal.addEventListener('abort', () => resolve(), { once: true })
      })
      await teardown
      return { ok: true, data: { components: {} } }
    })
    const handler = createTraceConditionHandler(
      mockWorkspaceManager,
      mockDatabase,
      mockCacheManager,
      { breakpointSmart, dynamicDependencies }
    )
    const controller = new AbortController()
    let settled = false
    const running = handler(
      {
        sample_id: 'sha256:test',
        persist_artifact: false,
        reuse_cached: false,
      },
      controller.signal
    ).finally(() => {
      settled = true
    })

    const receivedSignal = await started
    controller.abort(new Error('cancel trace planning'))
    await Promise.resolve()

    expect(receivedSignal).toBe(controller.signal)
    expect(breakpointSmart.mock.calls[0]?.[1]).toBe(controller.signal)
    expect(settled).toBe(false)

    resolveTeardown()
    await expect(running).rejects.toMatchObject({ name: 'AbortError' })
  })
})
