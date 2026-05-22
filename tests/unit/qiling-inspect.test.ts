import { describe, expect, jest, test } from '@jest/globals'
import { createQilingInspectHandler, qilingInspectToolDefinition } from '../../src/plugins/qiling/tools/qiling-inspect.js'

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
    expect((result.data as any).status).toBe('setup_required')
    expect((result.data as any).backend.available).toBe(false)
    expect(result.warnings).toEqual(expect.arrayContaining(['qiling missing']))
    expect(runPythonJson).not.toHaveBeenCalled()
  })

  test('declares qiling readiness output schema for Linux dynamic suite', () => {
    expect(qilingInspectToolDefinition.name).toBe('qiling.inspect')
    expect(qilingInspectToolDefinition.outputSchema).toBeDefined()
    expect(qilingInspectToolDefinition.runtime?.handler).toBe('executeQilingInspect')
  })
})
