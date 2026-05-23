import { describe, expect, test } from '@jest/globals'
import {
  BackendWorkerContractSchema,
  defineTool,
  createPluginTestHarness,
  definePlugin,
} from '../../src/plugins/sdk.js'
import {
  buildBackendWorkerRequest,
  checkBackendWorkerReadiness,
  runBackendWorker,
} from '../../src/worker/backend-worker-client.js'

describe('backend worker contract', () => {
  const contract = BackendWorkerContractSchema.parse({
    backendName: 'FixtureBackend',
    backendKind: 'external',
    adapter: 'fixture.adapter',
    envVar: 'FIXTURE_BACKEND_PATH',
    supportedModes: ['builtin', 'external'],
    defaultMode: 'builtin',
    inputArtifactTypes: ['javascript_source'],
    outputArtifactTypes: ['fixture_output'],
    policy: {
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      maxInputBytes: 1024,
      defaultTimeoutMs: 1000,
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: ['Set FIXTURE_BACKEND_PATH to enable external mode.'],
    },
  })

  test('parses worker backend metadata through defineTool', () => {
    const tool = defineTool({
      name: 'fixture.worker.run',
      description: 'Fixture worker',
      inputSchema: {},
      workerBackend: contract,
      handler: async () => ({ ok: true }),
    })

    expect(tool.definition.workerBackend).toEqual(
      expect.objectContaining({
        version: 'backend-worker.v1',
        backendName: 'FixtureBackend',
        adapter: 'fixture.adapter',
      })
    )
  })

  test('registers worker-backed tools in plugin harness', () => {
    const plugin = definePlugin({
      id: 'fixture-worker',
      name: 'Fixture Worker',
      executionDomain: 'static',
      tools: [
        defineTool({
          name: 'fixture.worker.run',
          description: 'Fixture worker',
          inputSchema: {},
          workerBackend: contract,
          handler: async () => ({ ok: true }),
        }),
      ],
    })
    const harness = createPluginTestHarness()
    harness.registerPlugin(plugin)

    expect(harness.registeredTools[0].definition.workerBackend).toEqual(
      expect.objectContaining({ backendName: 'FixtureBackend' })
    )
  })

  test('builds requests with passive policy defaults', () => {
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: contract,
      args: { path: 'sample.js' },
    })

    expect(request.tool).toBe('fixture.worker.run')
    expect(request.context.policy).toEqual(
      expect.objectContaining({
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
  })

  test('readiness reports external backend missing without starting it', () => {
    const readiness = checkBackendWorkerReadiness(contract, { mode: 'external' })

    expect(readiness).toEqual(
      expect.objectContaining({
        status: 'backend_missing',
        does_not_start_backend: true,
        reasons: expect.arrayContaining(['backend_path_missing']),
      })
    )
  })

  test('builtin worker mode returns structured WorkerResult', async () => {
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: contract,
      args: { path: 'sample.js' },
    })
    const result = await runBackendWorker(request, {
      fixtureData: { normalized: true },
    })

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        backend: 'FixtureBackend',
        normalized: true,
        execution_semantics: expect.objectContaining({
          actual_mode: 'worker_builtin',
          live_execution: false,
        }),
      })
    )
    expect(result.evidence?.[0]).toEqual(
      expect.objectContaining({
        category: 'provenance',
        source: 'FixtureBackend',
      })
    )
  })
})
