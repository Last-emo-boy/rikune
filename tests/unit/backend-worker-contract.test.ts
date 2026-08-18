import { describe, expect, test } from '@jest/globals'
import { join } from 'path'
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
          data_provenance: 'fixture',
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

  test('external worker mode executes JSON stdin/stdout wrapper when explicitly enabled', async () => {
    const workerPath = join(process.cwd(), 'tests', 'fixtures', 'workers', 'fixture-worker.mjs')
    const externalContract = BackendWorkerContractSchema.parse({
      ...contract,
      commandHint: `node ${workerPath}`,
      defaultMode: 'external',
      policy: {
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        maxOutputBytes: 4096,
        defaultTimeoutMs: 1000,
      },
    })
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: externalContract,
      args: { path: 'sample.js' },
    })

    const result = await runBackendWorker(request, {
      mode: 'external',
      allowExternalBackend: true,
    })

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        external: true,
        execution_semantics: expect.objectContaining({
          actual_mode: 'worker_external',
          live_execution: false,
          data_provenance: 'analysis',
        }),
      })
    )
  })

  test('external worker mode is denied unless explicitly enabled', async () => {
    const workerPath = join(process.cwd(), 'tests', 'fixtures', 'workers', 'fixture-worker.mjs')
    const externalContract = BackendWorkerContractSchema.parse({
      ...contract,
      commandHint: `node ${workerPath}`,
      defaultMode: 'external',
    })
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: externalContract,
      args: { path: 'sample.js' },
    })

    const result = await runBackendWorker(request, {
      mode: 'external',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(
      expect.arrayContaining(['external_backend_execution_not_enabled'])
    )
  })

  test('external worker mode rejects malformed backend output', async () => {
    const workerPath = join(process.cwd(), 'tests', 'fixtures', 'workers', 'fixture-worker.mjs')
    const externalContract = BackendWorkerContractSchema.parse({
      ...contract,
      commandHint: `node ${workerPath} malformed`,
      defaultMode: 'external',
    })
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: externalContract,
      args: { path: 'sample.js' },
    })

    const result = await runBackendWorker(request, {
      mode: 'external',
      allowExternalBackend: true,
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining(['external_backend_malformed_output']))
  })

  test('external worker mode enforces output limits', async () => {
    const workerPath = join(process.cwd(), 'tests', 'fixtures', 'workers', 'fixture-worker.mjs')
    const externalContract = BackendWorkerContractSchema.parse({
      ...contract,
      commandHint: `node ${workerPath} large`,
      defaultMode: 'external',
      policy: {
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        maxOutputBytes: 64,
        defaultTimeoutMs: 1000,
      },
    })
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: externalContract,
      args: { path: 'sample.js' },
    })

    const result = await runBackendWorker(request, {
      mode: 'external',
      allowExternalBackend: true,
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(
      expect.arrayContaining(['external_backend_output_limit_exceeded'])
    )
  })

  test('external worker mode enforces timeouts', async () => {
    const workerPath = join(process.cwd(), 'tests', 'fixtures', 'workers', 'fixture-worker.mjs')
    const externalContract = BackendWorkerContractSchema.parse({
      ...contract,
      commandHint: `node ${workerPath} slow`,
      defaultMode: 'external',
      policy: {
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        maxOutputBytes: 4096,
        defaultTimeoutMs: 50,
      },
    })
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: externalContract,
      args: { path: 'sample.js' },
    })

    const result = await runBackendWorker(request, {
      mode: 'external',
      allowExternalBackend: true,
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining(['external_backend_timeout']))
  })

  test('external worker command rejects shell launchers and control operators', async () => {
    const workerPath = join(process.cwd(), 'tests', 'fixtures', 'workers', 'fixture-worker.mjs')
    const shellContract = BackendWorkerContractSchema.parse({
      ...contract,
      commandHint: `cmd /c node ${workerPath}`,
      defaultMode: 'external',
    })
    const chainedContract = BackendWorkerContractSchema.parse({
      ...contract,
      commandHint: `node ${workerPath} && whoami`,
      defaultMode: 'external',
    })

    const shellReadiness = checkBackendWorkerReadiness(shellContract, { mode: 'external' })
    const chainedReadiness = checkBackendWorkerReadiness(chainedContract, { mode: 'external' })

    expect(shellReadiness.status).toBe('policy_denied')
    expect(shellReadiness.reasons).toEqual(
      expect.arrayContaining(['backend_shell_launcher_rejected'])
    )
    expect(chainedReadiness.status).toBe('policy_denied')
    expect(chainedReadiness.reasons).toEqual(
      expect.arrayContaining(['backend_shell_metacharacter_rejected'])
    )
  })

  test('builtin worker mode rejects artifact output paths outside allowed roots', async () => {
    const allowedRoot = join(process.cwd(), 'test-backend-artifacts')
    const outsidePath = join(process.cwd(), 'outside-backend-artifacts', 'result.json')
    const restrictedContract = BackendWorkerContractSchema.parse({
      ...contract,
      policy: {
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        allowedRoots: [allowedRoot],
      },
    })
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: restrictedContract,
      args: { path: 'sample.js', output_path: outsidePath },
    })

    const result = await runBackendWorker(request)

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining(['artifact_path_outside_allowed_roots']))
    expect(result.artifacts).toBeUndefined()
  })

  test('worker input is rejected when policy maxInputBytes is exceeded', async () => {
    const restrictedContract = BackendWorkerContractSchema.parse({
      ...contract,
      policy: {
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        maxInputBytes: 64,
      },
    })
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: restrictedContract,
      args: { payload: 'x'.repeat(512) },
    })

    const result = await runBackendWorker(request)

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining(['backend_worker_input_limit_exceeded']))
    expect(result.data).toEqual(
      expect.objectContaining({
        max_input_bytes: 64,
        backend: 'FixtureBackend',
      })
    )
  })

  test('external worker diagnostics redact host paths and env-like secrets', async () => {
    const previousSecret = process.env.RIKUNE_TEST_SECRET_VALUE
    process.env.RIKUNE_TEST_SECRET_VALUE = 'SUPER_SECRET_VALUE_123456789'
    const workerPath = join(process.cwd(), 'tests', 'fixtures', 'workers', 'fixture-worker.mjs')
    const externalContract = BackendWorkerContractSchema.parse({
      ...contract,
      commandHint: `node ${workerPath} leak`,
      defaultMode: 'external',
    })
    const request = buildBackendWorkerRequest({
      tool: 'fixture.worker.run',
      backend: externalContract,
      args: { path: 'sample.js' },
    })

    try {
      const result = await runBackendWorker(request, {
        mode: 'external',
        allowExternalBackend: true,
      })
      const stderr = String((result.data as any)?.stderr ?? '')

      expect(result.ok).toBe(false)
      expect(result.errors).toEqual(expect.arrayContaining(['external_backend_failed']))
      expect(stderr).not.toContain('SUPER_SECRET_VALUE_123456789')
      expect(stderr).not.toContain(process.cwd())
      expect(stderr).toContain('<redacted>')
      expect(stderr).toContain('<path>')
    } finally {
      if (previousSecret === undefined) {
        delete process.env.RIKUNE_TEST_SECRET_VALUE
      } else {
        process.env.RIKUNE_TEST_SECRET_VALUE = previousSecret
      }
    }
  })
})
