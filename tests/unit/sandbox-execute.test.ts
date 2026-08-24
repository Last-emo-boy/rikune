import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import {
  createSandboxExecuteHandler,
  sandboxExecuteToolDefinition,
} from '../../src/plugins/dynamic/tools/sandbox-execute.js'

describe('sandbox.execute tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let policyGuard: PolicyGuard
  let handler: ReturnType<typeof createSandboxExecuteHandler>

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sandbox-execute-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    policyGuard = new PolicyGuard(path.join(tempDir, 'audit.log'))
    handler = createSandboxExecuteHandler(workspaceManager, database, policyGuard)
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('declares sandbox execution metadata and handoff contracts', () => {
    const recipe = sandboxExecuteToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'sandbox.dynamic-execution-profile'
    )

    expect(sandboxExecuteToolDefinition.runtime?.handler).toBe('executeSandboxExecute')
    expect(sandboxExecuteToolDefinition.aspects).toEqual(
      expect.objectContaining({
        execution: expect.arrayContaining(['dynamic', 'emulation', 'safe_simulation']),
        runtimes: expect.arrayContaining(['safe-simulation', 'speakeasy', 'windows-sandbox']),
        safety: expect.arrayContaining([
          'opt_in_dynamic',
          'requires_isolation',
          'approval_required_for_live_execution',
          'no_network_by_default',
        ]),
        capabilities: expect.arrayContaining([
          'sandbox-trace',
          'runtime-trace',
          'workflow-handoff',
        ]),
      })
    )
    expect(sandboxExecuteToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        allowedBackends: ['local', 'docker', 'windows-sandbox', 'hyperv'],
        networkPolicy: 'disabled',
      })
    )
    expect(sandboxExecuteToolDefinition.runtimePolicy?.allowedBackends).not.toContain('speakeasy')
    expect(sandboxExecuteToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'sandbox_trace_json' }),
        expect.objectContaining({ type: 'dynamic_trace_json' }),
      ])
    )
    expect(sandboxExecuteToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'behavior',
          artifactTypes: expect.arrayContaining(['sandbox_trace_json', 'dynamic_trace_json']),
        }),
        expect.objectContaining({
          category: 'provenance',
          artifactTypes: expect.arrayContaining(['sandbox_trace_json', 'dynamic_trace_json']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['sandbox.execute'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'dynamic.trace.import',
          'analysis.evidence.graph',
          'report.generate',
          'workflow.search',
        ]),
        producesArtifacts: ['sandbox_trace_json', 'dynamic_trace_json'],
        runtimeBackends: expect.arrayContaining(['safe-simulation', 'speakeasy']),
      })
    )
    expect(sandboxExecuteToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendKind: 'builtin',
        adapter: 'sandbox.execute.dynamic-profile',
        outputArtifactTypes: ['sandbox_trace_json', 'dynamic_trace_json'],
      })
    )
  })

  test('should return error for unknown sample', async () => {
    const result = await handler({
      sample_id: `sha256:${'a'.repeat(64)}`,
      approved: true,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should deny dynamic execution without explicit approval', async () => {
    const sampleId = await ingestSample(workspaceManager, database, Buffer.from('MZ demo'))
    const result = await handler({
      sample_id: sampleId,
      approved: false,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('requires explicit approval')
    expect(result.warnings?.join(' ')).toContain('approved=true')
  })

  test('should run safe simulation and persist artifact when approved', async () => {
    const sampleBuffer = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.from('\x00'.repeat(256), 'binary'),
      Buffer.from(
        'powershell.exe -enc AAAA http://evil.example/a HKEY_CURRENT_USER\\Software\\Run',
        'utf-8'
      ),
    ])
    const sampleId = await ingestSample(workspaceManager, database, sampleBuffer)

    const result = await handler({
      sample_id: sampleId,
      approved: true,
      mode: 'safe_simulation',
      network: 'disabled',
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      simulated: boolean
      run_id: string
      iocs: Record<string, string[]>
      risk: { level: string }
      execution_semantics: {
        live_windows_sandbox_execution: boolean
        safe_simulation: boolean
      }
      evidence_summary: {
        artifact_types: string[]
        recommended_next_tools: string[]
      }
      workflow_handoff: {
        artifact_contract: { expected_consumers: string[] }
        dynamic_boundary: { safe_simulation: boolean; live_execution: boolean }
      }
      quality_gates: {
        dynamic_trace_persisted: boolean
        sandbox_trace_persisted: boolean
        approved_execution: boolean
      }
      recommended_next_tools: string[]
    }
    expect(data.simulated).toBe(true)
    expect(data.execution_semantics.live_windows_sandbox_execution).toBe(false)
    expect(data.execution_semantics.safe_simulation).toBe(true)
    expect(data.evidence_summary.artifact_types).toEqual(
      expect.arrayContaining(['sandbox_trace_json', 'dynamic_trace_json'])
    )
    expect(data.evidence_summary.recommended_next_tools).toEqual(
      expect.arrayContaining(['dynamic.trace.import', 'analysis.evidence.graph'])
    )
    expect(data.workflow_handoff.artifact_contract.expected_consumers).toEqual(
      expect.arrayContaining(['artifact.read', 'dynamic.trace.import', 'analysis.evidence.graph'])
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        safe_simulation: true,
        live_execution: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        approved_execution: true,
        dynamic_trace_persisted: true,
        sandbox_trace_persisted: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['artifact.read', 'dynamic.trace.import', 'workflow.search'])
    )
    expect(result.warnings?.join(' ')).toContain('did not perform live Windows Sandbox execution')
    expect(data.run_id.startsWith('sim-')).toBe(true)
    expect(Array.isArray(data.iocs.urls)).toBe(true)
    expect(typeof data.risk.level).toBe('string')
    expect((result.artifacts || []).length).toBeGreaterThan(0)

    const artifacts = database.findArtifacts(sampleId)
    const sandboxArtifact = artifacts.find((item) => item.type === 'sandbox_trace_json')
    expect(sandboxArtifact).toBeDefined()
    expect(artifacts.some((item) => item.type === 'dynamic_trace_json')).toBe(true)

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persistedEnvelope = JSON.parse(
      await fs.readFile(path.join(workspace.root, sandboxArtifact!.path), 'utf-8')
    ) as {
      workflow_handoff?: { schema?: string }
      quality_gates?: { sandbox_trace_persisted?: boolean; dynamic_trace_persisted?: boolean }
    }
    expect(persistedEnvelope.workflow_handoff?.schema).toBe(
      'rikune.sandbox_execute.workflow_handoff.v1'
    )
    expect(persistedEnvelope.quality_gates).toEqual(
      expect.objectContaining({
        sandbox_trace_persisted: true,
        dynamic_trace_persisted: true,
      })
    )
  })

  test('should run memory-guided simulation and recover memory regions plus execution hypotheses', async () => {
    const sampleBuffer = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.from('\x00'.repeat(256), 'binary'),
      Buffer.from(
        [
          'GetProcAddress LoadLibraryA WriteProcessMemory OpenProcess SetThreadContext ResumeThread',
          'NtQuerySystemInformation Kernel_Code_Integrity_Status_Raw',
          'RegOpenKeyExW HKEY_CURRENT_USER\\Software\\Run',
          'cmd.exe /c whoami',
          '@Packer/Protector Detection VMProtect Themida Entry point in non-first section',
        ].join(' '),
        'utf-8'
      ),
    ])
    const sampleId = await ingestSample(workspaceManager, database, sampleBuffer)

    const result = await handler({
      sample_id: sampleId,
      approved: true,
      mode: 'memory_guided',
      network: 'disabled',
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      mode: string
      backend: string
      simulated: boolean
      memory_regions?: Array<{ region_type: string; indicators: string[] }>
      api_resolution?: Array<{ api: string; provenance: string }>
      execution_hypotheses?: Array<{ stage: string; indicators: string[] }>
      environment: { isolation: string }
      metrics?: { memory_region_count?: number }
    }

    expect(data.mode).toBe('memory_guided')
    expect(data.backend).toBe('static-memory-guided')
    expect(data.simulated).toBe(true)
    expect(data.environment.isolation).toBe('image_memory_guided')
    expect((data.memory_regions || []).length).toBeGreaterThan(0)
    expect(
      (data.api_resolution || []).some((item) => item.api.toLowerCase() === 'writeprocessmemory')
    ).toBe(true)
    expect(
      (data.execution_hypotheses || []).some((item) => item.stage === 'resolve_dynamic_apis')
    ).toBe(true)
    expect(
      (data.execution_hypotheses || []).some(
        (item) => item.stage === 'prepare_remote_process_access'
      )
    ).toBe(true)
    expect(
      (data.memory_regions || []).some((item) => item.region_type === 'process_operation_plan')
    ).toBe(true)
  })

  test('should execute speakeasy mode with an emulator worker response', async () => {
    let capturedRequest:
      | {
          job_id: string
          tool: string
          sample: { sample_id: string; path: string }
          args: Record<string, unknown>
        }
      | undefined

    const speakeasyHandler = createSandboxExecuteHandler(workspaceManager, database, policyGuard, {
      callWorker: async (request) => {
        capturedRequest = request
        return {
          job_id: request.job_id,
          ok: true,
          warnings: [],
          errors: [],
          data: {
            run_id: 'speakeasy-run-1',
            status: 'completed',
            mode: 'speakeasy',
            backend: 'speakeasy-emulator',
            simulated: false,
            timeout_sec: 40,
            event_count: 2,
            timeline: [
              {
                event_type: 'api_call',
                category: 'instrumentation',
                indicator: 'VirtualAlloc',
                confidence: 0.95,
              },
              {
                event_type: 'return',
                category: 'completion',
                indicator: 'analysis_complete',
                confidence: 0.8,
              },
            ],
            iocs: {},
            capabilities: [
              {
                name: 'runtime_api_trace',
                evidence_count: 2,
                confidence: 0.91,
              },
            ],
            risk: {
              score: 18,
              level: 'low',
              confidence: 0.82,
            },
            environment: {
              network_policy: 'disabled',
              executed: true,
              isolation: 'user_mode_emulation',
            },
            evidence: {
              runtime_api_calls: [
                { api: 'VirtualAlloc', provider: 'speakeasy' },
                { api: 'CreateFileW', provider: 'speakeasy' },
              ],
            },
            inference: {
              classification: 'suspicious',
              summary: 'Speakeasy emulation completed',
            },
            metrics: {
              runtime_api_call_count: 2,
            },
          },
          artifacts: [],
          metrics: {
            worker_ms: 17,
          },
        }
      },
    })

    const sampleId = await ingestSample(
      workspaceManager,
      database,
      Buffer.from('MZ speakeasy test sample')
    )

    const result = await speakeasyHandler({
      sample_id: sampleId,
      approved: true,
      mode: 'speakeasy',
      network: 'disabled',
      timeout_sec: 40,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    expect(capturedRequest).toEqual(
      expect.objectContaining({
        tool: 'sandbox.execute',
        sample: expect.objectContaining({
          sample_id: sampleId,
        }),
        args: expect.objectContaining({
          mode: 'speakeasy',
        }),
      })
    )

    const data = result.data as {
      mode: string
      backend: string
      simulated: boolean
      timeline: Array<{ event_type: string }>
      evidence: { runtime_api_calls?: unknown[] }
      environment: { executed: boolean; isolation: string }
      execution_semantics: {
        live_windows_sandbox_execution: boolean
        emulation: boolean
      }
      workflow_handoff: {
        dynamic_boundary: { emulation: boolean; safe_simulation: boolean }
      }
      quality_gates: {
        emulation: boolean
        persisted_artifact_count: number
      }
      metrics?: { runtime_api_call_count?: number }
    }

    expect(data.mode).toBe('speakeasy')
    expect(data.backend).toBe('speakeasy-emulator')
    expect(data.simulated).toBe(false)
    expect(data.environment.executed).toBe(true)
    expect(data.environment.isolation).toBe('user_mode_emulation')
    expect(data.execution_semantics.live_windows_sandbox_execution).toBe(false)
    expect(data.execution_semantics.emulation).toBe(true)
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        emulation: true,
        safe_simulation: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        emulation: true,
        persisted_artifact_count: 0,
      })
    )
    expect((data.metrics?.runtime_api_call_count || 0) > 0).toBe(true)
    expect((data.evidence.runtime_api_calls || []).length).toBeGreaterThan(0)
    expect(data.timeline.some((item) => item.event_type === 'api_call')).toBe(true)
  })

  test('forwards cancellation to the sandbox worker and waits for teardown', async () => {
    const sampleId = await ingestSample(workspaceManager, database, Buffer.from('MZ cancel'))
    let resolveStarted!: (signal: AbortSignal) => void
    const started = new Promise<AbortSignal>((resolve) => {
      resolveStarted = resolve
    })
    let resolveTeardown!: () => void
    const teardown = new Promise<void>((resolve) => {
      resolveTeardown = resolve
    })
    const callWorker = jest.fn(async (_request, signal?: AbortSignal) => {
      if (!signal) throw new Error('missing AbortSignal')
      resolveStarted(signal)
      await new Promise<void>((resolve) => {
        signal.addEventListener('abort', () => resolve(), { once: true })
      })
      await teardown
      return {
        job_id: 'cancelled-sandbox',
        ok: true,
        warnings: [],
        errors: [],
        data: {},
        artifacts: [],
        metrics: {},
      }
    })
    const abortableHandler = createSandboxExecuteHandler(
      workspaceManager,
      database,
      policyGuard,
      { callWorker }
    )
    const controller = new AbortController()
    let settled = false
    const running = abortableHandler(
      {
        sample_id: sampleId,
        approved: true,
        persist_artifact: false,
      },
      controller.signal
    ).finally(() => {
      settled = true
    })

    const receivedSignal = await started
    controller.abort(new Error('cancel sandbox'))
    await Promise.resolve()

    expect(receivedSignal).toBe(controller.signal)
    expect(settled).toBe(false)

    resolveTeardown()
    await expect(running).rejects.toMatchObject({ name: 'AbortError' })
    expect(database.findArtifacts(sampleId)).toHaveLength(0)
  })
})

async function ingestSample(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  data: Buffer
): Promise<string> {
  const sha256 = crypto.createHash('sha256').update(data).digest('hex')
  const md5 = crypto.createHash('md5').update(data).digest('hex')
  const sampleId = `sha256:${sha256}`

  database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
    id: sampleId,
    sha256,
    md5,
    size: data.length,
    file_type: 'PE32',
    created_at: new Date().toISOString(),
    source: 'test',
  })

  const workspace = await workspaceManager.createWorkspace(sampleId)
  await fs.writeFile(path.join(workspace.original, 'sample.exe'), data)
  return sampleId
}
