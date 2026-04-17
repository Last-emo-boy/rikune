import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { createSandboxExecuteHandler } from '../../src/plugins/dynamic/tools/sandbox-execute.js'
import { createDynamicDependenciesHandler } from '../../src/plugins/dynamic/tools/dynamic-dependencies.js'

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
    }
    expect(data.simulated).toBe(true)
    expect(data.run_id.startsWith('sim-')).toBe(true)
    expect(Array.isArray(data.iocs.urls)).toBe(true)
    expect(typeof data.risk.level).toBe('string')
    expect((result.artifacts || []).length).toBeGreaterThan(0)

    const artifacts = database.findArtifacts(sampleId)
    expect(artifacts.some((item) => item.type === 'sandbox_trace_json')).toBe(true)
    expect(artifacts.some((item) => item.type === 'dynamic_trace_json')).toBe(true)
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
    expect((data.api_resolution || []).some((item) => item.api.toLowerCase() === 'writeprocessmemory')).toBe(
      true
    )
    expect((data.execution_hypotheses || []).some((item) => item.stage === 'resolve_dynamic_apis')).toBe(
      true
    )
    expect((data.execution_hypotheses || []).some((item) => item.stage === 'prepare_remote_process_access')).toBe(
      true
    )
    expect((data.memory_regions || []).some((item) => item.region_type === 'process_operation_plan')).toBe(
      true
    )
  })

  test(
    'should execute speakeasy mode when emulator is available',
    async () => {
      const dependencyHandler = createDynamicDependenciesHandler(workspaceManager, database)
      const dependencyResult = await dependencyHandler({})

    expect(dependencyResult.ok).toBe(true)
    const dependencyData = dependencyResult.data as {
      components?: {
        speakeasy?: {
          available?: boolean
          distribution?: string
        }
      }
    }

    const speakeasyAvailable = Boolean(dependencyData.components?.speakeasy?.available)
    if (!speakeasyAvailable || process.platform !== 'win32' || !process.execPath.toLowerCase().endsWith('.exe')) {
      expect(true).toBe(true)
      return
    }

    const preferredFixture = path.join(
      process.cwd(),
      'src',
      'plugins',
      'static-triage',
      'helpers',
      'DotNetMetadataProbe',
      'bin',
      'Debug',
      'net10.0',
      'DotNetMetadataProbe.exe'
    )
    let samplePath = process.execPath
    try {
      await fs.access(preferredFixture)
      samplePath = preferredFixture
    } catch {
      samplePath = process.execPath
    }

    const sampleBuffer = await fs.readFile(samplePath)
    const sampleId = await ingestSample(workspaceManager, database, sampleBuffer)

    const result = await handler({
      sample_id: sampleId,
      approved: true,
      mode: 'speakeasy',
      network: 'disabled',
      timeout_sec: 40,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      mode: string
      backend: string
      simulated: boolean
      timeline: Array<{ event_type: string }>
      evidence: { runtime_api_calls?: unknown[] }
      environment: { executed: boolean; isolation: string }
      metrics?: { runtime_api_call_count?: number }
    }

    expect(data.mode).toBe('speakeasy')
    expect(data.backend).toBe('speakeasy-emulator')
    expect(data.simulated).toBe(false)
    expect(data.environment.executed).toBe(true)
    expect(data.environment.isolation).toBe('user_mode_emulation')
    expect((data.metrics?.runtime_api_call_count || 0) > 0).toBe(true)
    expect((data.evidence.runtime_api_calls || []).length).toBeGreaterThan(0)
    expect(data.timeline.some((item) => item.event_type === 'api_call')).toBe(true)
    },
    30000
  )
})

async function ingestSample(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  data: Buffer
): Promise<string> {
  const sha256 = crypto.createHash('sha256').update(data).digest('hex')
  const md5 = crypto.createHash('md5').update(data).digest('hex')
  const sampleId = `sha256:${sha256}`

  database.insertSample({
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
