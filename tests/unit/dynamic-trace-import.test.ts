import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createDynamicTraceImportHandler } from '../../src/plugins/dynamic/tools/dynamic-trace-import.js'

describe('dynamic.trace.import tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-dynamic-trace-import')
    testDbPath = path.join(process.cwd(), 'test-dynamic-trace-import.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
  })

  test('should import inline runtime trace and persist artifact plus analysis record', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createDynamicTraceImportHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      format: 'generic_json',
      evidence_kind: 'trace',
      trace_name: 'frida_remote_ops',
      trace_json: {
        executed: true,
        events: [
          {
            api: 'OpenProcess',
            module: 'kernel32.dll',
            arguments: ['PROCESS_ALL_ACCESS', '1234'],
          },
          {
            api: 'WriteProcessMemory',
            module: 'kernel32.dll',
            arguments: ['remote_process', 'payload_buffer'],
          },
          {
            api: 'GetProcAddress',
            module: 'kernel32.dll',
            arguments: ['kernel32.dll', 'WriteProcessMemory'],
          },
        ],
        memory_regions: [
          {
            region_type: 'dispatch_table',
            purpose: 'process_operation_plan',
            source: 'frida',
            confidence: 0.94,
            base_address: '0x180040000',
            indicators: ['OpenProcess', 'WriteProcessMemory', 'ResumeThread'],
          },
        ],
      },
    })

    expect(result.ok).toBe(true)

    const data = result.data as any
    expect(data.format).toBe('generic_json')
    expect(data.executed).toBe(true)
    expect(data.summary.high_signal_apis).toContain('OpenProcess')
    expect(data.summary.high_signal_apis).toContain('WriteProcessMemory')
    expect(data.summary.stages).toContain('prepare_remote_process_access')
    expect(data.summary.stages).toContain('resolve_dynamic_apis')
    expect(data.analysis_id).toBeDefined()
    expect(data.artifact.path).toContain('reports/dynamic/imported_frida_remote_ops_')

    const artifacts = database.findArtifactsByType(sampleId, 'dynamic_trace_json')
    expect(artifacts).toHaveLength(1)
    const analyses = database.findAnalysesBySample(sampleId)
    expect(analyses.some((item) => item.stage === 'dynamic_trace_import')).toBe(true)
  })

  test('should auto-normalize sandbox-like payloads as hybrid evidence', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createDynamicTraceImportHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      format: 'auto',
      evidence_kind: 'hybrid',
      trace_json: {
        run_id: 'sandbox-memory-guided',
        mode: 'memory_guided',
        timeline: [{ indicator: 'WriteProcessMemory' }],
        api_resolution: [
          {
            api: 'GetProcAddress',
            provenance: 'dynamic_resolution_api',
            confidence: 0.92,
            sources: ['kernel32.dll!GetProcAddress'],
          },
        ],
        memory_regions: [
          {
            region_type: 'api_resolution_table',
            purpose: 'dynamic_api_table',
            source: 'memory_guided',
            confidence: 0.81,
            indicators: ['GetProcAddress', 'LoadLibraryA'],
          },
        ],
        execution_hypotheses: [
          {
            stage: 'resolve_dynamic_apis',
            description: 'Resolve Win32 APIs dynamically',
            source: 'memory_guided',
            confidence: 0.83,
            indicators: ['GetProcAddress'],
          },
        ],
        environment: {
          executed: false,
        },
      },
    })

    expect(result.ok).toBe(true)
    expect(result.warnings).toBeDefined()
    expect(result.warnings?.some((item) => item.includes('does not prove full execution'))).toBe(true)

    const data = result.data as any
    expect(data.format).toBe('sandbox_trace')
    expect(data.evidence_kind).toBe('hybrid')
    expect(data.executed).toBe(false)
    expect(data.summary.high_signal_apis).toContain('GetProcAddress')
    expect(data.summary.memory_regions).toContain('dynamic_api_table')
  })

  test('should auto-normalize behavior capture artifacts through embedded normalized trace', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createDynamicTraceImportHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      format: 'auto',
      trace_json: {
        schema: 'rikune.behavior_capture.v1',
        task_id: 'behavior-task-1',
        status: 'completed',
        normalized_trace: {
          schema_version: '0.1.0',
          source_format: 'sandbox_trace',
          evidence_kind: 'trace',
          source_name: 'behavior-task-1',
          source_mode: 'live_behavior_capture',
          imported_at: new Date().toISOString(),
          executed: true,
          raw_event_count: 2,
          api_calls: [],
          memory_regions: [],
          modules: ['sample.exe', 'kernel32.dll'],
          strings: ['C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\drop.tmp'],
          stages: ['process_execution', 'file_operations'],
          risk_hints: [],
          notes: ['coarse behavior capture'],
        },
      },
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.format).toBe('sandbox_trace')
    expect(data.executed).toBe(true)
    expect(data.summary.stages).toContain('process_execution')
    expect(data.summary.observed_modules).toContain('kernel32.dll')
  })
})
