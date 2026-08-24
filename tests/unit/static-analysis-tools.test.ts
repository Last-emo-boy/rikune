import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createStaticCapabilityTriageHandler } from '../../src/plugins/static-triage/tools/static-capability-triage.js'
import { createPEStructureAnalyzeHandler } from '../../src/plugins/pe-analysis/tools/pe-structure-analyze.js'
import {
  compilerPackerDetectToolDefinition,
  createCompilerPackerDetectHandler,
} from '../../src/plugins/static-triage/tools/compiler-packer-detect.js'

describe('static analysis tools', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-static-analysis-tools')
    testDbPath = path.join(process.cwd(), 'test-static-analysis-tools.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)

    const sampleId = 'sha256:' + 'e'.repeat(64)
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: 'e'.repeat(64),
      md5: 'e'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), 'MZ', 'utf-8')
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

  test('static.capability.triage should normalize capability findings and persist artifact', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const handler = createStaticCapabilityTriageHandler(workspaceManager, database, {
      callWorker: async () => ({
        job_id: 'worker-job-capability',
        ok: true,
        warnings: [],
        errors: [],
        data: {
          status: 'ready',
          capability_count: 3,
          behavior_namespaces: ['host-interaction/process', 'communication/http'],
          capability_groups: {
            service: 1,
            network: 2,
            crypto: 1,
            anti_analysis: 1,
          },
          capabilities: [
            {
              rule_id: 'service/install',
              name: 'install service',
              namespace: 'host-interaction/service',
              scopes: ['file'],
              group: 'service',
              confidence: 0.82,
              match_count: 1,
              evidence_summary: 'CreateServiceW import',
            },
            {
              rule_id: 'http/client',
              name: 'send HTTP request',
              namespace: 'communication/http',
              scopes: ['file'],
              group: 'network',
              confidence: 0.76,
              match_count: 2,
              evidence_summary: 'WinHTTP strings',
            },
            {
              rule_id: 'crypto/encrypt-data',
              name: 'encrypt data using AES',
              namespace: 'data-manipulation/encryption',
              scopes: ['function'],
              group: 'crypto',
              confidence: 0.88,
              match_count: 3,
              evidence_summary: 'CryptEncrypt and AES key schedule constants',
            },
            {
              rule_id: 'anti-analysis/debugger-check',
              name: 'check for debugger',
              namespace: 'anti-analysis/anti-debugging',
              scopes: ['function'],
              group: 'anti_analysis',
              confidence: 0.79,
              match_count: 1,
              evidence_summary: 'IsDebuggerPresent import',
            },
          ],
          summary: 'Recovered static capabilities.',
          backend: {
            available: true,
            engine: 'capa',
            source: 'python_module',
            version: '9.3.1',
            rules: {
              available: true,
              path: 'C:/rules/capa',
              source: 'env',
            },
          },
        },
        artifacts: [],
        metrics: {
          elapsed_ms: 12,
        },
      }),
    })

    const result = await handler({ sample_id: sampleId, session_tag: 'static-session' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.capability_count).toBe(4)
    expect(data.capability_groups.network).toBe(2)
    expect(data.capabilities[0].name).toBe('install service')
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.static_triage.evidence_summary.v1',
        capability_count: 4,
        high_confidence_count: 4,
      })
    )
    expect(data.correlation_bundle).toEqual(
      expect.objectContaining({
        result_mode: 'static_triage_correlation_bundle',
        recommended_next_tools: expect.arrayContaining([
          'static.config.carver',
          'crypto.identify',
          'packer.detect',
          'analysis.evidence.graph',
        ]),
      })
    )
    expect(data.correlation_bundle.bundles.config.suspected).toBe(true)
    expect(data.correlation_bundle.bundles.crypto.suspected).toBe(true)
    expect(data.correlation_bundle.bundles.packer.suspected).toBe(true)
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        runtime_started: false,
        sample_executed: false,
        network_accessed: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_only: true,
        dynamic_backend_started: false,
        correlation_bundle_ready: true,
      })
    )
    expect(data.artifact.type).toBe('static_capability_triage')
    expect(data.analysis_id).toBeDefined()

    const artifacts = database.findArtifactsByType(sampleId, 'static_capability_triage')
    expect(artifacts).toHaveLength(1)
    const analyses = database.findAnalysesBySample(sampleId)
    expect(analyses.some((item) => item.stage === 'static_capability_triage')).toBe(true)
  })

  test('pe.structure.analyze should return error when static worker is unavailable', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const handler = createPEStructureAnalyzeHandler({ workspaceManager, database } as any)
    // callWorker DI removed in plugin migration; test uses default worker path

    const result = await handler({ sample_id: sampleId, session_tag: 'pe-structure-session' })

    // Without a running Python backend, handler returns ok: false
    expect(result.ok).toBe(false)
    expect(result.errors?.length).toBeGreaterThan(0)
  })

  test('compiler.packer.detect should normalize Detect It Easy findings and persist attribution output', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    expect(compilerPackerDetectToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
      'compiler_packer_attribution'
    )
    expect(compilerPackerDetectToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'static-triage.compiler-packer-attribution',
        producesArtifacts: ['compiler_packer_attribution'],
        nextTools: expect.arrayContaining([
          'packer.detect',
          'unpack.workflow.plan',
          'analysis.evidence.graph',
        ]),
      })
    )
    const handler = createCompilerPackerDetectHandler(workspaceManager, database, {
      resolveBackend: () => ({
        available: true,
        source: 'config',
        path: 'C:/tools/diec.exe',
        version: '3.10',
        checked_candidates: ['C:/tools/diec.exe'],
        error: null,
      }),
      executeBackend: async () => ({
        format: 'json',
        command: ['C:/tools/diec.exe', '-j', 'sample.exe'],
        stdout: JSON.stringify({
          detects: [
            { name: 'PE32 executable', category: 'file_type' },
            { name: 'Microsoft Visual C++', category: 'compiler' },
            { name: 'UPX', category: 'packer' },
          ],
        }),
        stderr: '',
      }),
    })

    const result = await handler({ sample_id: sampleId, session_tag: 'compiler-session' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.summary.compiler_count).toBe(1)
    expect(data.summary.packer_count).toBe(1)
    expect(data.summary.likely_primary_file_type).toBe('PE32 executable')
    expect(data.compiler_findings[0].name).toBe('Microsoft Visual C++')
    expect(data.packer_findings[0].name).toBe('UPX')
    expect(data.artifact.type).toBe('compiler_packer_attribution')
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.compiler_packer_attribution.evidence_summary.v1',
        status: 'ready',
        compiler_count: 1,
        packer_count: 1,
        top_packers: expect.arrayContaining(['UPX']),
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.compiler_packer_attribution.workflow_handoff.v1',
        handoff_mode: 'compiler_packer_attribution_to_unpack_and_reporting',
        recommended_next_tools: expect.arrayContaining([
          'packer.detect',
          'unpack.workflow.plan',
          'analysis.evidence.graph',
        ]),
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'packer-validation-and-unpack-planning',
          priority: 'high',
          next_tools: expect.arrayContaining(['packer.detect', 'unpack.workflow.plan']),
        }),
      ])
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_attribution: true,
        static_backend_started: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        packer_evidence_present: true,
        unpack_handoff_ready: true,
        runtime_followup_requires_opt_in: true,
      })
    )
    expect(data.next_actions).toEqual(
      expect.arrayContaining([
        expect.stringContaining('packer.detect'),
        expect.stringContaining('unpack.workflow.plan'),
      ])
    )

    const artifacts = database.findArtifactsByType(sampleId, 'compiler_packer_attribution')
    expect(artifacts).toHaveLength(1)
    const analyses = database.findAnalysesBySample(sampleId)
    expect(analyses.some((item) => item.stage === 'compiler_packer_detection')).toBe(true)
  })

  test('compiler.packer.detect should return setup guidance when Detect It Easy is unavailable', async () => {
    const sampleId = 'sha256:' + 'e'.repeat(64)
    const handler = createCompilerPackerDetectHandler(workspaceManager, database, {
      resolveBackend: () => ({
        available: false,
        source: 'path',
        path: null,
        version: null,
        checked_candidates: ['diec.exe'],
        error: 'Detect It Easy not found',
      }),
    })

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('setup_required')
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.compiler_packer_attribution.evidence_summary.v1',
        status: 'setup_required',
        warning_count: 1,
      })
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        static_backend_started: false,
        sample_executed_by_tool: false,
        runtime_followup_requires_opt_in: true,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        static_backend_available: false,
        static_backend_started: false,
        setup_required: true,
      })
    )
    expect(result.setup_actions?.length).toBeGreaterThan(0)
    expect(result.required_user_inputs?.some((item: any) => item.key === 'die_path')).toBe(true)
  })
})
