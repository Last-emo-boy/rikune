/**
 * Unit tests for workflow.reconstruct tool
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createReconstructWorkflowHandler,
  ReconstructWorkflowInputSchema,
} from '../../src/workflows/reconstruct.js'
import {
  persistSemanticFunctionExplanationsArtifact,
  persistSemanticNameSuggestionsArtifact,
} from '../../src/semantic-name-suggestion-artifacts.js'

describe('workflow.reconstruct tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-reconstruct-workflow')
    testDbPath = path.join(process.cwd(), 'test-reconstruct-workflow.db')
    testCachePath = path.join(process.cwd(), 'test-cache-reconstruct-workflow')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)
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
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }
  })

  async function setupSample(sampleId: string, hashChar: string) {
    database.insertSample({
      id: sampleId,
      sha256: hashChar.repeat(64),
      md5: hashChar.repeat(32),
      size: 8192,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })
    await workspaceManager.createWorkspace(sampleId)
  }

  async function seedRuntimeArtifact(
    sampleId: string,
    fileName: string,
    sourceName: string,
    api: string,
    createdAt: string
  ) {
    const workspace = await workspaceManager.createWorkspace(sampleId)
    const reportsDir = path.join(workspace.root, 'reports', 'dynamic')
    fs.mkdirSync(reportsDir, { recursive: true })
    const absolutePath = path.join(reportsDir, fileName)
    fs.writeFileSync(
      absolutePath,
      JSON.stringify(
        {
          schema_version: '0.1.0',
          source_format: 'normalized',
          evidence_kind: 'trace',
          source_name: sourceName,
          imported_at: createdAt,
          executed: true,
          raw_event_count: 1,
          api_calls: [
            {
              api,
              module: 'kernel32.dll',
              category: 'process_manipulation',
              count: 1,
              confidence: 0.9,
              sources: [sourceName],
            },
          ],
          memory_regions: [],
          modules: [],
          strings: [],
          stages: ['stage'],
          risk_hints: [],
          notes: [],
        },
        null,
        2
      ),
      'utf-8'
    )
    database.insertArtifact({
      id: `artifact-${fileName}`,
      sample_id: sampleId,
      type: 'dynamic_trace_json',
      path: `reports/dynamic/${fileName}`,
      sha256: 'a'.repeat(64),
      mime: 'application/json',
      created_at: createdAt,
    })
  }

  test('should apply input defaults', () => {
    const parsed = ReconstructWorkflowInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.path).toBe('auto')
    expect(parsed.topk).toBe(16)
    expect(parsed.validate_build).toBe(true)
    expect(parsed.run_harness).toBe(true)
    expect(parsed.build_timeout_ms).toBe(60000)
    expect(parsed.run_timeout_ms).toBe(30000)
    expect(parsed.evidence_scope).toBe('all')
    expect(parsed.include_plan).toBe(true)
    expect(parsed.include_obfuscation_fallback).toBe(true)
    expect(parsed.reuse_cached).toBe(true)
  })

  test('should require evidence_session_tag when evidence_scope=session', () => {
    expect(() =>
      ReconstructWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')
  })

  test('should require compare_evidence_session_tag when compare_evidence_scope=session', () => {
    expect(() =>
      ReconstructWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        compare_evidence_scope: 'session',
      })
    ).toThrow('compare_evidence_session_tag')
  })

  test('should return error when sample does not exist', async () => {
    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager)
    const result = await handler({ sample_id: 'sha256:' + 'f'.repeat(64) })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should auto-route to dotnet export path', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    await setupSample(sampleId, '1')

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          is_dotnet: true,
          dotnet_version: '6.0',
          target_framework: '.NET 6.0',
          suspected: [{ runtime: '.NET', confidence: 0.95, evidence: ['CLR'] }],
        },
      })
    const planHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          feasibility: 'high',
          confidence: 0.88,
          restoration_expectation: 'High-confidence C# structural restoration is feasible.',
          blockers: [],
          recommendations: ['Prioritize metadata-driven recovery'],
        },
      })
    const dotnetExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          export_root: 'reports/dotnet_reconstruct/demo',
          csproj_path: 'reports/dotnet_reconstruct/demo/RecoveredDotNet.csproj',
          readme_path: 'reports/dotnet_reconstruct/demo/README.md',
          metadata_path: 'reports/dotnet_reconstruct/demo/MANAGED_METADATA.json',
          reverse_notes_path: 'reports/dotnet_reconstruct/demo/REVERSE_NOTES.md',
          fallback_notes_path: null,
          managed_profile: {
            assembly_name: 'Recovered.Sample',
            assembly_version: '1.0.0.0',
            module_name: 'Recovered.Sample.dll',
            metadata_version: 'v4.0.30319',
            is_library: true,
            entry_point_token: null,
            type_count: 12,
            method_count: 38,
            namespace_count: 3,
            assembly_reference_count: 4,
            resource_count: 1,
            dominant_namespaces: ['Recovered.Sample'],
            notable_types: ['Recovered.Sample.Runner'],
            assembly_references: ['System.Runtime', 'System.Net.Http'],
            resources: ['config.json'],
            analysis_priorities: ['inspect_public_surface_and_host_integration'],
          },
          classes: [{}, {}],
        },
      })
    const nativeExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: false,
        errors: ['native should not be called'],
      })

    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
      runtimeDetectHandler,
      planHandler,
      nativeExportHandler,
      dotnetExportHandler,
    })

    const result = await handler({
      sample_id: sampleId,
      path: 'auto',
      export_name: 'demo',
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.selected_path).toBe('dotnet')
    expect(data.export.tool).toBe('dotnet.reconstruct.export')
    expect(data.export.class_count).toBe(2)
    expect(data.export.notes_path).toContain('REVERSE_NOTES.md')
    expect(data.export.metadata_path).toContain('MANAGED_METADATA.json')
    expect(data.export.managed_profile.assembly_name).toBe('Recovered.Sample')
    expect(data.plan).not.toBeNull()
    expect(data.runtime.is_dotnet).toBe(true)
    expect(data.notes.join(' ')).toContain('inspect_public_surface_and_host_integration')
    expect(dotnetExportHandler).toHaveBeenCalledTimes(1)
    expect(dotnetExportHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
      })
    )
    expect(nativeExportHandler).toHaveBeenCalledTimes(0)
  })

  test('should auto-route to native export path', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    await setupSample(sampleId, '2')

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          is_dotnet: false,
          suspected: [{ runtime: 'c++', confidence: 0.85, evidence: ['msvcrt'] }],
        },
      })
    const planHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          feasibility: 'medium',
          confidence: 0.62,
          restoration_expectation: 'Native semantic reconstruction is feasible.',
          blockers: [],
          recommendations: ['Prefer ranked functions first'],
        },
      })
    const nativeExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          export_root: 'reports/reconstruct/demo',
          manifest_path: 'reports/reconstruct/demo/manifest.json',
          gaps_path: 'reports/reconstruct/demo/gaps.md',
          notes_path: 'reports/reconstruct/demo/reverse_notes.md',
          build_validation: {
            status: 'passed',
            log_path: 'reports/reconstruct/demo/BUILD_VALIDATION.log',
            executable_path: 'reports/reconstruct/demo/reconstruct_harness.exe',
          },
          harness_validation: {
            status: 'passed',
            log_path: 'reports/reconstruct/demo/HARNESS_VALIDATION.log',
          },
          module_count: 3,
          unresolved_count: 5,
          binary_profile: {
            binary_role: 'dll',
            original_filename: 'demo.dll',
            export_count: 2,
            forwarder_count: 0,
            notable_exports: ['DllRegisterServer', 'RunRecon'],
            packed: true,
            packing_confidence: 0.76,
            analysis_priorities: ['trace_export_surface_first', 'unpack_or_deobfuscate_before_deep_semantics'],
          },
        },
      })
    const dotnetExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: false,
        errors: ['dotnet should not be called'],
      })

    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
      runtimeDetectHandler,
      planHandler,
      nativeExportHandler,
      dotnetExportHandler,
    })

    const result = await handler({
      sample_id: sampleId,
      path: 'auto',
      export_name: 'demo',
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.selected_path).toBe('native')
    expect(data.export.tool).toBe('code.reconstruct.export')
    expect(data.export.module_count).toBe(3)
    expect(data.export.unresolved_count).toBe(5)
    expect(data.export.notes_path).toContain('reverse_notes.md')
    expect(data.export.build_validation_status).toBe('passed')
    expect(data.export.harness_validation_status).toBe('passed')
    expect(data.export.build_log_path).toContain('BUILD_VALIDATION.log')
    expect(data.export.executable_path).toContain('reconstruct_harness.exe')
    expect(data.export.binary_profile.binary_role).toBe('dll')
    expect(data.notes.join(' ')).toContain('trace_export_surface_first')
    expect(data.notes.join(' ')).toContain('Native build validation: passed')
    expect(nativeExportHandler).toHaveBeenCalledTimes(1)
    expect(nativeExportHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        validate_build: true,
        run_harness: true,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
      })
    )
    expect(dotnetExportHandler).toHaveBeenCalledTimes(0)
  })

  test('should surface provenance and selection diffs in workflow output', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    await setupSample(sampleId, '9')
    await seedRuntimeArtifact(
      sampleId,
      'alpha.json',
      'alpha-session',
      'CreateRemoteThread',
      '2026-03-10T00:00:00.000Z'
    )
    await seedRuntimeArtifact(
      sampleId,
      'beta.json',
      'beta-session',
      'WriteProcessMemory',
      '2026-03-11T00:00:00.000Z'
    )
    await persistSemanticNameSuggestionsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-10T00:00:00.000Z',
      session_tag: 'semantic-alpha',
      suggestions: [
        {
          address: '0x401000',
          candidate_name: 'alpha_name',
          confidence: 0.8,
          why: 'alpha',
        },
      ],
    })
    await persistSemanticNameSuggestionsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:00:00.000Z',
      session_tag: 'semantic-beta',
      suggestions: [
        {
          address: '0x401000',
          candidate_name: 'beta_name',
          confidence: 0.9,
          why: 'beta',
        },
      ],
    })
    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-10T00:00:00.000Z',
      session_tag: 'semantic-alpha',
      explanations: [
        {
          address: '0x401000',
          summary: 'alpha explanation',
          behavior: 'alpha_behavior',
          confidence: 0.7,
        },
      ],
    })
    await persistSemanticFunctionExplanationsArtifact(workspaceManager, database, {
      schema_version: 1,
      sample_id: sampleId,
      created_at: '2026-03-11T00:00:00.000Z',
      session_tag: 'semantic-beta',
      explanations: [
        {
          address: '0x401000',
          summary: 'beta explanation',
          behavior: 'beta_behavior',
          confidence: 0.9,
        },
      ],
    })

    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
      runtimeDetectHandler: jest.fn(async () => ({
        ok: true,
        data: {
          is_dotnet: false,
          suspected: [{ runtime: 'c++', confidence: 0.85, evidence: ['msvcrt'] }],
        },
      })),
      planHandler: jest.fn(async () => ({
        ok: true,
        data: {
          feasibility: 'medium',
          confidence: 0.6,
          restoration_expectation: 'Native semantic reconstruction is feasible.',
          blockers: [],
          recommendations: ['Review low-confidence blocks'],
        },
      })),
      nativeExportHandler: jest.fn(async () => ({
        ok: true,
        data: {
          export_root: 'reports/reconstruct/compare',
          manifest_path: 'reports/reconstruct/compare/manifest.json',
          gaps_path: 'reports/reconstruct/compare/gaps.md',
          module_count: 2,
          unresolved_count: 1,
        },
      })),
    })

    const result = await handler({
      sample_id: sampleId,
      path: 'native',
      evidence_scope: 'session',
      evidence_session_tag: 'beta-session',
      compare_evidence_scope: 'session',
      compare_evidence_session_tag: 'alpha-session',
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-beta',
      compare_semantic_scope: 'session',
      compare_semantic_session_tag: 'semantic-alpha',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.provenance.runtime.session_tags).toContain('beta-session')
    expect(data.provenance.semantic_names.session_tags).toContain('semantic-beta')
    expect(data.selection_diffs.runtime.baseline.session_selector).toBe('alpha-session')
    expect(data.selection_diffs.semantic_names.baseline.session_selector).toBe('semantic-alpha')
    expect(data.selection_diffs.semantic_explanations.baseline.session_selector).toBe('semantic-alpha')
  })

  test('should reject forced dotnet path when runtime is not dotnet', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    await setupSample(sampleId, '3')

    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
      runtimeDetectHandler: jest
        .fn<(args: ToolArgs) => Promise<WorkerResult>>()
        .mockResolvedValue({
          ok: true,
          data: {
            is_dotnet: false,
            suspected: [{ runtime: 'c++', confidence: 0.8, evidence: ['msvcrt'] }],
          },
        }),
    })

    const result = await handler({
      sample_id: sampleId,
      path: 'dotnet',
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Requested dotnet path')
  })

  test('should reuse cached workflow result', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    await setupSample(sampleId, '4')

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          is_dotnet: false,
          suspected: [{ runtime: 'c++', confidence: 0.85, evidence: ['msvcrt'] }],
        },
      })
    const planHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          feasibility: 'medium',
          confidence: 0.6,
          restoration_expectation: 'Native semantic reconstruction is feasible.',
          blockers: [],
          recommendations: ['Review low-confidence blocks'],
        },
      })
    const nativeExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          export_root: 'reports/reconstruct/cached',
          manifest_path: 'reports/reconstruct/cached/manifest.json',
          gaps_path: 'reports/reconstruct/cached/gaps.md',
          module_count: 2,
          unresolved_count: 1,
        },
      })

    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
      runtimeDetectHandler,
      planHandler,
      nativeExportHandler,
    })

    const first = await handler({
      sample_id: sampleId,
      path: 'native',
      export_name: 'cached',
    })
    const second = await handler({
      sample_id: sampleId,
      path: 'native',
      export_name: 'cached',
    })

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    expect(runtimeDetectHandler).toHaveBeenCalledTimes(2)
    expect(planHandler).toHaveBeenCalledTimes(1)
    expect(nativeExportHandler).toHaveBeenCalledTimes(1)
    expect(second.warnings).toContain('Result from cache')
    expect((second.metrics as any)?.cached).toBe(true)
  })

  test('should fallback to native path when dotnet export fails', async () => {
    const sampleId = 'sha256:' + '5'.repeat(64)
    await setupSample(sampleId, '5')

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          is_dotnet: true,
          dotnet_version: '6.0',
          target_framework: '.NET 6.0',
        },
      })
    const planHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          feasibility: 'high',
          confidence: 0.82,
          restoration_expectation: 'dotnet expected',
          blockers: [],
          recommendations: [],
        },
      })
    const dotnetExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: false,
        errors: ['dotnet export failure'],
      })
    const nativeExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          export_root: 'reports/reconstruct/fallback_native',
          manifest_path: 'reports/reconstruct/fallback_native/manifest.json',
          gaps_path: 'reports/reconstruct/fallback_native/gaps.md',
          module_count: 4,
          unresolved_count: 2,
        },
      })

    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
      runtimeDetectHandler,
      planHandler,
      dotnetExportHandler,
      nativeExportHandler,
    })

    const result = await handler({
      sample_id: sampleId,
      path: 'auto',
      fallback_on_error: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.selected_path).toBe('native')
    expect(data.degraded).toBe(true)
    expect(data.stage_status.export_primary).toBe('failed')
    expect(data.stage_status.export_fallback).toBe('ok')
    expect(data.export.tool).toBe('code.reconstruct.export')
  })

  test('should return partial result when all exports fail and allow_partial=true', async () => {
    const sampleId = 'sha256:' + '6'.repeat(64)
    await setupSample(sampleId, '6')

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          is_dotnet: false,
          suspected: [{ runtime: 'c++', confidence: 0.78, evidence: ['msvcrt'] }],
        },
      })
    const planHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          feasibility: 'low',
          confidence: 0.45,
          restoration_expectation: 'partial only',
          blockers: ['packed'],
          recommendations: ['deobfuscate first'],
        },
      })
    const dotnetExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: false,
        errors: ['dotnet failed'],
      })
    const nativeExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: false,
        errors: ['native failed'],
      })

    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
      runtimeDetectHandler,
      planHandler,
      dotnetExportHandler,
      nativeExportHandler,
    })

    const result = await handler({
      sample_id: sampleId,
      path: 'native',
      fallback_on_error: true,
      allow_partial: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.degraded).toBe(true)
    expect(data.export).toBeNull()
    expect(data.stage_status.export_primary).toBe('failed')
    expect(data.stage_status.export_fallback).toBe('failed')
    expect(data.plan).not.toBeNull()
  })

  test('should fail when all exports fail and allow_partial=false', async () => {
    const sampleId = 'sha256:' + '7'.repeat(64)
    await setupSample(sampleId, '7')

    const handler = createReconstructWorkflowHandler(workspaceManager, database, cacheManager, {
      runtimeDetectHandler: jest
        .fn<(args: ToolArgs) => Promise<WorkerResult>>()
        .mockResolvedValue({
          ok: true,
          data: {
            is_dotnet: false,
          },
        }),
      planHandler: jest.fn<(args: ToolArgs) => Promise<WorkerResult>>().mockResolvedValue({
        ok: true,
        data: {
          feasibility: 'low',
          confidence: 0.4,
          restoration_expectation: 'partial only',
          blockers: [],
          recommendations: [],
        },
      }),
      nativeExportHandler: jest
        .fn<(args: ToolArgs) => Promise<WorkerResult>>()
        .mockResolvedValue({
          ok: false,
          errors: ['native failed'],
        }),
      dotnetExportHandler: jest
        .fn<(args: ToolArgs) => Promise<WorkerResult>>()
        .mockResolvedValue({
          ok: false,
          errors: ['dotnet failed'],
        }),
    })

    const result = await handler({
      sample_id: sampleId,
      path: 'native',
      fallback_on_error: true,
      allow_partial: false,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('allow_partial=false')
  })
})
