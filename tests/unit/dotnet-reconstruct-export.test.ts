/**
 * Unit tests for dotnet.reconstruct.export tool
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createDotNetReconstructExportHandler,
  DotNetReconstructExportInputSchema,
} from '../../src/tools/dotnet-reconstruct-export.js'

describe('dotnet.reconstruct.export tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-dotnet-reconstruct')
    testDbPath = path.join(process.cwd(), 'test-dotnet-reconstruct.db')
    testCachePath = path.join(process.cwd(), 'test-cache-dotnet-reconstruct')

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

  function buildReconstructExportResult(): WorkerResult {
    return {
      ok: true,
      data: {
        modules: [
          {
            name: 'network_ops',
            confidence: 0.78,
            functions: [
              {
                function: 'net_init',
                address: '0x401000',
                confidence: 0.8,
                gaps: ['unresolved_data_symbols'],
              },
            ],
          },
          {
            name: 'core',
            confidence: 0.62,
            functions: [
              {
                function: 'core_main',
                address: '0x402000',
                confidence: 0.62,
                gaps: [],
              },
            ],
          },
        ],
        gaps_path: 'reports/reconstruct/demo/gaps.md',
      },
    }
  }

  function buildManagedMetadataResult(): WorkerResult {
    return {
      ok: true,
      data: {
        is_dotnet: true,
        assembly_name: 'Recovered.Sample',
        assembly_version: '1.0.0.0',
        module_name: 'Recovered.Sample.dll',
        metadata_version: 'v4.0.30319',
        dotnet_version: '8.0',
        target_framework: '.NET 8.0',
        is_library: true,
        entry_point_token: null,
        assembly_references: [
          { name: 'System.Runtime', version: '8.0.0.0', culture: null },
          { name: 'System.Net.Http', version: '8.0.0.0', culture: null },
        ],
        resources: [{ name: 'config.json', attributes: 'Public', implementation: 'embedded' }],
        namespaces: [{ name: 'Recovered.Sample', type_count: 1, method_count: 2 }],
        types: [
          {
            token: '0x02000001',
            namespace: 'Recovered.Sample',
            name: 'Runner',
            full_name: 'Recovered.Sample.Runner',
            kind: 'class',
            visibility: 'public',
            base_type: 'System.Object',
            method_count: 2,
            field_count: 1,
            nested_type_count: 0,
            flags: [],
            methods: [
              {
                name: 'Run',
                token: '0x06000001',
                rva: 4096,
                attributes: ['public'],
                is_constructor: false,
                is_static: false,
              },
              {
                name: '.ctor',
                token: '0x06000002',
                rva: 0,
                attributes: ['public', 'special_name'],
                is_constructor: true,
                is_static: false,
              },
            ],
          },
        ],
        summary: {
          type_count: 1,
          method_count: 2,
          namespace_count: 1,
          assembly_reference_count: 2,
          resource_count: 1,
        },
      },
    }
  }

  test('should apply input defaults', () => {
    const parsed = DotNetReconstructExportInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.topk).toBe(16)
    expect(parsed.project_name).toBe('RecoveredDotNet')
    expect(parsed.namespace).toBe('Recovered')
    expect(parsed.include_metadata_types).toBe(true)
    expect(parsed.max_managed_types).toBe(64)
    expect(parsed.include_obfuscation_fallback).toBe(true)
    expect(parsed.validate_build).toBe(true)
    expect(parsed.build_timeout_ms).toBe(45000)
    expect(parsed.evidence_scope).toBe('all')
    expect(parsed.reuse_cached).toBe(true)
  })

  test('should require evidence_session_tag when evidence_scope=session', () => {
    expect(() =>
      DotNetReconstructExportInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')
  })

  test('should return error when sample does not exist', async () => {
    const handler = createDotNetReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager
    )

    const result = await handler({
      sample_id: 'sha256:' + 'f'.repeat(64),
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should return error when runtime is not dotnet', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    await setupSample(sampleId, '1')

    const handler = createDotNetReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        runtimeDetectHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: true,
            data: {
              is_dotnet: false,
              suspected: [{ runtime: 'c++', confidence: 0.8, evidence: ['msvcrt'] }],
            },
          }),
      }
    )

    const result = await handler({
      sample_id: sampleId,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('not recognized as .NET')
  })

  test('should export dotnet project skeleton with fallback notes when packed', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    await setupSample(sampleId, '2')

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          is_dotnet: true,
          dotnet_version: '4.8',
          target_framework: '.NET Framework 4.8',
          suspected: [{ runtime: '.NET', confidence: 0.95, evidence: ['CLR'] }],
        },
      })
    const packerDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          packed: true,
          confidence: 0.85,
        },
      })
    const reconstructExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(buildReconstructExportResult())
    const dotNetMetadataHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(buildManagedMetadataResult())
    const buildValidator = jest
      .fn<(csprojPath: string, cwd: string, timeoutMs: number) => Promise<any>>()
      .mockResolvedValue({
        attempted: true,
        status: 'passed',
        command: 'dotnet build',
        dotnet_cli_available: true,
        exit_code: 0,
        timed_out: false,
        stdout: 'Build succeeded.',
        stderr: '',
        error: null,
      })

    const handler = createDotNetReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        runtimeDetectHandler,
        packerDetectHandler,
        reconstructExportHandler,
        dotNetMetadataHandler,
        buildValidator,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      project_name: 'RecoveredSample',
      namespace: 'Recovered.Sample',
      export_name: 'dotnet_export',
      topk: 10,
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.is_dotnet).toBe(true)
    expect(data.packed).toBe(true)
    expect(data.csproj_path).toContain('.csproj')
    expect(data.readme_path).toContain('README.md')
    expect(data.metadata_path).toContain('MANAGED_METADATA.json')
    expect(data.reverse_notes_path).toContain('REVERSE_NOTES.md')
    expect(data.fallback_notes_path).toContain('IL_FALLBACK_NOTES.md')
    expect(data.degraded_mode).toBe(true)
    expect(Array.isArray(data.degradation_reasons)).toBe(true)
    expect(data.managed_profile).toBeDefined()
    expect(data.managed_profile.assembly_name).toBe('Recovered.Sample')
    expect(data.build_validation.status).toBe('passed')
    expect(data.build_validation.log_path).toContain('BUILD_VALIDATION.log')
    expect(Array.isArray(data.classes)).toBe(true)
    expect(data.classes.length).toBeGreaterThan(0)
    expect(data.classes.some((item: any) => item.source === 'metadata')).toBe(true)
    expect(data.classes.some((item: any) => item.source === 'module')).toBe(true)
    expect(reconstructExportHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
      })
    )

    const workspace = await workspaceManager.getWorkspace(sampleId)
    const csprojAbs = path.join(workspace.root, data.csproj_path)
    const readmeAbs = path.join(workspace.root, data.readme_path)
    const metadataAbs = path.join(workspace.root, data.metadata_path)
    const reverseNotesAbs = path.join(workspace.root, data.reverse_notes_path)
    const fallbackAbs = path.join(workspace.root, data.fallback_notes_path)
    const buildLogAbs = path.join(workspace.root, data.build_validation.log_path)
    expect(fs.existsSync(csprojAbs)).toBe(true)
    expect(fs.existsSync(readmeAbs)).toBe(true)
    expect(fs.existsSync(metadataAbs)).toBe(true)
    expect(fs.existsSync(reverseNotesAbs)).toBe(true)
    expect(fs.existsSync(fallbackAbs)).toBe(true)
    expect(fs.existsSync(buildLogAbs)).toBe(true)
    expect(result.artifacts?.length).toBeGreaterThanOrEqual(6)
    expect(result.artifacts?.some((artifact: any) => artifact.type === 'dotnet_metadata')).toBe(true)
    expect(result.artifacts?.some((artifact: any) => artifact.type === 'dotnet_reverse_notes')).toBe(true)
  })

  test('should cache dotnet reconstruction output', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    await setupSample(sampleId, '3')

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
    const packerDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          packed: false,
          confidence: 0.1,
        },
      })
    const reconstructExportHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(buildReconstructExportResult())
    const dotNetMetadataHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(buildManagedMetadataResult())
    const buildValidator = jest
      .fn<(csprojPath: string, cwd: string, timeoutMs: number) => Promise<any>>()
      .mockResolvedValue({
        attempted: true,
        status: 'passed',
        command: 'dotnet build',
        dotnet_cli_available: true,
        exit_code: 0,
        timed_out: false,
        stdout: 'Build succeeded.',
        stderr: '',
        error: null,
      })

    const handler = createDotNetReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        runtimeDetectHandler,
        packerDetectHandler,
        reconstructExportHandler,
        dotNetMetadataHandler,
        buildValidator,
      }
    )

    const first = await handler({
      sample_id: sampleId,
      export_name: 'dotnet_cached',
    })
    const second = await handler({
      sample_id: sampleId,
      export_name: 'dotnet_cached',
    })

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    expect(runtimeDetectHandler).toHaveBeenCalledTimes(2)
    expect(packerDetectHandler).toHaveBeenCalledTimes(1)
    expect(reconstructExportHandler).toHaveBeenCalledTimes(1)
    expect(dotNetMetadataHandler).toHaveBeenCalledTimes(1)
    expect(buildValidator).toHaveBeenCalledTimes(1)
    expect(second.warnings).toContain('Result from cache')
    expect((second.metrics as any)?.cached).toBe(true)
  })

  test('should mark degraded mode when build validation fails', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    await setupSample(sampleId, '4')

    const handler = createDotNetReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        runtimeDetectHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: true,
            data: {
              is_dotnet: true,
              dotnet_version: '8.0',
              target_framework: '.NET 8.0',
            },
          }),
        packerDetectHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: true,
            data: {
              packed: false,
              confidence: 0.1,
            },
          }),
        reconstructExportHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue(buildReconstructExportResult()),
        dotNetMetadataHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue(buildManagedMetadataResult()),
        buildValidator: jest
          .fn<(csprojPath: string, cwd: string, timeoutMs: number) => Promise<any>>()
          .mockResolvedValue({
            attempted: true,
            status: 'failed',
            command: 'dotnet build',
            dotnet_cli_available: true,
            exit_code: 1,
            timed_out: false,
            stdout: '',
            stderr: 'compile error',
            error: 'dotnet build failed with exit code 1',
          }),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'dotnet_failed_build',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.degraded_mode).toBe(true)
    expect(data.build_validation.status).toBe('failed')
    expect(data.fallback_notes_path).toContain('IL_FALLBACK_NOTES.md')
    expect((result.warnings || []).join(' ')).toContain('build validation failed')
  })

  test('should still export metadata-driven skeletons when native reconstruction is unavailable', async () => {
    const sampleId = 'sha256:' + '5'.repeat(64)
    await setupSample(sampleId, '5')

    const handler = createDotNetReconstructExportHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        runtimeDetectHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: true,
            data: {
              is_dotnet: true,
              dotnet_version: '8.0',
              target_framework: '.NET 8.0',
            },
          }),
        packerDetectHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: true,
            data: {
              packed: false,
              confidence: 0.05,
            },
          }),
        reconstructExportHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: false,
            errors: ['ghidra decompile unavailable'],
          }),
        dotNetMetadataHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue(buildManagedMetadataResult()),
        buildValidator: jest
          .fn<(csprojPath: string, cwd: string, timeoutMs: number) => Promise<any>>()
          .mockResolvedValue({
            attempted: true,
            status: 'passed',
            command: 'dotnet build',
            dotnet_cli_available: true,
            exit_code: 0,
            timed_out: false,
            stdout: 'Build succeeded.',
            stderr: '',
            error: null,
          }),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      export_name: 'metadata_only',
      include_metadata_types: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.degraded_mode).toBe(true)
    expect(data.managed_profile.assembly_name).toBe('Recovered.Sample')
    expect(data.classes.length).toBeGreaterThan(0)
    expect(data.classes.every((item: any) => item.source === 'metadata')).toBe(true)
    expect((result.warnings || []).join(' ')).toContain('module reconstruction unavailable')
  })
})
