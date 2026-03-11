/**
 * Unit tests for dotnet.metadata.extract tool
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createDotNetMetadataExtractHandler,
  DotNetMetadataExtractInputSchema,
} from '../../src/tools/dotnet-metadata-extract.js'

describe('dotnet.metadata.extract tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-dotnet-metadata')
    testDbPath = path.join(process.cwd(), 'test-dotnet-metadata.db')
    testCachePath = path.join(process.cwd(), 'test-cache-dotnet-metadata')

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
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.dll'), 'managed sample placeholder', 'utf-8')
  }

  function buildRuntimeResult(): WorkerResult {
    return {
      ok: true,
      data: {
        is_dotnet: true,
        dotnet_version: '8.0',
        target_framework: '.NET 8.0',
        suspected: [{ runtime: '.NET', confidence: 0.96, evidence: ['CLR'] }],
      },
    }
  }

  function buildProbeResult() {
    return {
      ok: true,
      data: {
        is_dotnet: true,
        assembly_name: 'Recovered.Sample',
        assembly_version: '1.0.0.0',
        module_name: 'Recovered.Sample.dll',
        metadata_version: 'v4.0.30319',
        target_framework: '.NETCoreApp,Version=v8.0',
        is_library: true,
        entry_point_token: null,
        assembly_references: [{ name: 'System.Runtime', version: '8.0.0.0', culture: null }],
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
            ],
          },
        ],
        summary: {
          type_count: 1,
          method_count: 2,
          namespace_count: 1,
          assembly_reference_count: 1,
          resource_count: 1,
        },
      },
      warnings: ['Type list truncated from 10 to 1.'],
    }
  }

  test('should apply input defaults', () => {
    const parsed = DotNetMetadataExtractInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.include_types).toBe(true)
    expect(parsed.include_methods).toBe(true)
    expect(parsed.max_types).toBe(80)
    expect(parsed.max_methods_per_type).toBe(24)
    expect(parsed.force_refresh).toBe(false)
  })

  test('should reject non-dotnet runtime targets', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    await setupSample(sampleId, '1')

    const handler = createDotNetMetadataExtractHandler(
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

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('not recognized as a .NET assembly')
  })

  test('should merge runtime hints with managed metadata probe output', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    await setupSample(sampleId, '2')

    const probeRunner = jest
      .fn<(samplePath: string, options: any) => Promise<any>>()
      .mockResolvedValue(buildProbeResult())
    const handler = createDotNetMetadataExtractHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        runtimeDetectHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue(buildRuntimeResult()),
        probeRunner,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      max_types: 12,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.is_dotnet).toBe(true)
    expect(data.dotnet_version).toBe('8.0')
    expect(data.target_framework).toBe('.NET 8.0')
    expect(data.assembly_name).toBe('Recovered.Sample')
    expect(data.types[0].full_name).toBe('Recovered.Sample.Runner')
    expect(probeRunner).toHaveBeenCalledTimes(1)
    expect(result.warnings).toContain('Type list truncated from 10 to 1.')
  })

  test('should reuse cached metadata extraction results', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    await setupSample(sampleId, '3')

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(buildRuntimeResult())
    const probeRunner = jest
      .fn<(samplePath: string, options: any) => Promise<any>>()
      .mockResolvedValue(buildProbeResult())

    const handler = createDotNetMetadataExtractHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        runtimeDetectHandler,
        probeRunner,
      }
    )

    const first = await handler({ sample_id: sampleId })
    const second = await handler({ sample_id: sampleId })

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    expect(runtimeDetectHandler).toHaveBeenCalledTimes(2)
    expect(probeRunner).toHaveBeenCalledTimes(1)
    expect(second.warnings).toContain('Result from cache')
    expect((second.metrics as any)?.cached).toBe(true)
  })
})
