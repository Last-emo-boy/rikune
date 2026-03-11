/**
 * Unit tests for dotnet.types.list tool
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createDotNetTypesListHandler,
  DotNetTypesListInputSchema,
} from '../../src/tools/dotnet-types-list.js'

describe('dotnet.types.list tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-dotnet-types')
    testDbPath = path.join(process.cwd(), 'test-dotnet-types.db')
    testCachePath = path.join(process.cwd(), 'test-cache-dotnet-types')

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

  function buildMetadataResult(): WorkerResult {
    return {
      ok: true,
      data: {
        is_dotnet: true,
        assembly_name: 'Recovered.Sample',
        assembly_version: '1.0.0.0',
        module_name: 'Recovered.Sample.dll',
        metadata_version: 'v4.0.30319',
        dotnet_version: '8.0',
        target_framework: '.NETCoreApp,Version=v8.0',
        is_library: true,
        entry_point_token: null,
        assembly_references: [],
        resources: [],
        namespaces: [
          { name: 'Recovered.Sample', type_count: 1, method_count: 2 },
          { name: 'Recovered.Sample.Internal', type_count: 1, method_count: 1 },
        ],
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
                rva: 4112,
                attributes: ['public'],
                is_constructor: true,
                is_static: false,
              },
            ],
          },
          {
            token: '0x02000002',
            namespace: 'Recovered.Sample.Internal',
            name: 'HiddenWorker',
            full_name: 'Recovered.Sample.Internal.HiddenWorker',
            kind: 'class',
            visibility: 'internal',
            base_type: 'System.Object',
            method_count: 1,
            field_count: 0,
            nested_type_count: 0,
            flags: [],
            methods: [
              {
                name: 'Execute',
                token: '0x06000003',
                rva: 8192,
                attributes: ['assembly'],
                is_constructor: false,
                is_static: true,
              },
            ],
          },
        ],
        summary: {
          type_count: 2,
          method_count: 3,
          namespace_count: 2,
          assembly_reference_count: 0,
          resource_count: 0,
        },
      },
      warnings: ['metadata probe warning'],
      metrics: {
        elapsed_ms: 25,
        tool: 'dotnet.metadata.extract',
        cached: true,
      },
    }
  }

  test('should apply input defaults', () => {
    const parsed = DotNetTypesListInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.include_methods).toBe(false)
    expect(parsed.max_types).toBe(120)
    expect(parsed.max_methods_per_type).toBe(24)
    expect(parsed.force_refresh).toBe(false)
  })

  test('should return filtered type inventory', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    await setupSample(sampleId, '1')

    const metadataHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue(buildMetadataResult())

    const handler = createDotNetTypesListHandler(
      workspaceManager,
      database,
      cacheManager,
      { metadataHandler }
    )

    const result = await handler({
      sample_id: sampleId,
      namespace_prefix: 'Recovered.Sample',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.returned_type_count).toBe(2)
    expect(data.total_type_count).toBe(2)
    expect(data.types[0].full_name).toBe('Recovered.Sample.Runner')
    expect(data.types[0].is_public).toBe(true)
    expect(data.types[0].methods).toEqual([])
    expect(data.types[1].is_public).toBe(false)
    expect(result.warnings).toContain('metadata probe warning')
    expect(metadataHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        include_types: true,
        include_methods: false,
        max_types: 120,
      })
    )
  })

  test('should include methods and respect type truncation', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    await setupSample(sampleId, '2')

    const handler = createDotNetTypesListHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        metadataHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue(buildMetadataResult()),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      include_methods: true,
      max_types: 1,
      max_methods_per_type: 1,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.returned_type_count).toBe(1)
    expect(data.truncated).toBe(true)
    expect(data.types[0].methods).toHaveLength(1)
    expect(result.warnings).toContain('Type list truncated from 2 to 1.')
  })

  test('should surface metadata extraction failures', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    await setupSample(sampleId, '3')

    const handler = createDotNetTypesListHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        metadataHandler: jest
          .fn<(args: ToolArgs) => Promise<WorkerResult>>()
          .mockResolvedValue({
            ok: false,
            errors: ['Target sample is not recognized as a .NET assembly.'],
          }),
      }
    )

    const result = await handler({ sample_id: sampleId })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('Target sample is not recognized as a .NET assembly.')
  })
})
