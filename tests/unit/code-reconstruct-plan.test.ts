/**
 * Unit tests for code.reconstruct.plan tool
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createCodeReconstructPlanHandler,
  CodeReconstructPlanInputSchema,
} from '../../src/tools/code-reconstruct-plan.js'

describe('code.reconstruct.plan tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-reconstruct-plan')
    testDbPath = path.join(process.cwd(), 'test-reconstruct-plan.db')
    testCachePath = path.join(process.cwd(), 'test-cache-reconstruct-plan')

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

  test('should apply input defaults', () => {
    const parsed = CodeReconstructPlanInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.target_language).toBe('auto')
    expect(parsed.depth).toBe('standard')
    expect(parsed.include_decompiler).toBe(true)
    expect(parsed.include_strings).toBe(true)
  })

  test('should return error when sample does not exist', async () => {
    const handler = createCodeReconstructPlanHandler(workspaceManager, database, cacheManager)

    const result = await handler({
      sample_id: 'sha256:' + 'f'.repeat(64),
      target_language: 'auto',
      depth: 'standard',
      include_decompiler: true,
      include_strings: true,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should produce high feasibility plan for unpacked dotnet sample', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
      ok: true,
      data: {
        is_dotnet: true,
        suspected: [
          { runtime: '.NET', confidence: 0.95, evidence: ['CLR metadata'] },
        ],
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

    const handler = createCodeReconstructPlanHandler(
      workspaceManager,
      database,
      cacheManager,
      { runtimeDetectHandler, packerDetectHandler }
    )

    const result = await handler({
      sample_id: sampleId,
      target_language: 'auto',
      depth: 'deep',
      include_decompiler: true,
      include_strings: true,
    })

    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    const data = result.data as any
    expect(data.feasibility).toBe('high')
    const primaryRuntime = data.runtime_summary.primary_runtime.toLowerCase()
    expect(primaryRuntime.includes('dotnet') || primaryRuntime.includes('.net')).toBe(true)
    expect(Array.isArray(data.phases)).toBe(true)
    expect(data.phases.length).toBeGreaterThanOrEqual(3)
    expect(runtimeDetectHandler).toHaveBeenCalledTimes(1)
    expect(packerDetectHandler).toHaveBeenCalledTimes(1)
  })

  test('should cache reconstruction plan', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
      ok: true,
      data: {
        is_dotnet: false,
        suspected: [
          { runtime: 'c++', confidence: 0.75, evidence: ['msvcrt.dll'] },
        ],
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

    const handler = createCodeReconstructPlanHandler(
      workspaceManager,
      database,
      cacheManager,
      { runtimeDetectHandler, packerDetectHandler }
    )

    const input = {
      sample_id: sampleId,
      target_language: 'cpp',
      depth: 'standard',
      include_decompiler: true,
      include_strings: true,
    } as const

    const first = await handler(input)
    const second = await handler(input)

    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    expect(runtimeDetectHandler).toHaveBeenCalledTimes(1)
    expect(packerDetectHandler).toHaveBeenCalledTimes(1)
    expect(second.warnings).toContain('Result from cache')
    expect((second.metrics as any)?.cached).toBe(true)
  })

  test('should return low feasibility when runtime and packer data are unavailable', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const runtimeDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: false,
        errors: ['runtime worker unavailable'],
      })
    const packerDetectHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: false,
        errors: ['packer worker unavailable'],
      })

    const handler = createCodeReconstructPlanHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        runtimeDetectHandler,
        packerDetectHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      target_language: 'auto',
      depth: 'quick',
      include_decompiler: false,
      include_strings: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.feasibility).toBe('low')
    expect(result.warnings?.join(' ')).toContain('runtime.detect unavailable')
    expect(result.warnings?.join(' ')).toContain('packer.detect unavailable')
  })
})
