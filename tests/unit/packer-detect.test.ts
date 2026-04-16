/**
 * Unit tests for packer.detect tool
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { createPackerDetectHandler } from '../../src/plugins/static-triage/tools/packer-detect.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('packer.detect tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let handler: ReturnType<typeof createPackerDetectHandler>
  let tempDir: string
  let dbPath: string

  beforeEach(async () => {
    // Create temporary directory for test
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'packer-detect-test-'))
    dbPath = path.join(tempDir, 'test.db')

    // Initialize components
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(dbPath)
    cacheManager = new CacheManager(path.join(tempDir, 'cache'), database)

    // Create handler
    handler = createPackerDetectHandler(workspaceManager, database, cacheManager)
  })

  afterEach(async () => {
    // Clean up
    try {
      await fs.rm(tempDir, { recursive: true, force: true })
    } catch (error) {
      // Ignore cleanup errors
    }
  })

  test('should return error for non-existent sample', async () => {
    const result = await handler({
      sample_id: 'sha256:nonexistent',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should detect unpacked PE file', async () => {
    // Create a minimal PE file for testing
    const sampleData = createMinimalPE()
    const sampleId = await ingestTestSample(sampleData, workspaceManager, database)

    const result = await handler({
      sample_id: sampleId,
    })

    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    
    const data = result.data as {
      packed: boolean
      confidence: number
      detections: unknown[]
      methods: string[]
    }
    
    expect(data.packed).toBe(false)
    expect(data.confidence).toBe(0.0)
    expect(data.detections).toHaveLength(0)
  })

  test('should use specified engines', async () => {
    const sampleData = createMinimalPE()
    const sampleId = await ingestTestSample(sampleData, workspaceManager, database)

    const result = await handler({
      sample_id: sampleId,
      engines: ['entropy'],
    })

    expect(result.ok).toBe(true)
    expect(result.metrics?.engines_used).toEqual(['entropy'])
  })

  test('should use default engines when not specified', async () => {
    const sampleData = createMinimalPE()
    const sampleId = await ingestTestSample(sampleData, workspaceManager, database)

    const result = await handler({
      sample_id: sampleId,
    })

    expect(result.ok).toBe(true)
    expect(result.metrics?.engines_used).toEqual(['yara', 'entropy', 'entrypoint'])
  })

  test('should cache results', async () => {
    const sampleData = createMinimalPE()
    const sampleId = await ingestTestSample(sampleData, workspaceManager, database)

    // First call
    const result1 = await handler({
      sample_id: sampleId,
    })
    expect(result1.ok).toBe(true)

    // Second call should use cache
    const result2 = await handler({
      sample_id: sampleId,
    })
    expect(result2.ok).toBe(true)
    expect(result2.warnings).toContain('Result from cache')
  })

  test('should reuse cache for equivalent engine sets with different order', async () => {
    const sampleData = createMinimalPE()
    const sampleId = await ingestTestSample(sampleData, workspaceManager, database)

    const first = await handler({
      sample_id: sampleId,
      engines: ['entropy', 'yara'],
    })
    expect(first.ok).toBe(true)

    const second = await handler({
      sample_id: sampleId,
      engines: ['yara', 'entropy'],
    })
    expect(second.ok).toBe(true)
    expect(second.warnings).toContain('Result from cache')
  })

  test('should return metrics', async () => {
    const sampleData = createMinimalPE()
    const sampleId = await ingestTestSample(sampleData, workspaceManager, database)

    const result = await handler({
      sample_id: sampleId,
    })

    expect(result.ok).toBe(true)
    expect(result.metrics).toBeDefined()
    expect(result.metrics?.elapsed_ms).toBeGreaterThan(0)
    expect(result.metrics?.tool).toBe('packer.detect')
  })

  test('should handle different engine combinations', async () => {
    const sampleData = createMinimalPE()
    const sampleId = await ingestTestSample(sampleData, workspaceManager, database)

    // Test with only YARA
    const result1 = await handler({
      sample_id: sampleId,
      engines: ['yara'],
    })
    expect(result1.ok).toBe(true)

    // Test with only entropy
    const result2 = await handler({
      sample_id: sampleId,
      engines: ['entropy'],
    })
    expect(result2.ok).toBe(true)

    // Test with only entrypoint
    const result3 = await handler({
      sample_id: sampleId,
      engines: ['entrypoint'],
    })
    expect(result3.ok).toBe(true)

    // Test with all engines
    const result4 = await handler({
      sample_id: sampleId,
      engines: ['yara', 'entropy', 'entrypoint'],
    })
    expect(result4.ok).toBe(true)
  })
})

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create a minimal valid PE file for testing
 */
function createMinimalPE(): Buffer {
  const buffer = Buffer.alloc(512)
  
  // DOS Header
  buffer.write('MZ', 0, 'ascii')
  buffer.writeUInt32LE(64, 60) // e_lfanew
  
  // PE Signature
  buffer.write('PE\x00\x00', 64, 'ascii')
  
  // COFF Header
  buffer.writeUInt16LE(0x014c, 68) // Machine (IMAGE_FILE_MACHINE_I386)
  buffer.writeUInt16LE(1, 70) // NumberOfSections
  buffer.writeUInt16LE(224, 84) // SizeOfOptionalHeader
  buffer.writeUInt16LE(0x010F, 86) // Characteristics
  
  // Optional Header
  buffer.writeUInt16LE(0x010b, 88) // Magic (PE32)
  buffer.writeUInt32LE(0x1000, 104) // AddressOfEntryPoint
  buffer.writeUInt32LE(0x1000, 108) // BaseOfCode
  buffer.writeUInt32LE(0x2000, 112) // BaseOfData
  buffer.writeUInt32LE(0x400000, 116) // ImageBase
  buffer.writeUInt32LE(0x1000, 120) // SectionAlignment
  buffer.writeUInt32LE(0x200, 124) // FileAlignment
  buffer.writeUInt32LE(0x3000, 144) // SizeOfImage
  buffer.writeUInt32LE(0x200, 148) // SizeOfHeaders
  
  // Section Header
  buffer.write('.text\x00\x00\x00', 312, 'ascii') // Name
  buffer.writeUInt32LE(0x1000, 320) // VirtualSize
  buffer.writeUInt32LE(0x1000, 324) // VirtualAddress
  buffer.writeUInt32LE(0x200, 328) // SizeOfRawData
  buffer.writeUInt32LE(0x200, 332) // PointerToRawData
  buffer.writeUInt32LE(0x60000020, 348) // Characteristics
  
  return buffer
}

/**
 * Ingest a test sample and return its sample_id
 */
async function ingestTestSample(
  data: Buffer,
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
): Promise<string> {
  const crypto = await import('crypto')
  const sha256 = crypto.createHash('sha256').update(data).digest('hex')
  const md5 = crypto.createHash('md5').update(data).digest('hex')
  const sampleId = `sha256:${sha256}`

  // Create workspace
  const workspace = await workspaceManager.createWorkspace(sampleId)

  // Store sample file
  await fs.writeFile(path.join(workspace.original, 'sample.exe'), data)

  // Insert into database
  database.insertSample({
    id: sampleId,
    sha256,
    md5,
    size: data.length,
    file_type: 'PE32',
    created_at: new Date().toISOString(),
    source: 'test',
  })

  return sampleId
}
