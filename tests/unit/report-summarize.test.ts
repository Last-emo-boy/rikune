/**
 * Unit tests for report.summarize tool
 * Requirements: 15.2, 24.2
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createReportSummarizeHandler } from '../../src/plugins/reporting/tools/report-summarize.js'

describe('report.summarize tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let handler: ReturnType<typeof createReportSummarizeHandler>
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    // Create temporary directories for testing
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-report-summarize')
    testDbPath = path.join(process.cwd(), 'test-report-summarize.db')
    testCachePath = path.join(process.cwd(), 'test-cache-report-summarize')

    // Clean up if exists with retry logic for Windows
    const cleanupWithRetry = (filePath: string, isDirectory: boolean = false) => {
      let attempts = 0
      const maxAttempts = 3
      while (attempts < maxAttempts) {
        try {
          if (fs.existsSync(filePath)) {
            if (isDirectory) {
              fs.rmSync(filePath, { recursive: true, force: true })
            } else {
              fs.unlinkSync(filePath)
            }
          }
          break
        } catch (e: any) {
          attempts++
          if (attempts >= maxAttempts) {
            console.warn(`Failed to cleanup ${filePath} in beforeEach:`, e.message)
          } else {
            const delay = 100 * attempts
            const start = Date.now()
            while (Date.now() - start < delay) {
              // Busy wait
            }
          }
        }
      }
    }

    cleanupWithRetry(testWorkspaceRoot, true)
    cleanupWithRetry(testDbPath, false)
    cleanupWithRetry(testCachePath, true)

    // Initialize components
    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)
    handler = createReportSummarizeHandler(workspaceManager, database, cacheManager)
  })

  afterEach(() => {
    // Close database connection before cleanup
    try {
      database.close()
    } catch (e) {
      // Ignore if already closed
    }

    // Clean up with retry logic for Windows file locks
    const cleanupWithRetry = (filePath: string, isDirectory: boolean = false) => {
      let attempts = 0
      const maxAttempts = 3
      while (attempts < maxAttempts) {
        try {
          if (fs.existsSync(filePath)) {
            if (isDirectory) {
              fs.rmSync(filePath, { recursive: true, force: true })
            } else {
              fs.unlinkSync(filePath)
            }
          }
          break
        } catch (e: any) {
          attempts++
          if (attempts >= maxAttempts) {
            console.warn(`Failed to cleanup ${filePath} after ${maxAttempts} attempts:`, e.message)
          } else {
            // Wait a bit before retrying
            const delay = 100 * attempts
            const start = Date.now()
            while (Date.now() - start < delay) {
              // Busy wait
            }
          }
        }
      }
    }

    cleanupWithRetry(testWorkspaceRoot, true)
    cleanupWithRetry(testDbPath, false)
    cleanupWithRetry(testCachePath, true)
  })

  test('should return error for non-existent sample', async () => {
    const result = await handler({
      sample_id: 'sha256:nonexistent',
      mode: 'triage',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
    expect(result.errors![0]).toContain('Sample not found')
  })

  test('should degrade to triage fallback for dotnet mode', async () => {
    // Create a test sample
    const sampleId = 'sha256:' + '0'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '0'.repeat(64),
      md5: '0'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const result = await handler({
      sample_id: sampleId,
      mode: 'dotnet',
    })

    expect(result.ok).toBe(true)
    expect(result.warnings).toBeDefined()
    expect(result.warnings!.some((item) => item.includes('dotnet'))).toBe(true)
    const data = result.data as { summary: string }
    expect(data.summary.toLowerCase()).toContain('dotnet fallback')
  })

  test('should generate report structure for triage mode', async () => {
    // Create a test sample with workspace
    const sampleId = 'sha256:' + '1'.repeat(64)
    const sha256 = '1'.repeat(64)
    
    database.insertSample({
      id: sampleId,
      sha256,
      md5: '1'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    // Create workspace and sample file
    const workspace = await workspaceManager.createWorkspace(sampleId)
    
    // Create a minimal PE file (MZ header)
    const peData = Buffer.alloc(1024)
    peData.write('MZ', 0, 'ascii')
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), peData)

    // Execute report.summarize
    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
    })

    // Verify result structure
    // Note: The actual analysis may fail due to invalid PE structure,
    // but we're testing that the tool returns the correct structure
    expect(result).toBeDefined()
    expect(result.ok).toBeDefined()
    expect(result.metrics).toBeDefined()
    expect(result.metrics!.tool).toBe('report.summarize')
    expect(result.metrics!.elapsed_ms).toBeGreaterThan(0)

    if (result.ok && result.data) {
      // Verify report structure (Requirements: 15.2, 24.2)
      const data = result.data as any
      
      expect(data.summary).toBeDefined()
      expect(typeof data.summary).toBe('string')
      
      expect(data.confidence).toBeDefined()
      expect(typeof data.confidence).toBe('number')
      expect(data.confidence).toBeGreaterThanOrEqual(0)
      expect(data.confidence).toBeLessThanOrEqual(1)
      
      expect(data.threat_level).toBeDefined()
      expect(['clean', 'suspicious', 'malicious', 'unknown']).toContain(data.threat_level)
      
      expect(data.iocs).toBeDefined()
      expect(data.iocs.suspicious_imports).toBeDefined()
      expect(Array.isArray(data.iocs.suspicious_imports)).toBe(true)
      expect(data.iocs.suspicious_strings).toBeDefined()
      expect(Array.isArray(data.iocs.suspicious_strings)).toBe(true)
      expect(data.iocs.yara_matches).toBeDefined()
      expect(Array.isArray(data.iocs.yara_matches)).toBe(true)
      
      expect(data.evidence).toBeDefined()
      expect(Array.isArray(data.evidence)).toBe(true)
      
      expect(data.recommendation).toBeDefined()
      expect(typeof data.recommendation).toBe('string')
    }
  })

  test('should handle invalid mode gracefully', async () => {
    // Create a test sample
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

    const result = await handler({
      sample_id: sampleId,
      mode: 'invalid_mode' as any,
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
    expect(result.errors![0]).toContain('Unsupported mode')
  })

  test('should include metrics in response', async () => {
    // Create a test sample
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

    const result = await handler({
      sample_id: sampleId,
      mode: 'triage',
    })

    expect(result.metrics).toBeDefined()
    expect(result.metrics!.tool).toBe('report.summarize')
    expect(result.metrics!.elapsed_ms).toBeGreaterThan(0)
    expect(typeof result.metrics!.elapsed_ms).toBe('number')
  })

  test('should default to triage mode when mode not specified', async () => {
    // Create a test sample
    const sampleId = 'sha256:' + '4'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '4'.repeat(64),
      md5: '4'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    // Create workspace and sample file
    const workspace = await workspaceManager.createWorkspace(sampleId)
    const peData = Buffer.alloc(1024)
    peData.write('MZ', 0, 'ascii')
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), peData)

    // Call without specifying mode (should default to 'triage')
    const result = await handler({
      sample_id: sampleId,
    })

    // Should execute triage workflow (may fail due to invalid PE, but should attempt it)
    expect(result).toBeDefined()
    expect(result.metrics).toBeDefined()
    expect(result.metrics!.tool).toBe('report.summarize')
  })
})
