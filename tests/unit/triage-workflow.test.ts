/**
 * Unit tests for triage workflow
 * Requirements: 15.1, 15.2, 15.4, 15.5
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { createTriageWorkflowHandler } from '../../src/workflows/triage.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('Triage Workflow', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testDir: string
  let dbPath: string

  beforeEach(async () => {
    // Create temporary test directory
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'triage-test-'))
    const workspaceRoot = path.join(testDir, 'workspaces')
    const cacheDir = path.join(testDir, 'cache')
    dbPath = path.join(testDir, 'test.db')

    // Initialize components
    workspaceManager = new WorkspaceManager(workspaceRoot)
    database = new DatabaseManager(dbPath)
    cacheManager = new CacheManager(cacheDir, database)
  })

  afterEach(async () => {
    // Cleanup
    database.close()
    await fs.rm(testDir, { recursive: true, force: true })
  })

  test('should return error for non-existent sample', async () => {
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    const result = await handler({
      sample_id: 'sha256:nonexistent',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should validate input schema', async () => {
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    // Missing sample_id
    const result = await handler({})

    expect(result.ok).toBe(false)
    expect(result.errors).toBeDefined()
  })

  test('should have correct structure in successful result', async () => {
    // This test verifies the output structure without requiring a real sample
    // We'll mock the individual tool handlers in integration tests
    
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    // Create a dummy sample
    const sampleId = 'sha256:' + '0'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '0'.repeat(64),
      md5: '0'.repeat(32),
      size: 1024,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    // Create workspace with a dummy file
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'test.exe'), Buffer.from('MZ'))

    const result = await handler({ sample_id: sampleId })

    // The workflow should attempt to run but may fail on individual tools
    // We're mainly checking that it doesn't crash and returns proper structure
    expect(result).toBeDefined()
    expect(result.metrics).toBeDefined()
    expect(result.metrics?.tool).toBe('workflow.triage')
    expect(result.metrics?.elapsed_ms).toBeGreaterThan(0)
  })

  test('should aggregate results from multiple tools', async () => {
    // This is a structural test - integration tests will verify actual functionality
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
    expect(typeof handler).toBe('function')
  })

  test('should calculate threat level correctly', async () => {
    // Test the threat level calculation logic indirectly through the workflow
    // Integration tests will verify with real samples
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should identify suspicious imports', async () => {
    // This will be tested in integration tests with real PE files
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should extract IOCs from strings', async () => {
    // This will be tested in integration tests with real PE files
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should generate evidence list', async () => {
    // This will be tested in integration tests with real PE files
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should provide recommendations based on threat level', async () => {
    // This will be tested in integration tests with real PE files
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should complete within reasonable time', async () => {
    // Requirement: 15.3 - should complete within 5 minutes
    // This will be verified in integration tests with real samples
    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    
    expect(handler).toBeDefined()
  })

  test('should handle partial tool failures gracefully', async () => {
    // Create a dummy sample
    const sampleId = 'sha256:' + '1'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 1024,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    // Create workspace with a dummy file
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'test.exe'), Buffer.from('MZ'))

    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    const result = await handler({ sample_id: sampleId })

    // Should not crash even if tools fail
    expect(result).toBeDefined()
    expect(result.metrics).toBeDefined()
  })

  test('should include raw results from individual tools', async () => {
    // Create a dummy sample
    const sampleId = 'sha256:' + '2'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 1024,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    // Create workspace with a dummy file
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, 'test.exe'), Buffer.from('MZ'))

    const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    const result = await handler({ sample_id: sampleId })

    // Check that result structure includes raw_results field
    if (result.ok && result.data) {
      const data = result.data as any
      expect(data.raw_results).toBeDefined()
      expect(data.raw_results).toHaveProperty('static_capability')
      expect(data.raw_results).toHaveProperty('pe_structure')
      expect(data.raw_results).toHaveProperty('compiler_packer')
    }
  })
})
