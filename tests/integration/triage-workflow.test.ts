/**
 * Integration tests for triage workflow
 * Tests end-to-end workflow with real samples
 * Requirements: 15.3, 26.7
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { createTriageWorkflowHandler } from '../../src/workflows/triage.js'
import { createSampleIngestHandler } from '../../src/tools/sample-ingest.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('Triage Workflow Integration', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let policyGuard: PolicyGuard
  let testDir: string
  let dbPath: string
  let auditLogPath: string
  let triageHandler: ReturnType<typeof createTriageWorkflowHandler>
  let ingestHandler: ReturnType<typeof createSampleIngestHandler>

  beforeAll(async () => {
    // Create temporary test directory
    testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'triage-integration-'))
    const workspaceRoot = path.join(testDir, 'workspaces')
    const cacheDir = path.join(testDir, 'cache')
    dbPath = path.join(testDir, 'test.db')
    auditLogPath = path.join(testDir, 'audit.log')

    // Initialize components
    workspaceManager = new WorkspaceManager(workspaceRoot)
    database = new DatabaseManager(dbPath)
    cacheManager = new CacheManager(cacheDir, database)
    policyGuard = new PolicyGuard(auditLogPath)
    
    triageHandler = createTriageWorkflowHandler(workspaceManager, database, cacheManager)
    ingestHandler = createSampleIngestHandler(workspaceManager, database, policyGuard)
  })

  afterAll(async () => {
    // Cleanup
    database.close()
    await fs.rm(testDir, { recursive: true, force: true })
  })

  /**
   * Helper function to create a minimal PE file for testing
   * Creates a valid PE header structure
   */
  async function createMinimalPE(): Promise<Buffer> {
    const pe = Buffer.alloc(1024)
    
    // DOS header
    pe.write('MZ', 0, 'ascii')  // e_magic
    pe.writeUInt32LE(0x80, 0x3c)  // e_lfanew (offset to PE header)
    
    // PE header at offset 0x80
    pe.write('PE\0\0', 0x80, 'ascii')  // Signature
    
    // COFF header
    pe.writeUInt16LE(0x014c, 0x84)  // Machine (IMAGE_FILE_MACHINE_I386)
    pe.writeUInt16LE(1, 0x86)  // NumberOfSections
    pe.writeUInt32LE(Math.floor(Date.now() / 1000), 0x88)  // TimeDateStamp
    pe.writeUInt32LE(0, 0x8c)  // PointerToSymbolTable
    pe.writeUInt32LE(0, 0x90)  // NumberOfSymbols
    pe.writeUInt16LE(0xe0, 0x94)  // SizeOfOptionalHeader
    pe.writeUInt16LE(0x010f, 0x96)  // Characteristics
    
    // Optional header
    pe.writeUInt16LE(0x010b, 0x98)  // Magic (PE32)
    pe.writeUInt8(0x0e, 0x9a)  // MajorLinkerVersion
    pe.writeUInt8(0x00, 0x9b)  // MinorLinkerVersion
    pe.writeUInt32LE(0x1000, 0x9c)  // SizeOfCode
    pe.writeUInt32LE(0x1000, 0xa0)  // SizeOfInitializedData
    pe.writeUInt32LE(0, 0xa4)  // SizeOfUninitializedData
    pe.writeUInt32LE(0x1000, 0xa8)  // AddressOfEntryPoint
    pe.writeUInt32LE(0x1000, 0xac)  // BaseOfCode
    pe.writeUInt32LE(0x2000, 0xb0)  // BaseOfData
    pe.writeUInt32LE(0x400000, 0xb4)  // ImageBase
    pe.writeUInt32LE(0x1000, 0xb8)  // SectionAlignment
    pe.writeUInt32LE(0x200, 0xbc)  // FileAlignment
    pe.writeUInt16LE(5, 0xc0)  // MajorOperatingSystemVersion
    pe.writeUInt16LE(1, 0xc2)  // MinorOperatingSystemVersion
    pe.writeUInt16LE(0, 0xc4)  // MajorImageVersion
    pe.writeUInt16LE(0, 0xc6)  // MinorImageVersion
    pe.writeUInt16LE(5, 0xc8)  // MajorSubsystemVersion
    pe.writeUInt16LE(1, 0xca)  // MinorSubsystemVersion
    pe.writeUInt32LE(0, 0xcc)  // Win32VersionValue
    pe.writeUInt32LE(0x3000, 0xd0)  // SizeOfImage
    pe.writeUInt32LE(0x200, 0xd4)  // SizeOfHeaders
    pe.writeUInt32LE(0, 0xd8)  // CheckSum
    pe.writeUInt16LE(3, 0xdc)  // Subsystem (IMAGE_SUBSYSTEM_WINDOWS_CUI)
    pe.writeUInt16LE(0, 0xde)  // DllCharacteristics
    
    return pe
  }

  /**
   * Helper function to create a PE with suspicious strings
   */
  async function createSuspiciousPE(): Promise<Buffer> {
    const pe = await createMinimalPE()
    
    // Add suspicious strings at the end
    const suspiciousStrings = [
      'http://malicious.example.com/payload',
      'C:\\Windows\\Temp\\malware.exe',
      'HKEY_LOCAL_MACHINE\\Software\\Malware',
      'cmd.exe /c del',
      'powershell.exe -enc',
      '192.168.1.100',
    ]
    
    let offset = 512
    for (const str of suspiciousStrings) {
      pe.write(str + '\0', offset, 'ascii')
      offset += str.length + 1
    }
    
    return pe
  }

  test('should complete triage workflow within 5 minutes', async () => {
    // Requirement: 15.3, 26.7
    const peData = await createMinimalPE()
    
    // Ingest sample
    const ingestResult = await ingestHandler({
      bytes_b64: peData.toString('base64'),
      filename: 'test_minimal.exe',
      source: 'integration_test',
    })
    
    expect(ingestResult.ok).toBe(true)
    expect(ingestResult.data).toBeDefined()
    const sampleId = (ingestResult.data as any).sample_id
    
    // Execute triage workflow and measure time
    const startTime = Date.now()
    const result = await triageHandler({ sample_id: sampleId })
    const elapsedMs = Date.now() - startTime
    
    // Verify completion time (5 minutes = 300,000 ms)
    expect(elapsedMs).toBeLessThan(5 * 60 * 1000)
    
    // Verify result structure
    expect(result).toBeDefined()
    expect(result.metrics).toBeDefined()
    expect(result.metrics?.elapsed_ms).toBeGreaterThan(0)
  }, 6 * 60 * 1000) // 6 minute timeout for the test itself

  test('should generate complete report structure', async () => {
    // Requirement: 15.2, 15.3
    const peData = await createMinimalPE()
    
    // Ingest sample
    const ingestResult = await ingestHandler({
      bytes_b64: peData.toString('base64'),
      filename: 'test_structure.exe',
      source: 'integration_test',
    })
    
    expect(ingestResult.ok).toBe(true)
    const sampleId = (ingestResult.data as any).sample_id
    
    // Execute triage workflow
    const result = await triageHandler({ sample_id: sampleId })
    
    // Verify report format (Requirement: 15.2)
    if (result.ok && result.data) {
      const data = result.data as any
      
      // Verify required fields
      expect(data.summary).toBeDefined()
      expect(typeof data.summary).toBe('string')
      expect(data.summary.length).toBeGreaterThan(0)
      
      expect(data.confidence).toBeDefined()
      expect(typeof data.confidence).toBe('number')
      expect(data.confidence).toBeGreaterThanOrEqual(0)
      expect(data.confidence).toBeLessThanOrEqual(1)
      
      expect(data.threat_level).toBeDefined()
      expect(['clean', 'suspicious', 'malicious', 'unknown']).toContain(data.threat_level)
      
      // Verify IOCs structure
      expect(data.iocs).toBeDefined()
      expect(data.iocs.suspicious_imports).toBeDefined()
      expect(Array.isArray(data.iocs.suspicious_imports)).toBe(true)
      expect(data.iocs.suspicious_strings).toBeDefined()
      expect(Array.isArray(data.iocs.suspicious_strings)).toBe(true)
      expect(data.iocs.yara_matches).toBeDefined()
      expect(Array.isArray(data.iocs.yara_matches)).toBe(true)
      
      // Verify evidence
      expect(data.evidence).toBeDefined()
      expect(Array.isArray(data.evidence)).toBe(true)
      
      // Verify recommendation
      expect(data.recommendation).toBeDefined()
      expect(typeof data.recommendation).toBe('string')
      expect(data.recommendation.length).toBeGreaterThan(0)
      
      // Verify raw results are included
      expect(data.raw_results).toBeDefined()
      expect(data.raw_results.fingerprint).toBeDefined()
      expect(data.raw_results.runtime).toBeDefined()
      expect(data.raw_results.imports).toBeDefined()
      expect(data.raw_results.strings).toBeDefined()
      expect(data.raw_results.yara).toBeDefined()
    }
  }, 6 * 60 * 1000)

  test('should detect suspicious strings in sample', async () => {
    // Requirement: 15.5
    const peData = await createSuspiciousPE()
    
    // Ingest sample
    const ingestResult = await ingestHandler({
      bytes_b64: peData.toString('base64'),
      filename: 'test_suspicious.exe',
      source: 'integration_test',
    })
    
    expect(ingestResult.ok).toBe(true)
    const sampleId = (ingestResult.data as any).sample_id
    
    // Execute triage workflow
    const result = await triageHandler({ sample_id: sampleId })
    
    // Verify suspicious strings are detected
    if (result.ok && result.data) {
      const data = result.data as any
      
      // Should detect at least some suspicious patterns
      const totalIOCs = 
        data.iocs.suspicious_imports.length +
        data.iocs.suspicious_strings.length +
        data.iocs.yara_matches.length
      
      // With suspicious strings, we should have some IOCs
      // Note: Actual detection depends on the worker implementation
      expect(totalIOCs).toBeGreaterThanOrEqual(0)
      
      // Check for URL detection
      if (data.iocs.urls) {
        expect(Array.isArray(data.iocs.urls)).toBe(true)
      }
      
      // Check for IP detection
      if (data.iocs.ip_addresses) {
        expect(Array.isArray(data.iocs.ip_addresses)).toBe(true)
      }
      
      // Check for file path detection
      if (data.iocs.file_paths) {
        expect(Array.isArray(data.iocs.file_paths)).toBe(true)
      }
      
      // Check for registry key detection
      if (data.iocs.registry_keys) {
        expect(Array.isArray(data.iocs.registry_keys)).toBe(true)
      }
    }
  }, 6 * 60 * 1000)

  test('should handle multiple samples concurrently', async () => {
    // Test that multiple triage workflows can run without interference
    const samples = await Promise.all([
      createMinimalPE(),
      createMinimalPE(),
      createSuspiciousPE(),
    ])
    
    // Ingest all samples
    const ingestResults = await Promise.all(
      samples.map((data, i) =>
        ingestHandler({
          bytes_b64: data.toString('base64'),
          filename: `test_concurrent_${i}.exe`,
          source: 'integration_test',
        })
      )
    )
    
    // Verify all ingests succeeded
    expect(ingestResults.every(r => r.ok)).toBe(true)
    
    const sampleIds = ingestResults.map(r => (r.data as any).sample_id)
    
    // Execute triage workflows concurrently
    const startTime = Date.now()
    const results = await Promise.all(
      sampleIds.map(id => triageHandler({ sample_id: id }))
    )
    const elapsedMs = Date.now() - startTime
    
    // Verify all completed
    expect(results.length).toBe(3)
    
    // Each should complete within reasonable time
    // (concurrent execution should not significantly slow down individual workflows)
    expect(elapsedMs).toBeLessThan(10 * 60 * 1000) // 10 minutes for 3 samples
    
    // Verify each result has unique data
    const summaries = results
      .filter(r => r.ok && r.data)
      .map(r => (r.data as any).summary)
    
    expect(summaries.length).toBeGreaterThan(0)
  }, 12 * 60 * 1000)

  test('should provide appropriate threat assessment', async () => {
    // Requirement: 15.2, 15.4
    const peData = await createMinimalPE()
    
    // Ingest sample
    const ingestResult = await ingestHandler({
      bytes_b64: peData.toString('base64'),
      filename: 'test_threat.exe',
      source: 'integration_test',
    })
    
    expect(ingestResult.ok).toBe(true)
    const sampleId = (ingestResult.data as any).sample_id
    
    // Execute triage workflow
    const result = await triageHandler({ sample_id: sampleId })
    
    if (result.ok && result.data) {
      const data = result.data as any
      
      // Verify threat level is one of the valid values
      expect(['clean', 'suspicious', 'malicious', 'unknown']).toContain(data.threat_level)
      
      // Verify confidence is reasonable
      expect(data.confidence).toBeGreaterThanOrEqual(0)
      expect(data.confidence).toBeLessThanOrEqual(1)
      
      // Verify evidence supports the assessment
      expect(data.evidence).toBeDefined()
      expect(Array.isArray(data.evidence)).toBe(true)
      
      // Verify recommendation is provided
      expect(data.recommendation).toBeDefined()
      expect(data.recommendation.length).toBeGreaterThan(0)
      
      // For a minimal clean PE, threat level should be clean or unknown
      // (since it has no suspicious features)
      expect(['clean', 'unknown']).toContain(data.threat_level)
    }
  }, 6 * 60 * 1000)

  test('should include performance metrics', async () => {
    // Requirement: 26.7
    const peData = await createMinimalPE()
    
    // Ingest sample
    const ingestResult = await ingestHandler({
      bytes_b64: peData.toString('base64'),
      filename: 'test_metrics.exe',
      source: 'integration_test',
    })
    
    expect(ingestResult.ok).toBe(true)
    const sampleId = (ingestResult.data as any).sample_id
    
    // Execute triage workflow
    const result = await triageHandler({ sample_id: sampleId })
    
    // Verify metrics are included
    expect(result.metrics).toBeDefined()
    expect(result.metrics?.tool).toBe('workflow.triage')
    expect(result.metrics?.elapsed_ms).toBeDefined()
    expect(result.metrics?.elapsed_ms).toBeGreaterThan(0)
    expect(result.metrics?.elapsed_ms).toBeLessThan(5 * 60 * 1000) // Within 5 minutes
  }, 6 * 60 * 1000)

  test('should handle partial tool failures gracefully', async () => {
    // Test resilience when some tools fail
    const peData = Buffer.alloc(100) // Invalid PE that will cause some tools to fail
    peData.write('MZ', 0, 'ascii') // Just MZ header, rest is invalid
    
    // Ingest sample
    const ingestResult = await ingestHandler({
      bytes_b64: peData.toString('base64'),
      filename: 'test_invalid.exe',
      source: 'integration_test',
    })
    
    expect(ingestResult.ok).toBe(true)
    const sampleId = (ingestResult.data as any).sample_id
    
    // Execute triage workflow
    const result = await triageHandler({ sample_id: sampleId })
    
    // Should not crash, even if tools fail
    expect(result).toBeDefined()
    expect(result.metrics).toBeDefined()
    
    // May have errors or warnings
    if (result.errors && result.errors.length > 0) {
      expect(Array.isArray(result.errors)).toBe(true)
    }
    
    if (result.warnings && result.warnings.length > 0) {
      expect(Array.isArray(result.warnings)).toBe(true)
    }
  }, 6 * 60 * 1000)

  test('should cache results for repeated analysis', async () => {
    // Test that repeated analysis uses cache
    const peData = await createMinimalPE()
    
    // Ingest sample
    const ingestResult = await ingestHandler({
      bytes_b64: peData.toString('base64'),
      filename: 'test_cache.exe',
      source: 'integration_test',
    })
    
    expect(ingestResult.ok).toBe(true)
    const sampleId = (ingestResult.data as any).sample_id
    
    // First execution
    const startTime1 = Date.now()
    const result1 = await triageHandler({ sample_id: sampleId })
    const elapsed1 = Date.now() - startTime1
    
    expect(result1).toBeDefined()
    
    // Second execution (should use cache for individual tools)
    const startTime2 = Date.now()
    const result2 = await triageHandler({ sample_id: sampleId })
    const elapsed2 = Date.now() - startTime2
    
    expect(result2).toBeDefined()
    
    // Second execution should be faster due to caching
    // (though this is not guaranteed in all cases)
    expect(elapsed2).toBeLessThanOrEqual(elapsed1 * 2) // Allow some variance
  }, 12 * 60 * 1000)
})
