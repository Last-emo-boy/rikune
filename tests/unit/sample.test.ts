/**
 * Unit tests for sample management
 */

import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { createSampleIngestHandler } from '../../src/tools/sample-ingest.js'
import { createSampleProfileGetHandler } from '../../src/tools/sample-profile-get.js'
import { createSampleRequestUploadHandler } from '../../src/tools/sample-request-upload.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'

describe('Sample Management', () => {
  let testDir: string
  let database: DatabaseManager
  let workspaceManager: WorkspaceManager
  let policyGuard: PolicyGuard

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sample-management-'))
    database = new DatabaseManager(path.join(testDir, 'test.db'))
    workspaceManager = new WorkspaceManager(path.join(testDir, 'workspaces'))
    policyGuard = new PolicyGuard(path.join(testDir, 'audit.log'))
  })

  afterEach(() => {
    database.close()
    fs.rmSync(testDir, { recursive: true, force: true })
  })

  test('ingests a sample and exposes a ready profile with workspace integrity', async () => {
    const ingest = createSampleIngestHandler(workspaceManager, database, policyGuard)
    const getProfile = createSampleProfileGetHandler(database, workspaceManager)
    const sampleBytes = Buffer.from('MZ\x90\x00\x03\x00\x00\x00')

    const ingestResult = await ingest({
      bytes_b64: sampleBytes.toString('base64'),
      filename: 'calc.exe',
      source: 'unit-test',
    })

    expect(ingestResult.ok).toBe(true)
    const ingestData = ingestResult.data as any
    expect(ingestData.sample_id).toMatch(/^sha256:[a-f0-9]{64}$/)
    expect(ingestData.file_type).toBe('PE')
    expect(ingestData.result_mode).toBe('sample_registered')

    const profileResult = await getProfile({
      sample_id: ingestData.sample_id,
      analysis_detail: 'compact',
    })

    expect(profileResult.ok).toBe(true)
    const profile = profileResult.data as any
    expect(profile.sample.id).toBe(ingestData.sample_id)
    expect(profile.sample.source).toBe('unit-test')
    expect(profile.analysis_summary.total_count).toBe(0)
    expect(profile.workspace.status).toBe('ready')
    expect(profile.workspace.workspace_exists).toBe(true)
    expect(profile.workspace.original_present).toBe(true)
    expect(profile.workspace.original_files).toContain('calc.exe')
    expect(profile.workspace.remediation).toEqual([])
  })

  test('creates a persisted upload session with staged workflow guidance', async () => {
    const requestUpload = createSampleRequestUploadHandler(database, { apiPort: 19080 })

    const uploadResult = await requestUpload({
      filename: 'agent.dll',
      ttl_seconds: 120,
    })

    expect(uploadResult.ok).toBe(true)
    const uploadData = uploadResult.data as any
    expect(uploadData.upload_url).toBe(`http://localhost:19080/api/v1/uploads/${uploadData.token}`)
    expect(uploadData.status_url).toBe(
      `http://localhost:19080/api/v1/uploads/${uploadData.token}/status`
    )
    expect(uploadData.result_mode).toBe('upload_session')
    expect(uploadData.recommended_next_tools).toEqual(
      expect.arrayContaining(['workflow.analyze.start', 'workflow.summarize'])
    )
    expect(uploadData.next_actions[0]).toContain('POST the file bytes')

    const session = database.findUploadSessionByToken(uploadData.token)
    expect(session).toBeDefined()
    expect(session?.status).toBe('pending')
    expect(session?.filename).toBe('agent.dll')
  })
})
