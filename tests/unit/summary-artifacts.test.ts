import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { createHash } from 'crypto'
import { DatabaseManager } from '../../src/database.js'
import {
  loadSummaryDigestArtifactSelection,
  persistSummaryDigestArtifact,
  SUMMARY_FINAL_DIGEST_ARTIFACT_TYPE,
} from '../../src/artifacts/summary-artifacts.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'

const SHA256 = '9'.repeat(64)
const SAMPLE_ID = `sha256:${SHA256}`

describe('summary digest artifact integrity', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-summary-artifact-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SHA256,
      md5: '8'.repeat(32),
      size: 1024,
      file_type: 'ELF',
      created_at: '2026-07-14T10:00:00.000Z',
      source: 'unit-test',
    })
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempRoot, { recursive: true, force: true })
  })

  test('uses collision-resistant immutable paths for concurrent writes', async () => {
    const artifacts = await Promise.all([
      persistSummaryDigestArtifact(
        workspaceManager,
        database,
        SAMPLE_ID,
        'final',
        { value: 'first' },
        'session-a'
      ),
      persistSummaryDigestArtifact(
        workspaceManager,
        database,
        SAMPLE_ID,
        'final',
        { value: 'second' },
        'session-a'
      ),
    ])

    expect(new Set(artifacts.map((artifact) => artifact.path)).size).toBe(2)
    expect(
      database.findArtifactsByType(SAMPLE_ID, SUMMARY_FINAL_DIGEST_ARTIFACT_TYPE)
    ).toHaveLength(2)
  })

  test('skips a digest whose persisted bytes no longer match the database SHA-256', async () => {
    const artifact = await persistSummaryDigestArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'final',
      { value: 'trusted' }
    )
    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    await fs.writeFile(path.join(workspace.root, artifact.path), '{"value":"tampered"}', 'utf8')

    const selection = await loadSummaryDigestArtifactSelection<Record<string, unknown>>(
      workspaceManager,
      database,
      SAMPLE_ID,
      'final',
      { scope: 'all' }
    )

    expect(selection.artifacts).toEqual([])
    expect(selection.latest_payload).toBeNull()
  })

  test('skips an artifact path that resolves outside the sample workspace', async () => {
    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    const outsidePath = path.join(tempRoot, 'outside-summary.json')
    const content = JSON.stringify({ value: 'outside' })
    await fs.writeFile(outsidePath, content, 'utf8')
    const reportDir = path.join(workspace.reports, 'summary', 'default')
    await fs.mkdir(reportDir, { recursive: true })
    const linkedPath = path.join(reportDir, 'linked.json')
    await fs.symlink(outsidePath, linkedPath)
    database.insertArtifact({
      id: 'summary-outside-link',
      sample_id: SAMPLE_ID,
      type: SUMMARY_FINAL_DIGEST_ARTIFACT_TYPE,
      path: path.relative(workspace.root, linkedPath).replace(/\\/g, '/'),
      sha256: createHash('sha256').update(content).digest('hex'),
      mime: 'application/json',
      created_at: '2026-07-14T10:01:00.000Z',
    })

    const selection = await loadSummaryDigestArtifactSelection<Record<string, unknown>>(
      workspaceManager,
      database,
      SAMPLE_ID,
      'final',
      { scope: 'all' }
    )

    expect(selection.artifacts).toEqual([])
  })
})
