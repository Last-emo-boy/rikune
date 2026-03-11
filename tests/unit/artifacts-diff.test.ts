import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createArtifactsDiffHandler } from '../../src/tools/artifacts-diff.js'

describe('artifacts.diff tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-artifacts-diff')
    testDbPath = path.join(process.cwd(), 'test-artifacts-diff.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
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
  })

  async function seedTrackedArtifact(
    sampleId: string,
    relativePath: string,
    sha256: string,
    createdAt: string
  ) {
    const workspace = await workspaceManager.createWorkspace(sampleId)
    const absolutePath = path.join(workspace.root, relativePath)
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true })
    fs.writeFileSync(absolutePath, relativePath, 'utf-8')
    let artifactType = 'report_markdown'
    if (relativePath.endsWith('manifest.json')) {
      artifactType = 'manifest'
    } else if (relativePath.endsWith('gaps.md')) {
      artifactType = 'gaps'
    }
    database.insertArtifact({
      id: `artifact-${relativePath.replace(/[\\/]/g, '-')}`,
      sample_id: sampleId,
      type: artifactType,
      path: relativePath.replace(/\\/g, '/'),
      sha256,
      mime: 'text/plain',
      created_at: createdAt,
    })
  }

  test('should diff two artifact sessions and report added/removed/changed items', async () => {
    const sampleId = 'sha256:' + 'a'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'a'.repeat(64),
      md5: 'a'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: '2026-03-11T00:00:00.000Z',
      source: 'unit-test',
    })

    await seedTrackedArtifact(
      sampleId,
      'reports/reconstruct/session-alpha/manifest.json',
      '1'.repeat(64),
      '2026-03-11T00:00:00.000Z'
    )
    await seedTrackedArtifact(
      sampleId,
      'reports/reconstruct/session-alpha/report.md',
      '2'.repeat(64),
      '2026-03-11T00:00:00.000Z'
    )
    await seedTrackedArtifact(
      sampleId,
      'reports/reconstruct/session-beta/manifest.json',
      '9'.repeat(64),
      '2026-03-11T00:01:00.000Z'
    )
    await seedTrackedArtifact(
      sampleId,
      'reports/reconstruct/session-beta/gaps.md',
      '3'.repeat(64),
      '2026-03-11T00:01:00.000Z'
    )

    const handler = createArtifactsDiffHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      left_session_tag: 'reports/reconstruct/session-alpha',
      right_session_tag: 'reports/reconstruct/session-beta',
      include_untracked_files: false,
      match_by: 'type',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.left_count).toBe(2)
    expect(data.right_count).toBe(2)
    expect(data.changed).toHaveLength(1)
    expect(data.changed[0].key).toBe('manifest')
    expect(data.changed[0].differences).toContain('sha256')
    expect(data.added.some((item: any) => item.artifact.path.includes('gaps.md'))).toBe(true)
    expect(data.removed.some((item: any) => item.artifact.path.includes('report.md'))).toBe(true)
    expect(data.summary.changed_fields.sha256).toBe(1)
  })

  test('should warn when one session has no matching artifacts', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: '2026-03-11T00:00:00.000Z',
      source: 'unit-test',
    })
    await seedTrackedArtifact(
      sampleId,
      'reports/reconstruct/session-alpha/manifest.json',
      '1'.repeat(64),
      '2026-03-11T00:00:00.000Z'
    )

    const handler = createArtifactsDiffHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      left_session_tag: 'reports/reconstruct/session-alpha',
      right_session_tag: 'reports/reconstruct/session-missing',
      include_untracked_files: false,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('right_session_tag'))).toBe(true)
    const data = result.data as any
    expect(data.right_count).toBe(0)
    expect(data.removed).toHaveLength(1)
  })
})
