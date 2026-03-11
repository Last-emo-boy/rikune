import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createArtifactsListHandler } from '../../src/tools/artifacts-list.js'

describe('artifacts.list tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let handler: ReturnType<typeof createArtifactsListHandler>

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'artifacts-list-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    handler = createArtifactsListHandler(workspaceManager, database)
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should return error for unknown sample', async () => {
    const result = await handler({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should list artifacts with file metadata', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-manifest-1',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/demo/manifest.json',
        mime: 'application/json',
        content: '{"module_count":2}',
      },
      {
        id: 'artifact-gaps-1',
        type: 'reconstruct_gaps',
        path: 'reports/reconstruct/demo/gaps.md',
        mime: 'text/markdown',
        content: '# gaps',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      count: number
      artifacts: Array<{ type: string; exists: boolean; size_bytes: number | null }>
    }
    expect(data.count).toBe(2)
    expect(data.artifacts.every((item) => item.exists === true)).toBe(true)
    expect(data.artifacts.every((item) => typeof item.size_bytes === 'number')).toBe(true)
  })

  test('should filter by artifact_type', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-manifest-1',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/demo/manifest.json',
        mime: 'application/json',
        content: '{"module_count":2}',
      },
      {
        id: 'artifact-gaps-1',
        type: 'reconstruct_gaps',
        path: 'reports/reconstruct/demo/gaps.md',
        mime: 'text/markdown',
        content: '# gaps',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_type: 'reconstruct_manifest',
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      count: number
      artifacts: Array<{ type: string }>
    }
    expect(data.count).toBe(1)
    expect(data.artifacts[0].type).toBe('reconstruct_manifest')
  })

  test('should keep missing artifacts visible by default', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-missing-1',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/demo/missing.json',
        mime: 'application/json',
        content: '{"will_delete":true}',
      },
    ])

    const workspace = await workspaceManager.getWorkspace(setup.sampleId)
    await fs.rm(path.join(workspace.root, 'reports', 'reconstruct', 'demo', 'missing.json'), {
      force: true,
    })

    const result = await handler({
      sample_id: setup.sampleId,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('missing on disk'))).toBe(true)
    const data = result.data as {
      count: number
      artifacts: Array<{ exists: boolean }>
    }
    expect(data.count).toBe(1)
    expect(data.artifacts[0].exists).toBe(false)
  })

  test('should hide missing artifacts when include_missing=false', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-missing-1',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/demo/missing.json',
        mime: 'application/json',
        content: '{"will_delete":true}',
      },
    ])

    const workspace = await workspaceManager.getWorkspace(setup.sampleId)
    await fs.rm(path.join(workspace.root, 'reports', 'reconstruct', 'demo', 'missing.json'), {
      force: true,
    })

    const result = await handler({
      sample_id: setup.sampleId,
      include_missing: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as { count: number; artifacts: unknown[] }
    expect(data.count).toBe(0)
    expect(data.artifacts).toHaveLength(0)
  })

  test('should support pagination and summary fields', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-1',
        type: 'report_markdown',
        path: 'reports/report_1.md',
        mime: 'text/markdown',
        content: '# 1',
      },
      {
        id: 'artifact-2',
        type: 'report_markdown',
        path: 'reports/report_2.md',
        mime: 'text/markdown',
        content: '# 2',
      },
      {
        id: 'artifact-3',
        type: 'trace_json',
        path: 'reports/trace_1.json',
        mime: 'application/json',
        content: '{}',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      page: 2,
      page_size: 2,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      count: number
      total_count: number
      page: number
      page_size: number
      total_pages: number
      summary: { by_type: Record<string, number> }
    }
    expect(data.count).toBe(1)
    expect(data.total_count).toBe(3)
    expect(data.page).toBe(2)
    expect(data.page_size).toBe(2)
    expect(data.total_pages).toBe(2)
    expect(data.summary.by_type.report_markdown).toBe(2)
  })

  test('should support high_value_only and artifact_types filters', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-manifest',
        type: 'reconstruct_manifest',
        path: 'reports/reconstruct/manifest.json',
        mime: 'application/json',
        content: '{}',
      },
      {
        id: 'artifact-raw',
        type: 'raw_dump',
        path: 'cache/raw.bin',
        mime: 'application/octet-stream',
        content: 'abcdef',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_types: ['reconstruct_manifest', 'raw_dump'],
      high_value_only: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      count: number
      artifacts: Array<{ type: string }>
      summary: { high_value_types: string[] }
    }
    expect(data.count).toBe(1)
    expect(data.artifacts[0].type).toBe('reconstruct_manifest')
    expect(data.summary.high_value_types).toContain('reconstruct_manifest')
  })

  test('should surface untracked filesystem artifacts in inventory', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [])
    const workspace = await workspaceManager.getWorkspace(setup.sampleId)
    await fs.mkdir(path.join(workspace.root, 'ghidra', 'exports'), { recursive: true })
    await fs.writeFile(
      path.join(workspace.root, 'ghidra', 'exports', 'demo.pseudo.c'),
      'int main(void) { return 0; }',
      'utf-8'
    )

    const result = await handler({
      sample_id: setup.sampleId,
      include_untracked_files: true,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('untracked file artifact'))).toBe(true)
    const data = result.data as {
      artifacts: Array<{ id: string; type: string; path: string }>
      summary: { untracked_count: number }
    }
    expect(data.summary.untracked_count).toBe(1)
    expect(data.artifacts[0].id.startsWith('fs:')).toBe(true)
    expect(data.artifacts[0].type).toBe('ghidra_pseudocode')
    expect(data.artifacts[0].path).toContain('demo.pseudo.c')
  })

  test('should support path_prefix filtering and latest_only per artifact type', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-old-report',
        type: 'report_markdown',
        path: 'reports/session_a/report_old.md',
        mime: 'text/markdown',
        content: '# old',
        created_at: '2026-03-10T00:00:00.000Z',
      },
      {
        id: 'artifact-new-report',
        type: 'report_markdown',
        path: 'reports/session_a/report_new.md',
        mime: 'text/markdown',
        content: '# new',
        created_at: '2026-03-11T00:00:00.000Z',
      },
      {
        id: 'artifact-other-trace',
        type: 'trace_json',
        path: 'reports/session_b/trace.json',
        mime: 'application/json',
        content: '{}',
        created_at: '2026-03-11T01:00:00.000Z',
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      path_prefix: 'reports/session_a',
      latest_only: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      count: number
      path_prefix: string
      session_tag: string | null
      retention_bucket: string | null
      latest_only: boolean
      artifacts: Array<{
        id: string
        path: string
        session_tag: string | null
        retention_bucket: string
        age_days: number
      }>
      summary: {
        latest_by_type: Record<string, { id: string; path: string }>
        latest_by_session: Record<string, { id: string; path: string; type: string }>
        session_index: Record<
          string,
          {
            count: number
            tracked_count: number
            untracked_count: number
            types: string[]
            retention_buckets: string[]
          }
        >
        by_retention_bucket: Record<string, number>
      }
    }
    expect(data.count).toBe(1)
    expect(data.path_prefix).toBe('reports/session_a')
    expect(data.session_tag).toBe(null)
    expect(data.retention_bucket).toBe(null)
    expect(data.latest_only).toBe(true)
    expect(data.artifacts[0].id).toBe('artifact-new-report')
    expect(data.artifacts[0].session_tag).toBe('reports/session_a')
    expect(data.artifacts[0].retention_bucket).toBeDefined()
    expect(data.artifacts[0].age_days).toBeGreaterThanOrEqual(0)
    expect(data.summary.latest_by_type.report_markdown.path).toBe('reports/session_a/report_new.md')
    expect(data.summary.latest_by_session['reports/session_a'].id).toBe('artifact-new-report')
    expect(data.summary.session_index['reports/session_a'].count).toBe(1)
    expect(data.summary.session_index['reports/session_a'].tracked_count).toBe(1)
    expect(data.summary.session_index['reports/session_a'].types).toContain('report_markdown')
    expect(Object.values(data.summary.by_retention_bucket).reduce((sum, value) => sum + value, 0)).toBe(1)
  })

  test('should filter by derived session_tag and retention_bucket', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [
      {
        id: 'artifact-archive-report',
        type: 'report_markdown',
        path: 'reports/reconstruct/legacy_session/report.md',
        mime: 'text/markdown',
        content: '# archive',
        created_at: '2020-01-01T00:00:00.000Z',
      },
      {
        id: 'artifact-active-report',
        type: 'report_markdown',
        path: 'reports/reconstruct/current_session/report.md',
        mime: 'text/markdown',
        content: '# active',
        created_at: new Date().toISOString(),
      },
    ])

    const result = await handler({
      sample_id: setup.sampleId,
      session_tag: 'reports/reconstruct/legacy_session',
      retention_bucket: 'archive',
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      count: number
      session_tag: string | null
      retention_bucket: string | null
      artifacts: Array<{
        id: string
        session_tag: string | null
        retention_bucket: string
        age_days: number
      }>
      summary: {
        latest_by_session: Record<string, { id: string }>
        session_index: Record<
          string,
          {
            count: number
            tracked_count: number
            untracked_count: number
            retention_buckets: string[]
          }
        >
        by_retention_bucket: Record<string, number>
      }
    }
    expect(data.count).toBe(1)
    expect(data.session_tag).toBe('reports/reconstruct/legacy_session')
    expect(data.retention_bucket).toBe('archive')
    expect(data.artifacts[0].id).toBe('artifact-archive-report')
    expect(data.artifacts[0].session_tag).toBe('reports/reconstruct/legacy_session')
    expect(data.artifacts[0].retention_bucket).toBe('archive')
    expect(data.artifacts[0].age_days).toBeGreaterThan(365)
    expect(data.summary.latest_by_session['reports/reconstruct/legacy_session'].id).toBe(
      'artifact-archive-report'
    )
    expect(data.summary.session_index['reports/reconstruct/legacy_session'].count).toBe(1)
    expect(data.summary.session_index['reports/reconstruct/legacy_session'].tracked_count).toBe(1)
    expect(data.summary.session_index['reports/reconstruct/legacy_session'].retention_buckets).toContain(
      'archive'
    )
    expect(data.summary.by_retention_bucket.archive).toBe(1)
  })
})

interface ArtifactFixture {
  id: string
  type: string
  path: string
  mime: string
  content: string
  created_at?: string
}

async function setupSampleWithArtifacts(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  artifacts: ArtifactFixture[]
): Promise<{ sampleId: string }> {
  const binary = Buffer.from('MZ test sample')
  const sha256 = crypto.createHash('sha256').update(binary).digest('hex')
  const md5 = crypto.createHash('md5').update(binary).digest('hex')
  const sampleId = `sha256:${sha256}`

  database.insertSample({
    id: sampleId,
    sha256,
    md5,
    size: binary.length,
    file_type: 'PE32',
    created_at: new Date().toISOString(),
    source: 'test',
  })

  const workspace = await workspaceManager.createWorkspace(sampleId)
  await fs.writeFile(path.join(workspace.original, 'sample.exe'), binary)

  for (const artifact of artifacts) {
    const absPath = path.join(workspace.root, artifact.path)
    await fs.mkdir(path.dirname(absPath), { recursive: true })
    await fs.writeFile(absPath, artifact.content, 'utf-8')

    const fileSha256 = crypto.createHash('sha256').update(artifact.content).digest('hex')
    database.insertArtifact({
      id: artifact.id,
      sample_id: sampleId,
      type: artifact.type,
      path: artifact.path,
      sha256: fileSha256,
      mime: artifact.mime,
      created_at: artifact.created_at || new Date().toISOString(),
    })
  }

  return { sampleId }
}
