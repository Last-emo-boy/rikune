import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createArtifactReadHandler } from '../../src/tools/artifact-read.js'

describe('artifact.read tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let handler: ReturnType<typeof createArtifactReadHandler>

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'artifact-read-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    handler = createArtifactReadHandler(workspaceManager, database)
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

  test('should read latest artifact content by type', async () => {
    const setup = await setupSampleWithArtifacts(
      workspaceManager,
      database,
      [
        {
          id: 'artifact-manifest-1',
          type: 'reconstruct_manifest',
          path: 'reports/reconstruct/demo/manifest.json',
          mime: 'application/json',
          content: JSON.stringify({ module_count: 2, modules: ['core', 'net'] }),
        },
      ]
    )

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_type: 'reconstruct_manifest',
    })

    expect(result.ok).toBe(true)
    expect(result.data).toBeDefined()
    const data = result.data as {
      artifact: { type: string }
      content?: string
      content_encoding?: string
    }
    expect(data.artifact.type).toBe('reconstruct_manifest')
    expect(data.content_encoding).toBe('utf8')
    expect(data.content).toContain('"module_count":2')
  })

  test('should support metadata-only mode via artifact_id selector', async () => {
    const setup = await setupSampleWithArtifacts(
      workspaceManager,
      database,
      [
        {
          id: 'artifact-gaps-1',
          type: 'reconstruct_gaps',
          path: 'reports/reconstruct/demo/gaps.md',
          mime: 'text/markdown',
          content: '# gaps\n- unresolved symbol',
        },
      ]
    )

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-gaps-1',
      include_content: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      artifact: { id: string }
      content?: string
      bytes_read: number
      truncated: boolean
    }
    expect(data.artifact.id).toBe('artifact-gaps-1')
    expect(data.content).toBeUndefined()
    expect(data.bytes_read).toBe(0)
    expect(data.truncated).toBe(false)
  })

  test('should truncate oversized artifact content', async () => {
    const largeContent = 'A'.repeat(4096)
    const setup = await setupSampleWithArtifacts(
      workspaceManager,
      database,
      [
        {
          id: 'artifact-large-1',
          type: 'reconstruct_manifest',
          path: 'reports/reconstruct/demo/manifest.json',
          mime: 'application/json',
          content: largeContent,
        },
      ]
    )

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-large-1',
      max_bytes: 512,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('truncated'))).toBe(true)
    const data = result.data as {
      bytes_read: number
      total_size: number
      truncated: boolean
      content?: string
    }
    expect(data.bytes_read).toBe(512)
    expect(data.total_size).toBe(4096)
    expect(data.truncated).toBe(true)
    expect(data.content?.length).toBe(512)
  })

  test('should parse JSON content when parse_json=true', async () => {
    const setup = await setupSampleWithArtifacts(
      workspaceManager,
      database,
      [
        {
          id: 'artifact-json-1',
          type: 'reconstruct_manifest',
          path: 'reports/reconstruct/demo/manifest.json',
          mime: 'application/json',
          content: '{"name":"demo","count":2}',
        },
      ]
    )

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_type: 'reconstruct_manifest',
      parse_json: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as { parsed_json?: { name: string; count: number } }
    expect(data.parsed_json?.name).toBe('demo')
    expect(data.parsed_json?.count).toBe(2)
  })

  test('should extract IOC highlights from UTF-8 content', async () => {
    const setup = await setupSampleWithArtifacts(
      workspaceManager,
      database,
      [
        {
          id: 'artifact-log-1',
          type: 'sandbox_trace_json',
          path: 'reports/dynamic/run.log',
          mime: 'text/plain',
          content:
            'cmd.exe /c whoami\nhttps://evil.example/a\nHKEY_CURRENT_USER\\Software\\Run\n\\\\.\\pipe\\demo',
        },
      ]
    )

    const result = await handler({
      sample_id: setup.sampleId,
      artifact_id: 'artifact-log-1',
      ioc_highlights: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as {
      highlights?: {
        urls?: string[]
        commands?: string[]
        registry_keys?: string[]
        pipes?: string[]
      }
    }
    expect(data.highlights?.urls?.[0]).toContain('https://evil.example/a')
    expect(data.highlights?.commands?.[0]).toContain('cmd.exe')
    expect(data.highlights?.registry_keys?.[0]).toContain('HKEY_CURRENT_USER')
    expect(data.highlights?.pipes?.[0]).toContain('\\\\.\\pipe\\demo')
  })

  test('should read untracked filesystem artifacts by path', async () => {
    const setup = await setupSampleWithArtifacts(workspaceManager, database, [])
    const workspace = await workspaceManager.getWorkspace(setup.sampleId)
    const relativePath = 'reports/triage/untracked-help.txt'
    await fs.mkdir(path.join(workspace.root, 'reports', 'triage'), { recursive: true })
    await fs.writeFile(
      path.join(workspace.root, relativePath),
      'usage: akasha --pid 123 --inject',
      'utf-8'
    )

    const result = await handler({
      sample_id: setup.sampleId,
      path: relativePath,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings?.some((item) => item.includes('untracked filesystem artifact'))).toBe(
      true
    )
    const data = result.data as {
      artifact: { id: string; path: string }
      content?: string
    }
    expect(data.artifact.id.startsWith('fs:')).toBe(true)
    expect(data.artifact.path).toBe(relativePath)
    expect(data.content).toContain('usage: akasha')
  })
})

interface ArtifactFixture {
  id: string
  type: string
  path: string
  mime: string
  content: string
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
      created_at: new Date().toISOString(),
    })
  }

  return { sampleId }
}
