import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { createHash } from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createStaticResourceGraphHandler,
  staticResourceGraphToolDefinition,
} from '../../src/plugins/static-triage/tools/static-resource-graph.js'

const SAMPLE_HASH = '1'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

describe('static.resource.graph tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let samplePath: string

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-resource-graph-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    const sampleBytes = Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.alloc(96, 0),
      Buffer.from('http://payload.example.net/install user32.dll kernel32.dll', 'ascii'),
    ])
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '1'.repeat(32),
      size: sampleBytes.length,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    samplePath = path.join(workspace.original, 'sample.exe')
    fs.writeFileSync(samplePath, sampleBytes)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore cleanup races in failed tests
    }
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('exports a static resource graph tool definition', () => {
    expect(staticResourceGraphToolDefinition.name).toBe('static.resource.graph')
    expect(staticResourceGraphToolDefinition.description).toContain('resource')
  })

  test('profiles sample bytes and persists a static_resource_graph artifact', async () => {
    const result = await createStaticResourceGraphHandler(workspaceManager, database)({
      sample_id: SAMPLE_ID,
      session_tag: 'resource-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.static_resource_graph.v1')
    expect(data.file.magic).toBe('pe_or_dos')
    expect(data.file.sha256).toBe(createHash('sha256').update(fs.readFileSync(samplePath)).digest('hex'))
    expect(Array.isArray(data.resources)).toBe(true)
    expect(data.recommended_next_tools).toContain('static.config.carver')

    const artifacts = database.findArtifactsByType(SAMPLE_ID, 'static_resource_graph')
    expect(artifacts).toHaveLength(1)
    expect(result.artifacts?.[0]?.type).toBe('static_resource_graph')
  })
})
