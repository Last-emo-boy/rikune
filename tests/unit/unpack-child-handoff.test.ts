import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { createHash } from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createUnpackChildHandoffHandler,
  unpackChildHandoffToolDefinition,
} from '../../src/plugins/unpacking/tools/unpack-child-handoff.js'

const SAMPLE_HASH = '9'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

function createMinimalPe(fillByte: number): Buffer {
  const buffer = Buffer.alloc(0x400, fillByte)
  buffer.write('MZ', 0, 'ascii')
  buffer.writeUInt32LE(0x80, 0x3c)
  buffer.write('PE\0\0', 0x80, 'ascii')
  const coff = 0x84
  buffer.writeUInt16LE(0x14c, coff)
  buffer.writeUInt16LE(1, coff + 2)
  buffer.writeUInt16LE(0xe0, coff + 16)
  const optional = coff + 20
  buffer.writeUInt16LE(0x10b, optional)
  const section = optional + 0xe0
  buffer.write('.text\0\0\0', section, 'ascii')
  buffer.writeUInt32LE(0x200, section + 8)
  buffer.writeUInt32LE(0x1000, section + 12)
  buffer.writeUInt32LE(0x200, section + 16)
  buffer.writeUInt32LE(0x200, section + 20)
  buffer.writeUInt32LE(0x60000020, section + 36)
  return buffer
}

describe('unpack.child.handoff tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let childPayload: Buffer
  let childOffset: number

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-unpack-child-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

    const primary = createMinimalPe(0)
    childPayload = createMinimalPe(0x41)
    const padding = Buffer.from('embedded-resource-padding', 'ascii')
    childOffset = primary.length + padding.length
    const sampleBytes = Buffer.concat([primary, padding, childPayload])
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '9'.repeat(32),
      size: sampleBytes.length,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'packed.exe'), sampleBytes)

    await persistStaticAnalysisJsonArtifact(workspaceManager, database, SAMPLE_ID, 'static_resource_graph', 'resource_graph', {
      schema: 'rikune.static_resource_graph.v1',
      resources: [
        {
          path: ['resources', 'id_10', 'id_1033'],
          dataOffset: childOffset,
          size: childPayload.length,
          magic: 'pe_or_dos',
          entropy: 6.7,
          sha256: createHash('sha256').update(childPayload).digest('hex'),
        },
      ],
    }, 'resource-session')
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore cleanup races in failed tests
    }
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('exports child handoff tool definition', () => {
    expect(unpackChildHandoffToolDefinition.name).toBe('unpack.child.handoff')
    expect(unpackChildHandoffToolDefinition.description).toContain('child samples')
  })

  test('registers embedded payload candidates as child samples', async () => {
    const result = await createUnpackChildHandoffHandler(workspaceManager, database)({
      sample_id: SAMPLE_ID,
      resource_scope: 'session',
      resource_session_tag: 'resource-session',
      max_children: 2,
      session_tag: 'handoff-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const childSha256 = createHash('sha256').update(childPayload).digest('hex')
    const childSampleId = `sha256:${childSha256}`

    expect(data.schema).toBe('rikune.unpack_child_handoff.v1')
    expect(data.summary.candidate_count).toBeGreaterThanOrEqual(1)
    expect(data.summary.registered_child_count).toBeGreaterThanOrEqual(1)
    expect(data.candidates.some((candidate: any) => candidate.sha256 === childSha256)).toBe(true)
    expect(data.registered_children.some((child: any) => child.sample_id === childSampleId)).toBe(true)
    expect(database.findSample(childSampleId)).toBeTruthy()
    expect(database.findArtifactsByType(SAMPLE_ID, 'unpack_child_payload').length).toBeGreaterThanOrEqual(1)
    expect(database.findArtifactsByType(SAMPLE_ID, 'unpack_child_handoff')).toHaveLength(1)
  })
})
