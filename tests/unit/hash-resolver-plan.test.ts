import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createHashResolverPlanHandler,
  hashResolverPlanToolDefinition,
} from '../../src/plugins/api-hash/tools/hash-resolver-plan.js'

const SAMPLE_HASH = '6'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

describe('hash.resolver.plan tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-hash-resolver-plan-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

    const sampleBytes = Buffer.concat([
      Buffer.from('MZ\0kernel32.dll\0LoadLibraryA\0GetProcAddress\0hash=0x6A4ABC5B\0', 'ascii'),
      Buffer.from([0x5b, 0xbc, 0x4a, 0x6a, 0x11, 0x22, 0x33, 0x44]),
    ])
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '6'.repeat(32),
      size: sampleBytes.length,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'resolver.exe'), sampleBytes)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore cleanup races in failed tests
    }
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('exports resolver planning tool definition', () => {
    expect(hashResolverPlanToolDefinition.name).toBe('hash.resolver.plan')
    expect(hashResolverPlanToolDefinition.description).toContain('resolver')
  })

  test('finds resolver indicators and hash-like constants', async () => {
    const result = await createHashResolverPlanHandler(workspaceManager, database)({
      sample_id: SAMPLE_ID,
      session_tag: 'resolver-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.api_hash_resolver_plan.v1')
    expect(data.resolver_indicators.some((item: any) => item.indicator === 'GetProcAddress')).toBe(true)
    expect(data.resolver_indicators.some((item: any) => item.indicator === 'LoadLibrary')).toBe(true)
    expect(data.hash_candidates.some((item: any) => item.normalized === '0x6a4abc5b')).toBe(true)
    expect(data.recommended_hashes).toContain('0x6a4abc5b')
    expect(data.algorithm_hints.some((item: any) => item.algorithm === 'ror13')).toBe(true)
    expect(data.recommended_next_tools).toContain('hash.identify')
    expect(result.artifacts?.[0]?.type).toBe('api_hash_resolver_plan')

    const artifacts = database.findArtifactsByType(SAMPLE_ID, 'api_hash_resolver_plan')
    expect(artifacts).toHaveLength(1)
  })
})
