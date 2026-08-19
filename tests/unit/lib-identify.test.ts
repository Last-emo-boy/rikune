import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import libIdentifyPlugin from '../../src/plugins/lib-identify/index.js'
import {
  createLibIdentifyHandler,
  libIdentifyToolDefinition,
} from '../../src/plugins/lib-identify/tools/lib-identify.js'
import {
  createLibSignaturesListHandler,
  libSignaturesListToolDefinition,
} from '../../src/plugins/lib-identify/tools/lib-signatures-list.js'
import type { MCPRegistry } from '../../src/core/mcp-registry.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import pino from 'pino'

const logger = pino({ level: 'silent' })

function resetSurfaceForTest(): void {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

describe('lib-identify plugin', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'a'.repeat(64)}`

  beforeEach(async () => {
    resetSurfaceForTest()
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lib-identify-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    database.insertSample({
      id: sampleId,
      sha256: 'a'.repeat(64),
      md5: 'a'.repeat(32),
      size: 4096,
      file_type: 'ELF executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(
      path.join(workspace.original, 'sample.elf'),
      Buffer.from([0x7f, 0x45, 0x4c, 0x46])
    )
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('registers lib.identify and lib.signatures.list tools with FLIRT aspects', () => {
    expect(libIdentifyPlugin.id).toBe('lib-identify')
    expect(libIdentifyPlugin.surfaceRules).toEqual(
      expect.objectContaining({
        tier: 2,
        category: 'reverse-engineering',
      })
    )
    expect(libIdentifyPlugin.aspects.capabilities).toEqual(
      expect.arrayContaining([
        'library-function-identification',
        'flirt-signature-matching',
        'sigdb-enumeration',
      ])
    )

    const registered: string[] = []
    const fakeServer = {
      registerTool: (def: { name: string }) => {
        registered.push(def.name)
      },
    }
    const toolNames = libIdentifyPlugin.register?.(
      fakeServer as any,
      { workspaceManager, database } as any
    )
    expect(registered).toEqual(['lib.identify', 'lib.signatures.list'])
    expect(toolNames).toEqual(['lib.identify', 'lib.signatures.list'])
  })

  test('lib.identify declares passive read-only runtime policy and FLIRT artifacts', () => {
    expect(libIdentifyToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(libIdentifyToolDefinition.aspects.capabilities).toEqual(
      expect.arrayContaining([
        'library-function-identification',
        'flirt-signature-matching',
        'function-naming',
        'boilerplate-filtering',
      ])
    )
    expect(libIdentifyToolDefinition.aspects.runtimes).toEqual(['rizin'])
    expect(libIdentifyToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'backend_lib_identify_matches' }),
        expect.objectContaining({ type: 'lib_signatures_list' }),
      ])
    )
  })

  test('lib.signatures.list requires sample_id and declares sigdb inventory', () => {
    expect(libSignaturesListToolDefinition.runtimePolicy?.passiveByDefault).toBe(true)
    expect(libSignaturesListToolDefinition.aspects.capabilities).toEqual(
      expect.arrayContaining([
        'flirt-signature-inventory',
        'sigdb-enumeration',
      ])
    )
    // sample_id is required (no default).
    const sampleField = (libSignaturesListToolDefinition.inputSchema as any).shape
      ?.sample_id
    expect(sampleField).toBeDefined()
  })

  test('returns setup_required when rizin backend is unavailable', async () => {
    // Ensure rizin is not resolvable in the test environment.
    delete process.env.RIZIN_PATH
    delete process.env.RZ_SIGDB

    const handler = createLibIdentifyHandler({
      workspaceManager,
      database,
    } as any)
    const result = await handler({
      sample_id: sampleId,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('setup_required')
    expect(data.backend.available).toBe(false)
    // setup_required hands off to system setup tooling, not the FLIRT tools.
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['system.health', 'system.setup.guide'])
    )
    expect(data.sample_executed_by_tool ?? false).toBe(false)
  })

  test('returns setup_required for lib.signatures.list when rizin unavailable', async () => {
    delete process.env.RIZIN_PATH
    delete process.env.RZ_SIGDB

    const handler = createLibSignaturesListHandler({
      workspaceManager,
      database,
    } as any)
    const result = await handler({
      sample_id: sampleId,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('setup_required')
    expect(data.backend.available).toBe(false)
  })

  test('validates missing sample_id rejects before backend resolution', async () => {
    delete process.env.RIZIN_PATH
    const handler = createLibIdentifyHandler({
      workspaceManager,
      database,
    } as any)
    // Zod parse happens before backend resolution; missing sample_id should throw.
    const result = await handler({ persist_artifact: false } as any)
    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/sample_id|Invalid arguments|required/i)
  })
})
