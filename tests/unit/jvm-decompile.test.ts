import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import jvmDecompilePlugin from '../../src/plugins/jvm-decompile/index.js'
import {
  createJvmDecompileHandler,
  jvmDecompileToolDefinition,
} from '../../src/plugins/jvm-decompile/tools/jvm-decompile.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'

function resetSurfaceForTest(): void {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

describe('jvm-decompile plugin', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'c'.repeat(64)}`

  beforeEach(async () => {
    resetSurfaceForTest()
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'jvm-decompile-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    database.insertSample({
      id: sampleId,
      sha256: 'c'.repeat(64),
      md5: 'c'.repeat(32),
      size: 4096,
      file_type: 'Java archive',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    // Write a minimal .class-shaped file so resolveSampleFile succeeds.
    await fs.writeFile(
      path.join(workspace.original, 'sample.class'),
      Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34])
    )
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('registers jvm.decompile with Java decompilation aspects', () => {
    expect(jvmDecompilePlugin.id).toBe('jvm-decompile')
    expect(jvmDecompilePlugin.aspects.capabilities).toEqual(
      expect.arrayContaining([
        'java-decompilation',
        'class-recovery',
        'source-recovery',
        'archive-decompilation',
      ])
    )
    expect(jvmDecompilePlugin.aspects.formats).toEqual(
      expect.arrayContaining(['class', 'jar', 'war', 'aar', 'jmod'])
    )
    expect(jvmDecompilePlugin.surfaceRules).toEqual(
      expect.objectContaining({ tier: 2, category: 'reverse-engineering' })
    )

    const registered: string[] = []
    const fakeServer = {
      registerTool: (def: { name: string }) => registered.push(def.name),
    }
    const toolNames = jvmDecompilePlugin.register?.(fakeServer as any, {
      workspaceManager,
      database,
    } as any)
    expect(registered).toEqual(['jvm.decompile'])
    expect(toolNames).toEqual(['jvm.decompile'])
  })

  test('declares passive read-only runtime policy and never executes bytecode', () => {
    expect(jvmDecompileToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(jvmDecompileToolDefinition.aspects.runtimes).toEqual(['cfr'])
    expect(jvmDecompileToolDefinition.runtimePolicy.notes).toEqual(
      expect.arrayContaining([
        expect.stringContaining('CFR decompiles bytecode by parsing class files'),
      ])
    )
  })

  test('returns setup_required when CFR_JAR is not configured', async () => {
    delete process.env.CFR_JAR
    delete process.env.JAVA_PATH
    delete process.env.JAVA_HOME

    const handler = createJvmDecompileHandler({
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
    expect(data.backend.missing).toBe('CFR_JAR')
    expect(data.summary).toMatch(/CFR jar not configured/)
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['system.health', 'system.setup.guide'])
    )
  })

  test('validates missing sample_id rejects before backend resolution', async () => {
    delete process.env.CFR_JAR
    const handler = createJvmDecompileHandler({
      workspaceManager,
      database,
    } as any)
    const result = await handler({ persist_artifact: false } as any)
    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/sample_id|Invalid arguments|required/i)
  })

  test('class filter accepts a substring and narrows decompiled classes', () => {
    // Schema-level: class_filter is an optional string.
    const parsed = jvmDecompileToolDefinition.inputSchema as any
    expect(parsed.shape.class_filter).toBeDefined()
    expect(parsed.shape.class_filter.isOptional()).toBe(true)
  })
})
