import { describe, expect, test } from '@jest/globals'
import { discoverBuiltInPlugins } from '../../src/core/plugin-system/discovery.js'
import { createPluginTestHarness, type Plugin } from '../../src/plugins/sdk.js'
import {
  createSerializationInventoryHandler,
  serializationInventoryToolDefinition,
  SERIALIZATION_INVENTORY_ARTIFACT_TYPE,
} from '../../src/plugins/serialization-format/tools/serialization-inventory.js'
import type { PluginToolDeps } from '../../src/plugins/sdk.js'
import { tmpdir } from 'os'
import { join } from 'path'

const TMP_DIR = tmpdir()

function requirePlugin(plugins: Plugin[], id: string): Plugin {
  const plugin = plugins.find((candidate) => candidate.id === id)
  expect(plugin).toBeDefined()
  return plugin as Plugin
}

describe('serialization-format plugin', () => {
  test('is discovered as a built-in plugin', async () => {
    const plugins = await discoverBuiltInPlugins()
    const plugin = requirePlugin(plugins, 'serialization-format')
    expect(plugin.tools).toBeDefined()
    expect(plugin.tools!.length).toBeGreaterThanOrEqual(1)
  })

  test('registers serialization.inventory tool', async () => {
    const plugins = await discoverBuiltInPlugins()
    const plugin = requirePlugin(plugins, 'serialization-format')
    const harness = createPluginTestHarness()
    harness.registerPlugin(plugin)
    const tool = harness.registeredTools.find(
      (entry) => entry.definition.name === 'serialization.inventory'
    )
    expect(tool).toBeDefined()
    expect(tool!.definition.aspects?.formats).toContain('protobuf')
    expect(tool!.definition.aspects?.formats).toContain('msgpack')
    expect(tool!.definition.artifacts?.[0]?.type).toBe(SERIALIZATION_INVENTORY_ARTIFACT_TYPE)
  })

  test('detects MessagePack format from a crafted buffer', async () => {
    // fixmap with 2 entries: "a" -> 1, "b" -> "hi"
    const data = Buffer.from([
      0x82, // fixmap, 2 entries
      0xa1, 0x61, // fixstr "a"
      0x01, // uint 1
      0xa1, 0x62, // fixstr "b"
      0xa2, 0x68, 0x69, // fixstr "hi"
    ])
    const deps = {
      workspaceManager: {},
      database: {
        findSample: () => ({ id: 'sha256:test' }),
      },
      resolvePrimarySamplePath: async () => ({ samplePath: '/tmp/claude-0/rikune-test-msgpack.bin' }),
    } as unknown as PluginToolDeps

    // Write the buffer to a temp file so the handler can read it.
    const fs = await import('fs/promises')
    const tmpPath = join(TMP_DIR, 'rikune-test-msgpack.bin')
    await fs.writeFile(tmpPath, data)
    ;(deps as any).resolvePrimarySamplePath = async () => ({ samplePath: tmpPath })

    const handler = createSerializationInventoryHandler(deps)
    const result: any = await handler({ sample_id: 'sha256:test', persist_artifact: false })
    expect(result.ok).toBe(true)
    expect(result.data.format).toBe('msgpack')
    expect(result.data.detections.some((d: any) => d.format === 'msgpack')).toBe(true)
    expect(result.data.safety).toContain('no_deserialization')
  })

  test('detects BSON format from a crafted buffer', async () => {
    // Minimal BSON document: { "hi": 1 }
    // int32 size | type 0x01 (double) | "hi\0" | 8 bytes double | 0x00 terminator
    // Simpler: { "a": int32 1 }
    // int32 size | 0x10 (int32) | "a\0" | int32 1 | 0x00
    const body = Buffer.concat([
      Buffer.from([0x10]), // int32 type
      Buffer.from('a\0', 'utf8'), // key "a" + null
      Buffer.from([0x01, 0x00, 0x00, 0x00]), // value 1
      Buffer.from([0x00]), // terminator
    ])
    const sizeBuf = Buffer.allocUnsafe(4)
    sizeBuf.writeInt32LE(body.length + 4, 0)
    const data = Buffer.concat([sizeBuf, body])

    const fs = await import('fs/promises')
    const tmpPath = join(TMP_DIR, 'rikune-test-bson.bin')
    await fs.writeFile(tmpPath, data)

    const deps = {
      workspaceManager: {},
      database: { findSample: () => ({ id: 'sha256:test' }) },
      resolvePrimarySamplePath: async () => ({ samplePath: tmpPath }),
    } as unknown as PluginToolDeps

    const handler = createSerializationInventoryHandler(deps)
    const result: any = await handler({ sample_id: 'sha256:test', persist_artifact: false })
    expect(result.ok).toBe(true)
    expect(result.data.detections.some((d: any) => d.format === 'bson')).toBe(true)
    expect(result.data.risk_level).toBeDefined()
  })

  test('detects Avro object container magic', async () => {
    const data = Buffer.concat([
      Buffer.from([0x4f, 0x62, 0x6a, 0x01]), // "Obj\x01"
      Buffer.alloc(32, 0),
    ])

    const fs = await import('fs/promises')
    const tmpPath = join(TMP_DIR, 'rikune-test-avro.bin')
    await fs.writeFile(tmpPath, data)

    const deps = {
      workspaceManager: {},
      database: { findSample: () => ({ id: 'sha256:test' }) },
      resolvePrimarySamplePath: async () => ({ samplePath: tmpPath }),
    } as unknown as PluginToolDeps

    const handler = createSerializationInventoryHandler(deps)
    const result: any = await handler({ sample_id: 'sha256:test', persist_artifact: false })
    expect(result.ok).toBe(true)
    expect(result.data.detections.some((d: any) => d.format === 'avro' && d.confidence === 'high')).toBe(true)
  })

  test('tool definition has workflow recipe and evidence mapping', () => {
    expect(serializationInventoryToolDefinition.workflowRecipes?.[0]?.id).toBe('serialization.inventory')
    expect(serializationInventoryToolDefinition.evidence?.length).toBeGreaterThan(0)
    expect(serializationInventoryToolDefinition.aspects?.safety).toContain('passive')
  })

  test('returns error for missing sample', async () => {
    const deps = {
      workspaceManager: {},
      database: { findSample: () => null },
    } as unknown as PluginToolDeps
    const handler = createSerializationInventoryHandler(deps)
    const result: any = await handler({ sample_id: 'sha256:missing', persist_artifact: false })
    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })
})
