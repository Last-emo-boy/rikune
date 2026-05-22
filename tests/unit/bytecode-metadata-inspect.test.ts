import { describe, expect, test } from '@jest/globals'
import { buildBytecodeMetadataFromBuffer } from '../../src/plugins/bytecode/tools/bytecode-metadata-inspect.js'

describe('bytecode.metadata.inspect', () => {
  test('extracts PYC metadata without starting Python or a decompiler', () => {
    const pyc = Buffer.alloc(32)
    pyc.writeUInt32LE(0x0a0d0da7, 0)
    pyc.writeUInt32LE(0, 4)
    pyc.writeUInt32LE(1700000000, 8)
    pyc.writeUInt32LE(1234, 12)
    pyc.write('demo.module', 16, 'ascii')

    const inventory = buildBytecodeMetadataFromBuffer(pyc, { filename: 'module.pyc' })

    expect(inventory.format).toBe('pyc')
    expect(inventory.version_hints).toContain('CPython 3.11')
    expect(inventory.header).toEqual(expect.objectContaining({ hash_based: false, source_size: 1234 }))
    expect(inventory.string_hints).toContain('demo.module')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_interpreter_start: true,
        no_decompiler_launch: true,
      })
    )
    expect(inventory.decompile_plan.status).toBe('plan_only')
  })

  test('covers Lua bytecode and V8 cached data as plan-only metadata inventories', () => {
    const lua = buildBytecodeMetadataFromBuffer(Buffer.from([0x1b, 0x4c, 0x75, 0x61, 0x54, 0x00]), {
      filename: 'chunk.luac',
    })
    const v8 = buildBytecodeMetadataFromBuffer(Buffer.from('V8CACHEDATA_DEMO_STRING'), {
      filename: 'cache.jsc',
    })

    expect(lua.format).toBe('lua-bytecode')
    expect(lua.version_hints).toContain('Lua 5.4')
    expect(v8.format).toBe('v8-cache')
    expect(v8.version_hints[0]).toMatch(/V8 cached data/i)
    expect([lua, v8].every((item) => item.policy.no_interpreter_start)).toBe(true)
  })
})
