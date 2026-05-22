import { describe, expect, test } from '@jest/globals'
import { buildWasmStructureFromBuffer } from '../../src/plugins/wasm/tools/wasm-structure-analyze.js'

describe('wasm.structure.analyze', () => {
  test('parses valid WASM module headers without starting a runtime', () => {
    const inventory = buildWasmStructureFromBuffer(
      Buffer.from([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x03, 0x6e, 0x61, 0x6d,
        0x07, 0x01, 0x00,
      ]),
      { filename: 'module.wasm' }
    )

    expect(inventory.format).toBe('wasm')
    expect(inventory.valid_magic).toBe(true)
    expect(inventory.version).toBe(1)
    expect(inventory.custom_sections).toContain('nam')
    expect(inventory.runtime_plan.status).toBe('plan_only')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_runtime_start: true,
      })
    )
    expect(inventory.next_actions.join(' ')).toMatch(/Do not instantiate/i)
  })

  test('returns explicit invalid magic summary while preserving passive policy', () => {
    const inventory = buildWasmStructureFromBuffer(Buffer.from('not wasm'), {
      filename: 'module.wasm',
    })

    expect(inventory.valid_magic).toBe(false)
    expect(inventory.sections).toEqual([])
    expect(inventory.policy.no_runtime_start).toBe(true)
    expect(inventory.summary).toMatch(/does not contain a valid WASM/i)
  })
})
