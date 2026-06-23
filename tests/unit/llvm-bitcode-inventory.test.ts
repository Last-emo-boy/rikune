import { describe, expect, test } from '@jest/globals'
import {
  buildLlvmBitcodeInventoryFromBuffer,
  llvmBitcodeInventoryToolDefinition,
} from '../../src/plugins/llvm-bitcode/tools/llvm-bitcode-inventory.js'

const RAW_MAGIC = Buffer.from([0x42, 0x43, 0xc0, 0xde])

function writeBits(bits: number[], value: number, width: number) {
  for (let i = 0; i < width; i++) bits.push((value >> i) & 1)
}

function writeVbr(bits: number[], value: number, width: number) {
  const payloadBits = width - 1
  const mask = (1 << payloadBits) - 1
  let remaining = value
  while (true) {
    let chunk = remaining & mask
    remaining >>= payloadBits
    if (remaining !== 0) chunk |= 1 << payloadBits
    writeBits(bits, chunk, width)
    if (remaining === 0) break
  }
}

function align32(bits: number[]) {
  while (bits.length % 32 !== 0) bits.push(0)
}

function bitsToBuffer(bits: number[]): Buffer {
  const bytes = Buffer.alloc(Math.ceil(bits.length / 8))
  bits.forEach((bit, index) => {
    if (bit) bytes[Math.floor(index / 8)] |= 1 << index % 8
  })
  return bytes
}

function rawBitcodeFixture(): Buffer {
  const bits: number[] = []
  writeBits(bits, 3, 2)
  writeVbr(bits, 1, 6)
  writeVbr(bits, 2, 6)
  writeVbr(bits, 42, 6)
  writeVbr(bits, 7, 6)
  writeBits(bits, 0, 2)
  align32(bits)
  return Buffer.concat([
    RAW_MAGIC,
    bitsToBuffer(bits),
    Buffer.from('target triple=x86_64-unknown-linux-gnu /tmp/source.c clang LLVM', 'ascii'),
  ])
}

function wrapperFixture(payload: Buffer): Buffer {
  const header = Buffer.alloc(20)
  header.writeUInt32LE(0x0b17c0de, 0)
  header.writeUInt32LE(0, 4)
  header.writeUInt32LE(header.length, 8)
  header.writeUInt32LE(payload.length, 12)
  header.writeUInt32LE(0, 16)
  return Buffer.concat([header, payload])
}

describe('llvm.bitcode.inventory', () => {
  test('decodes raw LLVM bitcode without invoking LLVM tools', () => {
    const inventory = buildLlvmBitcodeInventoryFromBuffer(rawBitcodeFixture(), {
      filename: 'module.bc',
      sampleId: 'sha256:llvm',
    })

    expect(inventory.format).toBe('llvm-bitcode')
    expect(inventory.detected_by).toContain('magic:BC-c0-de')
    expect(inventory.bitstream).toEqual(
      expect.objectContaining({
        decode_status: 'parsed',
        block_count: 1,
        record_count: 1,
      })
    )
    expect(inventory.embedded_strings).toEqual(
      expect.objectContaining({
        target_triples: expect.arrayContaining(['x86_64-unknown-linux-gnu']),
        paths: expect.arrayContaining(['/tmp/source.c']),
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_llvm_toolchain_required: true,
        no_compile: true,
        no_link: true,
        no_execute: true,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        llvm_tool_invoked_by_tool: false,
        compiled_by_tool: false,
        linked_by_tool: false,
        jit_started_by_tool: false,
      })
    )
  })

  test('detects LLVM bitcode wrapper metadata and embedded stream bounds', () => {
    const inventory = buildLlvmBitcodeInventoryFromBuffer(wrapperFixture(rawBitcodeFixture()), {
      filename: 'module.bc',
    })

    expect(inventory.format).toBe('llvm-bitcode-wrapper')
    expect(inventory.container).toEqual(
      expect.objectContaining({
        kind: 'bitcode-wrapper',
        version: 0,
        offset: 20,
        bounds_valid: true,
        embedded_magic_valid: true,
      })
    )
    expect(inventory.bitstream).toEqual(
      expect.objectContaining({ stream_offset: 20, decode_status: 'parsed' })
    )
  })

  test('flags invalid wrappers without executing or repairing input', () => {
    const bad = Buffer.alloc(24)
    bad.writeUInt32LE(0x0b17c0de, 0)
    bad.writeUInt32LE(7, 4)
    bad.writeUInt32LE(20, 8)
    bad.writeUInt32LE(4096, 12)

    const inventory = buildLlvmBitcodeInventoryFromBuffer(bad, { filename: 'bad.bc' })

    expect(inventory.format).toBe('llvm-bitcode-wrapper')
    expect(inventory.risk_summary.flags).toEqual(
      expect.arrayContaining([
        'wrapper-bounds-invalid',
        'wrapper-version-unexpected',
        'wrapper-embedded-magic-missing',
      ])
    )
    expect(inventory.policy.no_mutation).toBe(true)
  })

  test('declares passive workflow metadata for discovery and handoff', () => {
    expect(llvmBitcodeInventoryToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['llvm-bitcode', 'llvm-bc', 'llvm-ir', 'bc', 'll'])
    )
    expect(llvmBitcodeInventoryToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_llvm_toolchain_required', 'no_compile'])
    )
    expect(
      llvmBitcodeInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toContain('llvm_bitcode_inventory')
    expect(llvmBitcodeInventoryToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'llvm.bitcode-static-inventory',
        startsWith: ['llvm.bitcode.inventory'],
        nextTools: expect.arrayContaining(['artifact.read', 'workflow.search']),
        producesArtifacts: ['llvm_bitcode_inventory'],
        safety: expect.arrayContaining(['no_compile', 'no_link', 'no_execute']),
      })
    )
  })
})
