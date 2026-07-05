import { describe, expect, test } from '@jest/globals'
import { buildShaderIrInventoryFromBuffer } from '../../src/plugins/shader-ir/tools/shader-ir-inventory.js'

function spirvStringWords(value: string): number[] {
  const bytes = Buffer.from(`${value}\0`, 'utf8')
  const padded = Buffer.concat([bytes, Buffer.alloc((4 - (bytes.length % 4)) % 4)])
  const words: number[] = []
  for (let offset = 0; offset < padded.length; offset += 4) {
    words.push(padded.readUInt32LE(offset))
  }
  return words
}

function spirvInstruction(opcode: number, operands: number[]): number[] {
  return [((operands.length + 1) << 16) | opcode, ...operands]
}

function spirvFixture(): Buffer {
  const words = [
    0x07230203,
    0x00010300,
    0,
    16,
    0,
    ...spirvInstruction(17, [1]),
    ...spirvInstruction(14, [0, 1]),
    ...spirvInstruction(15, [4, 5, ...spirvStringWords('main')]),
    ...spirvInstruction(16, [5, 7]),
    ...spirvInstruction(5, [6, ...spirvStringWords('texture0')]),
    ...spirvInstruction(71, [6, 34, 0]),
    ...spirvInstruction(71, [6, 33, 1]),
  ]
  const data = Buffer.alloc(words.length * 4)
  words.forEach((word, index) => data.writeUInt32LE(word >>> 0, index * 4))
  return data
}

function dxContainerFixture(): Buffer {
  const dxilPayload = Buffer.from([0x42, 0x43, 0xc0, 0xde, 0x00, 0x00, 0x00, 0x00])
  const isgnPayload = Buffer.from('signature', 'ascii')
  const parts = [
    { fourcc: 'DXIL', payload: dxilPayload },
    { fourcc: 'ISGN', payload: isgnPayload },
  ]
  const headerSize = 32 + parts.length * 4
  const partBuffers = parts.map((part) => {
    const header = Buffer.alloc(8)
    header.write(part.fourcc, 0, 'ascii')
    header.writeUInt32LE(part.payload.length, 4)
    return Buffer.concat([header, part.payload])
  })
  const totalSize = headerSize + partBuffers.reduce((sum, part) => sum + part.length, 0)
  const header = Buffer.alloc(headerSize)
  header.write('DXBC', 0, 'ascii')
  header.writeUInt32LE(totalSize, 24)
  header.writeUInt32LE(parts.length, 28)
  let offset = headerSize
  for (let index = 0; index < parts.length; index++) {
    header.writeUInt32LE(offset, 32 + index * 4)
    offset += partBuffers[index].length
  }
  return Buffer.concat([header, ...partBuffers])
}

describe('shader IR inventory', () => {
  test('builds SPIR-V inventory without invoking validators or GPU runtimes', () => {
    const inventory = buildShaderIrInventoryFromBuffer(spirvFixture(), {
      filename: 'fragment.spv',
    })

    expect(inventory.format).toBe('spir-v')
    expect(inventory.structure.spirv).toEqual(
      expect.objectContaining({
        version: '1.3',
        memory_model: 'GLSL450',
        capabilities: expect.arrayContaining(['Shader']),
      })
    )
    expect(inventory.entry_points).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'main', stage: 'Fragment' })])
    )
    expect(inventory.resource_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ decoration: 'DescriptorSet', values: [0] }),
        expect.objectContaining({ decoration: 'Binding', values: [1] }),
      ])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_gpu_driver: true,
        no_shader_compiler: true,
        no_validator: true,
        no_disassembler: true,
      })
    )
    expect(inventory.quality_gates.validator_invoked_by_tool).toBe(false)
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['culifter.gpu.plan', 'analysis.evidence.graph'])
    )
  })

  test('builds DXIL container inventory from DXBC container parts', () => {
    const inventory = buildShaderIrInventoryFromBuffer(dxContainerFixture(), {
      filename: 'shader.dxil',
    })

    expect(inventory.format).toBe('dxil-container')
    expect(inventory.structure.dxcontainer).toEqual(
      expect.objectContaining({
        contains_dxil: true,
        part_fourccs: expect.arrayContaining(['DXIL', 'ISGN']),
      })
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['llvm.bitcode.inventory', 'culifter.gpu.plan'])
    )
    expect(inventory.policy.no_external_tool).toBe(true)
  })

  test('profiles WGSL source without compiling or running WebGPU', () => {
    const wgsl = Buffer.from(
      `
        struct Output { @builtin(position) pos: vec4<f32>, };
        @group(0) @binding(2) var<storage> buffer0: array<u32>;
        @compute @workgroup_size(8, 8, 1)
        fn main() {}
      `,
      'utf8'
    )
    const inventory = buildShaderIrInventoryFromBuffer(wgsl, { filename: 'shader.wgsl' })

    expect(inventory.format).toBe('wgsl-source')
    expect(inventory.entry_points).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'main', stage: 'compute' })])
    )
    expect(inventory.resource_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ group: 0, binding: 2, address_space: 'storage' }),
      ])
    )
    expect(inventory.quality_gates.runtime_started_by_tool).toBe(false)
  })
})
