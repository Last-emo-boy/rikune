import { describe, expect, test } from '@jest/globals'
import {
  btfTypeInventoryToolDefinition,
  buildBtfInventoryFromBuffer,
} from '../../src/plugins/btf/tools/btf-type-inventory.js'

const BTF_MAGIC = 0xeb9f

function stringTable(strings: string[]) {
  const offsets = new Map<string, number>()
  const chunks = [Buffer.from([0])]
  let offset = 1
  for (const value of strings) {
    offsets.set(value, offset)
    const bytes = Buffer.from(`${value}\0`, 'utf8')
    chunks.push(bytes)
    offset += bytes.length
  }
  return { table: Buffer.concat(chunks), offsets }
}

function btfInfo(kind: number, vlen = 0, kindFlag = false) {
  return (kindFlag ? 0x80000000 : 0) | (kind << 24) | vlen
}

function rawBtfFixture() {
  const { table, offsets } = stringTable([
    'int',
    'task_struct',
    'pid',
    'handle_exec',
    '.maps',
    'tracepoint/syscalls/sys_enter_execve',
    '0:1:0',
  ])
  const types: Buffer[] = []
  const intType = Buffer.alloc(16)
  intType.writeUInt32LE(offsets.get('int') ?? 0, 0)
  intType.writeUInt32LE(btfInfo(1), 4)
  intType.writeUInt32LE(4, 8)
  intType.writeUInt32LE(32, 12)
  types.push(intType)

  const structType = Buffer.alloc(24)
  structType.writeUInt32LE(offsets.get('task_struct') ?? 0, 0)
  structType.writeUInt32LE(btfInfo(4, 1), 4)
  structType.writeUInt32LE(4, 8)
  structType.writeUInt32LE(offsets.get('pid') ?? 0, 12)
  structType.writeUInt32LE(1, 16)
  structType.writeUInt32LE(0, 20)
  types.push(structType)

  const protoType = Buffer.alloc(12)
  protoType.writeUInt32LE(0, 0)
  protoType.writeUInt32LE(btfInfo(13), 4)
  protoType.writeUInt32LE(1, 8)
  types.push(protoType)

  const funcType = Buffer.alloc(12)
  funcType.writeUInt32LE(offsets.get('handle_exec') ?? 0, 0)
  funcType.writeUInt32LE(btfInfo(12), 4)
  funcType.writeUInt32LE(3, 8)
  types.push(funcType)

  const datasecType = Buffer.alloc(24)
  datasecType.writeUInt32LE(offsets.get('.maps') ?? 0, 0)
  datasecType.writeUInt32LE(btfInfo(15, 1), 4)
  datasecType.writeUInt32LE(4, 8)
  datasecType.writeUInt32LE(2, 12)
  datasecType.writeUInt32LE(0, 16)
  datasecType.writeUInt32LE(4, 20)
  types.push(datasecType)

  const typeSection = Buffer.concat(types)
  const header = Buffer.alloc(24)
  header.writeUInt16LE(BTF_MAGIC, 0)
  header[2] = 1
  header[3] = 0
  header.writeUInt32LE(24, 4)
  header.writeUInt32LE(0, 8)
  header.writeUInt32LE(typeSection.length, 12)
  header.writeUInt32LE(typeSection.length, 16)
  header.writeUInt32LE(table.length, 20)
  return { btf: Buffer.concat([header, typeSection, table]), offsets }
}

function btfExtFixture(offsets: Map<string, number>) {
  const core = Buffer.alloc(4 + 8 + 16)
  core.writeUInt32LE(16, 0)
  core.writeUInt32LE(offsets.get('tracepoint/syscalls/sys_enter_execve') ?? 0, 4)
  core.writeUInt32LE(1, 8)
  core.writeUInt32LE(8, 12)
  core.writeUInt32LE(2, 16)
  core.writeUInt32LE(offsets.get('0:1:0') ?? 0, 20)
  core.writeUInt32LE(0, 24)

  const header = Buffer.alloc(32)
  header.writeUInt16LE(BTF_MAGIC, 0)
  header[2] = 1
  header[3] = 0
  header.writeUInt32LE(32, 4)
  header.writeUInt32LE(0, 8)
  header.writeUInt32LE(0, 12)
  header.writeUInt32LE(0, 16)
  header.writeUInt32LE(0, 20)
  header.writeUInt32LE(0, 24)
  header.writeUInt32LE(core.length, 28)
  return Buffer.concat([header, core])
}

function align(value: number, alignment = 8) {
  return Math.ceil(value / alignment) * alignment
}

function elfWithBtfFixture(btf: Buffer, btfExt: Buffer) {
  const shstr = Buffer.from('\0.BTF\0.BTF.ext\0.shstrtab\0', 'ascii')
  const headerSize = 64
  const btfOffset = align(headerSize)
  const btfExtOffset = align(btfOffset + btf.length)
  const shstrOffset = align(btfExtOffset + btfExt.length)
  const sectionHeaderOffset = align(shstrOffset + shstr.length)
  const fileSize = sectionHeaderOffset + 4 * 64
  const elf = Buffer.alloc(fileSize)

  elf[0] = 0x7f
  elf.write('ELF', 1, 'ascii')
  elf[4] = 2
  elf[5] = 1
  elf[6] = 1
  elf.writeUInt16LE(1, 16)
  elf.writeUInt16LE(247, 18)
  elf.writeBigUInt64LE(BigInt(sectionHeaderOffset), 40)
  elf.writeUInt16LE(64, 58)
  elf.writeUInt16LE(4, 60)
  elf.writeUInt16LE(3, 62)

  btf.copy(elf, btfOffset)
  btfExt.copy(elf, btfExtOffset)
  shstr.copy(elf, shstrOffset)

  writeSection(elf, sectionHeaderOffset + 64, 1, btfOffset, btf.length)
  writeSection(elf, sectionHeaderOffset + 128, 6, btfExtOffset, btfExt.length)
  writeSection(elf, sectionHeaderOffset + 192, 15, shstrOffset, shstr.length)

  return elf
}

function writeSection(
  elf: Buffer,
  offset: number,
  nameOffset: number,
  dataOffset: number,
  size: number
) {
  elf.writeUInt32LE(nameOffset, offset)
  elf.writeUInt32LE(1, offset + 4)
  elf.writeBigUInt64LE(0n, offset + 8)
  elf.writeBigUInt64LE(0n, offset + 16)
  elf.writeBigUInt64LE(BigInt(dataOffset), offset + 24)
  elf.writeBigUInt64LE(BigInt(size), offset + 32)
  elf.writeUInt32LE(0, offset + 40)
  elf.writeUInt32LE(0, offset + 44)
  elf.writeBigUInt64LE(1n, offset + 48)
  elf.writeBigUInt64LE(0n, offset + 56)
}

describe('btf.type.inventory', () => {
  test('decodes raw BTF types without invoking kernel or libbpf tooling', () => {
    const { btf } = rawBtfFixture()
    const inventory = buildBtfInventoryFromBuffer(btf, {
      filename: 'vmlinux.btf',
      sampleId: 'sha256:btf',
    })

    expect(inventory.format).toBe('btf')
    expect(inventory.detected_by).toContain('magic:btf')
    expect(inventory.btf).toEqual(
      expect.objectContaining({
        present: true,
        decode_status: 'parsed',
        type_count: 5,
      })
    )
    expect(inventory.btf.kind_counts).toEqual(
      expect.objectContaining({ INT: 1, STRUCT: 1, FUNC: 1, DATASEC: 1 })
    )
    expect(inventory.btf.struct_preview).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'task_struct',
          members: expect.arrayContaining([expect.objectContaining({ name: 'pid' })]),
        }),
      ])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_bpf_syscall: true,
        no_kernel_verifier_run: true,
        no_program_load: true,
        no_libbpf: true,
        no_bpftool: true,
      })
    )
  })

  test('extracts ELF .BTF and .BTF.ext CO-RE relocation groups passively', () => {
    const { btf, offsets } = rawBtfFixture()
    const btfExt = btfExtFixture(offsets)
    const inventory = buildBtfInventoryFromBuffer(elfWithBtfFixture(btf, btfExt), {
      filename: 'program.bpf.o',
    })

    expect(inventory.format).toBe('btf-elf')
    expect(inventory.detected_by).toEqual(
      expect.arrayContaining(['section:.BTF', 'section:.BTF.ext'])
    )
    expect(inventory.container.btf_section).toEqual(expect.objectContaining({ name: '.BTF' }))
    expect(inventory.btf_ext).toEqual(
      expect.objectContaining({
        present: true,
        decode_status: 'parsed',
      })
    )
    expect(inventory.btf_ext.core_relocations).toEqual(
      expect.objectContaining({
        record_count: 1,
        groups: expect.arrayContaining([
          expect.objectContaining({
            section: 'tracepoint/syscalls/sys_enter_execve',
            kind_counts: expect.objectContaining({ FIELD_BYTE_OFFSET: 1 }),
            accessor_preview: expect.arrayContaining(['0:1:0']),
          }),
        ]),
      })
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['ebpf.bytecode.inventory', 'linux.runtime.plan'])
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        bpf_syscall_invoked_by_tool: false,
        kernel_verifier_invoked_by_tool: false,
        libbpf_invoked_by_tool: false,
      })
    )
  })

  test('declares passive workflow metadata for BTF and CO-RE handoff', () => {
    expect(btfTypeInventoryToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['btf', 'btf-ext', 'btf-elf', 'core-relocations'])
    )
    expect(btfTypeInventoryToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_libbpf', 'no_bpftool', 'no_program_load'])
    )
    expect(btfTypeInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
      'btf_type_inventory'
    )
    expect(btfTypeInventoryToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'btf.type-core-inventory',
        startsWith: ['btf.type.inventory'],
        nextTools: expect.arrayContaining(['ebpf.bytecode.inventory', 'linux.runtime.plan']),
        producesArtifacts: ['btf_type_inventory'],
        runtimeBackends: ['linux-runtime'],
      })
    )
  })
})
