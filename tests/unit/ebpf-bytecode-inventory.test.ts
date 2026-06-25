import { describe, expect, test } from '@jest/globals'
import {
  buildEbpfBytecodeInventoryFromBuffer,
  ebpfBytecodeInventoryToolDefinition,
} from '../../src/plugins/ebpf-bytecode/tools/ebpf-bytecode-inventory.js'

function ebpfInstruction(
  opcode: number,
  dst: number,
  src: number,
  off: number,
  imm: number
): Buffer {
  const data = Buffer.alloc(8)
  data[0] = opcode
  data[1] = (src << 4) | dst
  data.writeInt16LE(off, 2)
  data.writeInt32LE(imm, 4)
  return data
}

function rawEbpfFixture(): Buffer {
  return Buffer.concat([
    ebpfInstruction(0xb7, 1, 0, 0, 1),
    ebpfInstruction(0x18, 1, 1, 0, 7),
    ebpfInstruction(0x00, 0, 0, 0, 0),
    ebpfInstruction(0x85, 0, 0, 0, 1),
    ebpfInstruction(0x85, 0, 0, 0, 12),
    ebpfInstruction(0x05, 0, 0, -2, 0),
    ebpfInstruction(0x95, 0, 0, 0, 0),
  ])
}

function elf64EbpfObjectFixture(code: Buffer): Buffer {
  const shstrtab = Buffer.from('\0xdp\0.shstrtab\0', 'ascii')
  const codeOffset = 0x80
  const stringOffset = 0xc0
  const sectionHeaderOffset = 0x100
  const data = Buffer.alloc(sectionHeaderOffset + 64 * 3)

  data[0] = 0x7f
  data[1] = 0x45
  data[2] = 0x4c
  data[3] = 0x46
  data[4] = 2
  data[5] = 1
  data[6] = 1
  data.writeUInt16LE(1, 16)
  data.writeUInt16LE(247, 18)
  data.writeUInt32LE(1, 20)
  data.writeBigUInt64LE(BigInt(sectionHeaderOffset), 40)
  data.writeUInt16LE(64, 52)
  data.writeUInt16LE(64, 58)
  data.writeUInt16LE(3, 60)
  data.writeUInt16LE(2, 62)

  code.copy(data, codeOffset)
  shstrtab.copy(data, stringOffset)

  const xdpSection = sectionHeaderOffset + 64
  data.writeUInt32LE(1, xdpSection)
  data.writeUInt32LE(1, xdpSection + 4)
  data.writeBigUInt64LE(0x6n, xdpSection + 8)
  data.writeBigUInt64LE(BigInt(codeOffset), xdpSection + 24)
  data.writeBigUInt64LE(BigInt(code.length), xdpSection + 32)
  data.writeBigUInt64LE(8n, xdpSection + 48)
  data.writeBigUInt64LE(8n, xdpSection + 56)

  const shstrSection = sectionHeaderOffset + 64 * 2
  data.writeUInt32LE(5, shstrSection)
  data.writeUInt32LE(3, shstrSection + 4)
  data.writeBigUInt64LE(BigInt(stringOffset), shstrSection + 24)
  data.writeBigUInt64LE(BigInt(shstrtab.length), shstrSection + 32)

  return data
}

describe('ebpf.bytecode.inventory', () => {
  test('decodes raw eBPF bytecode without loading or verifying programs', () => {
    const inventory = buildEbpfBytecodeInventoryFromBuffer(rawEbpfFixture(), {
      filename: 'program.bpf',
      sampleId: 'sha256:ebpf',
    })

    expect(inventory.format).toBe('raw-ebpf')
    expect(inventory.instruction_count).toBe(7)
    expect(inventory.helper_calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ helper_id: 1, name: 'map_lookup_elem' }),
        expect.objectContaining({ helper_id: 12, name: 'tail_call' }),
      ])
    )
    expect(inventory.map_references).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          pseudo_type: 'BPF_PSEUDO_MAP_FD',
          fd_or_id: 7,
          access_hint: 'map-read',
        }),
      ])
    )
    expect(inventory.risk_summary.flags).toEqual(
      expect.arrayContaining(['tail-call', 'loop-backedge'])
    )
    expect(inventory.verifier_precheck).toEqual(
      expect.objectContaining({
        passive_precheck_only: true,
        instruction_width_valid: true,
        lddw_pairs_valid: true,
        jump_targets_in_range: true,
        last_instruction_exit: true,
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_bpf_syscall: true,
        no_kernel_verifier_run: true,
        no_program_load: true,
        no_attach: true,
        no_map_create: true,
        no_runtime_start: true,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.ebpf_bytecode_inventory.quality_gates.v1',
        passive_static_inventory: true,
        bpf_syscall_called_by_tool: false,
        kernel_verifier_run_by_tool: false,
        program_loaded_by_tool: false,
      })
    )
  })

  test('detects ELF EM_BPF sections and program type hints', () => {
    const inventory = buildEbpfBytecodeInventoryFromBuffer(
      elf64EbpfObjectFixture(
        Buffer.concat([ebpfInstruction(0xb7, 0, 0, 0, 0), ebpfInstruction(0x95, 0, 0, 0, 0)])
      ),
      { filename: 'xdp_prog.o' }
    )

    expect(inventory.format).toBe('ebpf-elf')
    expect(inventory.elf_header).toEqual(expect.objectContaining({ machine_name: 'EM_BPF' }))
    expect(inventory.sections).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'xdp',
          executable: true,
          program_type_hint: 'xdp',
          decoded_instruction_count: 2,
        }),
      ])
    )
    expect(inventory.decode_scope).toContain('xdp')
  })

  test('declares passive workflow metadata for discovery and handoff', () => {
    expect(ebpfBytecodeInventoryToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['ebpf', 'bpf', 'ebpf-bytecode', 'raw-ebpf', 'ebpf-elf'])
    )
    expect(ebpfBytecodeInventoryToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_bpf_syscall', 'no_kernel_verifier_run'])
    )
    expect(
      ebpfBytecodeInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toContain('ebpf_bytecode_inventory')
    expect(ebpfBytecodeInventoryToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'ebpf.bytecode-static-inventory',
        startsWith: ['ebpf.bytecode.inventory'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'elf.structure.analyze',
          'linux.runtime.plan',
        ]),
        producesArtifacts: ['ebpf_bytecode_inventory'],
        safety: expect.arrayContaining(['no_program_load', 'no_attach', 'no_kernel_verifier_run']),
      })
    )
  })
})
