import { describe, expect, test } from '@jest/globals'
import {
  buildLinuxBinaryInventoryFromBuffer,
  linuxBinaryInventoryToolDefinition,
} from '../../src/plugins/linux-binary/tools/linux-binary-inventory.js'

function writeAscii(buffer: Buffer, offset: number, value: string) {
  buffer.write(value, offset, 'ascii')
  buffer[offset + value.length] = 0
}

function minimalElf64WithLoaderProfile(): Buffer {
  const buffer = Buffer.alloc(0x700, 0)
  buffer[0] = 0x7f
  buffer.write('ELF', 1, 'ascii')
  buffer[4] = 2
  buffer[5] = 1
  buffer[6] = 1
  buffer[7] = 3
  buffer.writeUInt16LE(2, 16)
  buffer.writeUInt16LE(62, 18)
  buffer.writeUInt32LE(1, 20)
  buffer.writeBigUInt64LE(0x401000n, 24)
  buffer.writeBigUInt64LE(0x40n, 32)
  buffer.writeUInt16LE(64, 52)
  buffer.writeUInt16LE(56, 54)
  buffer.writeUInt16LE(4, 56)

  // PT_INTERP
  buffer.writeUInt32LE(3, 0x40)
  buffer.writeUInt32LE(4, 0x44)
  buffer.writeBigUInt64LE(0x200n, 0x48)
  buffer.writeBigUInt64LE(0x200n, 0x50)
  buffer.writeBigUInt64LE(0x200n, 0x58)
  buffer.writeBigUInt64LE(0x1cn, 0x60)
  buffer.writeBigUInt64LE(0x1cn, 0x68)

  // PT_DYNAMIC
  buffer.writeUInt32LE(2, 0x78)
  buffer.writeUInt32LE(4, 0x7c)

  // PT_GNU_STACK without PF_X.
  buffer.writeUInt32LE(0x6474e551, 0xb0)
  buffer.writeUInt32LE(6, 0xb4)

  // PT_GNU_RELRO
  buffer.writeUInt32LE(0x6474e552, 0xe8)
  buffer.writeUInt32LE(4, 0xec)

  writeAscii(buffer, 0x200, '/lib64/ld-linux-x86-64.so.2')
  writeAscii(buffer, 0x260, 'libc.so.6')
  writeAscii(buffer, 0x280, 'libcrypto.so.3')
  writeAscii(buffer, 0x2a0, '__stack_chk_fail')
  writeAscii(buffer, 0x2c0, 'BIND_NOW')
  writeAscii(buffer, 0x2e0, 'RUNPATH=/opt/demo/lib:/usr/local/lib')
  return buffer
}

describe('linux.binary.inventory', () => {
  test('declares passive loader/security workflow metadata', () => {
    expect(linuxBinaryInventoryToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'loader-profile',
        'security-profile',
        'hardening-candidates',
        'elf-interpreter-profile',
        'dependency-inventory',
        'workflow-handoff',
      ])
    )
    expect(linuxBinaryInventoryToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'linux-binary.passive-loader-security-profile',
        startsWith: ['linux.binary.inventory'],
        nextTools: expect.arrayContaining([
          'elf.structure.analyze',
          'linux.runtime.plan',
          'analysis.evidence.graph',
          'artifact.read',
        ]),
        producesArtifacts: ['linux_binary_inventory'],
        safety: expect.arrayContaining([
          'passive',
          'no_execute',
          'no_load',
          'no_core_replay',
          'no_kernel_module_load',
          'no_runtime_start',
        ]),
      })
    )
    expect(linuxBinaryInventoryToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noLiveExecution: true,
        noLoad: true,
        noMount: true,
        noCoreReplay: true,
        noKernelModuleLoad: true,
      })
    )
  })

  test('extracts conservative ELF loader and hardening candidates without execution', () => {
    const inventory = buildLinuxBinaryInventoryFromBuffer(minimalElf64WithLoaderProfile(), {
      filename: 'demo.elf',
      sampleId: 'sha256:linux',
    })

    expect(inventory.format).toBe('elf-executable')
    expect(inventory.elf_header).toEqual(
      expect.objectContaining({
        class: '64-bit',
        machine: 'x64',
        entrypoint: '0x401000',
      })
    )
    expect(inventory.loader_security_profile).toEqual(
      expect.objectContaining({
        entrypoint: '0x401000',
        interpreter: '/lib64/ld-linux-x86-64.so.2',
        dynamic_segment_present: true,
        nx_stack_candidate: true,
        executable_stack_candidate: false,
        relro_candidate: true,
        bind_now_candidate: true,
        canary_symbol_candidate: true,
      })
    )
    expect(inventory.loader_security_profile.needed_libraries).toEqual(
      expect.arrayContaining(['libc.so.6', 'libcrypto.so.3'])
    )
    expect(inventory.loader_security_profile.rpath_runpath_hints.join(' ')).toContain('/opt/demo/lib')
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.linux_binary_inventory.evidence_summary.v1',
        source_tool: 'linux.binary.inventory',
        format: 'elf-executable',
        loader_profile_present: true,
      })
    )
    expect(inventory.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        library_loaded_by_tool: false,
        core_replayed_by_tool: false,
        kernel_module_loaded_by_tool: false,
        runtime_started_by_tool: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        elf_header_present: true,
        loader_profile_present: true,
        hardening_candidates_present: true,
        sample_executed_by_tool: false,
      })
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'elf.structure.analyze',
        'linux.runtime.plan',
        'analysis.evidence.graph',
      ])
    )
  })
})
