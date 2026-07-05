import { describe, expect, test } from '@jest/globals'
import binaryHardeningPlugin from '../../src/plugins/binary-hardening/index.js'
import {
  BINARY_HARDENING_ARTIFACT_TYPE,
  binaryHardeningInventoryToolDefinition,
  buildBinaryHardeningInventoryFromBuffer,
  createBinaryHardeningInventoryHandler,
} from '../../src/plugins/binary-hardening/tools/binary-hardening-inventory.js'

function peFixture(strings: string[], dllCharacteristics: number): Buffer {
  const data = Buffer.alloc(0x1000, 0)
  data.write('MZ', 0, 'ascii')
  data.writeUInt32LE(0x80, 0x3c)
  data.write('PE\0\0', 0x80, 'ascii')
  data.writeUInt16LE(0x8664, 0x84)
  data.writeUInt16LE(2, 0x86)
  data.writeUInt16LE(0xf0, 0x94)
  data.writeUInt16LE(0x20b, 0x98)
  data.writeUInt16LE(dllCharacteristics, 0x80 + 24 + 0x46)

  const sectionTable = 0x80 + 24 + 0xf0
  data.write('.text', sectionTable, 'ascii')
  data.writeUInt32LE(0x100, sectionTable + 16)
  data.writeUInt32LE(0x400, sectionTable + 20)
  data.writeUInt32LE(0x60000020, sectionTable + 36)
  data.write('.jit', sectionTable + 40, 'ascii')
  data.writeUInt32LE(0x100, sectionTable + 56)
  data.writeUInt32LE(0x600, sectionTable + 60)
  data.writeUInt32LE(0xe0000020, sectionTable + 76)
  data.write(strings.join('\0'), 0x700, 'ascii')
  return data
}

function elfHardeningFixture(strings: string[]): Buffer {
  const data = Buffer.alloc(0x1400, 0)
  data.write('\x7fELF', 0, 'binary')
  data[4] = 2
  data[5] = 1
  data.writeUInt16LE(3, 0x10)
  data.writeUInt16LE(62, 0x12)
  data.writeBigUInt64LE(0x40n, 0x20)
  data.writeBigUInt64LE(0x500n, 0x28)
  data.writeUInt16LE(0x40, 0x36)
  data.writeUInt16LE(3, 0x38)
  data.writeUInt16LE(0x40, 0x3a)
  data.writeUInt16LE(3, 0x3c)
  data.writeUInt16LE(2, 0x3e)

  data.writeUInt32LE(0x6474e552, 0x40)
  data.writeUInt32LE(4, 0x44)

  data.writeUInt32LE(0x6474e551, 0x80)
  data.writeUInt32LE(6, 0x84)

  data.writeUInt32LE(2, 0xc0)
  data.writeUInt32LE(4, 0xc4)
  data.writeBigUInt64LE(0x300n, 0xc8)
  data.writeBigUInt64LE(0n, 0xd0)
  data.writeBigUInt64LE(0n, 0xd8)
  data.writeBigUInt64LE(0x40n, 0xe0)
  data.writeBigUInt64LE(0x40n, 0xe8)
  data.writeBigUInt64LE(8n, 0xf0)

  data.writeBigUInt64LE(24n, 0x300)
  data.writeBigUInt64LE(0n, 0x308)
  data.writeBigUInt64LE(0n, 0x310)

  const names = Buffer.from('\0.text\0.data\0.shstrtab\0', 'ascii')
  names.copy(data, 0x900)
  data.writeUInt32LE(1, 0x540)
  data.writeBigUInt64LE(0x6n, 0x548)
  data.writeBigUInt64LE(0xa00n, 0x558)
  data.writeBigUInt64LE(0x20n, 0x560)
  data.writeUInt32LE(7, 0x580)
  data.writeBigUInt64LE(0x3n, 0x588)
  data.writeBigUInt64LE(0xa20n, 0x598)
  data.writeBigUInt64LE(0x20n, 0x5a0)
  data.writeUInt32LE(13, 0x5c0)
  data.writeBigUInt64LE(0n, 0x5c8)
  data.writeBigUInt64LE(0x900n, 0x5d8)
  data.writeBigUInt64LE(BigInt(names.length), 0x5e0)

  data.write(strings.join('\0'), 0xb00, 'ascii')
  return data
}

function machoFixture(strings: string[]): Buffer {
  const data = Buffer.alloc(0x800, 0)
  data.writeUInt32LE(0xfeedfacf, 0)
  data.writeUInt32LE(0x0100000c, 4)
  data.writeUInt32LE(2, 8)
  data.writeUInt32LE(2, 12)
  data.writeUInt32LE(0, 16)
  data.writeUInt32LE(0, 20)
  data.writeUInt32LE(0x01200000, 24)
  data.write(strings.join('\0'), 0x200, 'ascii')
  return data
}

describe('binary.hardening.inventory', () => {
  test('declares passive cross-platform hardening metadata', () => {
    expect(binaryHardeningPlugin.id).toBe('binary-hardening')
    expect(binaryHardeningPlugin.executionDomain).toBe('static')
    expect(binaryHardeningPlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['binary-hardening', 'checksec', 'elf-hardening', 'cet', 'pac'])
    )
    expect(binaryHardeningInventoryToolDefinition.name).toBe('binary.hardening.inventory')
    expect(binaryHardeningInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)).toEqual(
      expect.arrayContaining([BINARY_HARDENING_ARTIFACT_TYPE])
    )
    const recipe = binaryHardeningInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'binary.hardening-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['binary.hardening.inventory'],
        producesArtifacts: [BINARY_HARDENING_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_loader_invocation',
          'no_exploit_test',
          'no_external_tool',
          'no_network_by_default',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'pe.security.profile',
        'compiler.codegen.fingerprint',
        'analysis.evidence.graph',
      ])
    )
  })

  test('summarizes PE DEP ASLR CFG XFG canary and W^X risks', () => {
    const inventory = buildBinaryHardeningInventoryFromBuffer(
      peFixture(
        ['__security_cookie', '__guard_xfg_check_icall_fptr', '__guard_check_icall_fptr'],
        0x4160
      ),
      { filename: 'guarded.exe', sampleId: 'sha256:pe' }
    )

    expect(inventory.format).toBe('pe-hardening-profile')
    expect(inventory.container.kind).toBe('pe')
    expect(inventory.mitigations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'pe.dep-nx', status: 'present' }),
        expect.objectContaining({ id: 'pe.aslr', status: 'present' }),
        expect.objectContaining({ id: 'pe.cfg', status: 'present' }),
        expect.objectContaining({ id: 'pe.xfg', status: 'candidate' }),
        expect.objectContaining({ id: 'stack.canary', status: 'present' }),
        expect.objectContaining({ id: 'section.no-wx', status: 'missing' }),
      ])
    )
    expect(inventory.section_risks).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'section.write-execute' })])
    )
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'section.write-execute' })])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_loader_invocation: true,
        no_exploit_test: true,
        no_external_tool: true,
        no_network: true,
      })
    )
  })

  test('summarizes ELF RELRO BIND_NOW PIE NX canary fortify and CET hints', () => {
    const inventory = buildBinaryHardeningInventoryFromBuffer(
      elfHardeningFixture([
        '__stack_chk_fail',
        '__memcpy_chk',
        'GNU_PROPERTY_X86_FEATURE_1_IBT',
        'GNU_PROPERTY_X86_FEATURE_1_SHSTK',
      ]),
      { filename: 'libhardened.so', sampleId: 'sha256:elf' }
    )

    expect(inventory.format).toBe('elf-hardening-profile')
    expect(inventory.container.features).toEqual(
      expect.objectContaining({
        relro_present: true,
        bind_now_candidate: true,
        pie_candidate: true,
        gnu_stack_executable: false,
      })
    )
    expect(inventory.mitigations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'elf.relro', status: 'present' }),
        expect.objectContaining({ id: 'elf.bind-now', status: 'present' }),
        expect.objectContaining({ id: 'elf.pie', status: 'present' }),
        expect.objectContaining({ id: 'elf.nx-stack', status: 'present' }),
        expect.objectContaining({ id: 'stack.canary', status: 'present' }),
        expect.objectContaining({ id: 'fortify', status: 'present' }),
        expect.objectContaining({ id: 'cet.ibt', status: 'candidate' }),
        expect.objectContaining({ id: 'cet.shstk', status: 'candidate' }),
      ])
    )
    expect(inventory.hardware_features).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'cet.ibt', candidate_only: true }),
        expect.objectContaining({ id: 'cet.shstk', candidate_only: true }),
      ])
    )
  })

  test('summarizes Mach-O PIE no-heap-exec PAC BTI MTE and CHERI hints', () => {
    const inventory = buildBinaryHardeningInventoryFromBuffer(
      machoFixture(['PACIASP', 'BTI', 'memtag', 'CHERI purecap']),
      { filename: 'agent.arm64e', sampleId: 'sha256:macho' }
    )

    expect(inventory.format).toBe('macho-hardening-profile')
    expect(inventory.container.arch).toBe('arm64e')
    expect(inventory.mitigations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'macho.pie', status: 'present' }),
        expect.objectContaining({ id: 'macho.no-heap-exec', status: 'present' }),
        expect.objectContaining({ id: 'aarch64.pac', status: 'candidate' }),
        expect.objectContaining({ id: 'aarch64.bti', status: 'candidate' }),
        expect.objectContaining({ id: 'aarch64.mte', status: 'candidate' }),
        expect.objectContaining({ id: 'cheri.purecap', status: 'candidate' }),
      ])
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        sample_executed_by_tool: false,
        loader_invoked_by_tool: false,
        exploit_test_performed_by_tool: false,
        network_used_by_tool: false,
      })
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createBinaryHardeningInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain(
      'resolvePrimarySamplePath dependency is unavailable'
    )
  })
})
