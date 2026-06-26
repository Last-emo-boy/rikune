import { describe, expect, test } from '@jest/globals'
import nativeDebugTypesPlugin from '../../src/plugins/native-debug-types/index.js'
import {
  NATIVE_DEBUG_TYPES_ARTIFACT_TYPE,
  buildNativeDebugTypesInventoryFromBuffer,
  createNativeDebugTypesInventoryHandler,
  nativeDebugTypesInventoryToolDefinition,
} from '../../src/plugins/native-debug-types/tools/native-debug-types-inventory.js'

function align(value: number, alignment = 8): number {
  return Math.ceil(value / alignment) * alignment
}

function ctfDictionaryFixture(compressed = false): Buffer {
  const data = Buffer.alloc(48)
  data.writeUInt16LE(0xdff2, 0)
  data[2] = 4
  data[3] = compressed ? 1 : 0
  data.writeUInt32LE(8, 16)
  data.writeUInt32LE(12, 20)
  data.writeUInt32LE(16, 24)
  data.writeUInt32LE(24, 36)
  data.writeUInt32LE(32, 40)
  data.writeUInt32LE(8, 44)
  return data
}

function dwarfInfoV5CompileUnit(): Buffer {
  const body = Buffer.from([0x05, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00])
  const header = Buffer.alloc(4)
  header.writeUInt32LE(body.length, 0)
  return Buffer.concat([header, body])
}

function dwarfAbbrevFixture(): Buffer {
  return Buffer.from([0x01, 0x11, 0x01, 0x03, 0x08, 0x13, 0x05, 0x25, 0x08, 0x00, 0x00, 0x00])
}

function debugNamesFixture(): Buffer {
  const data = Buffer.alloc(28)
  data.writeUInt32LE(24, 0)
  data.writeUInt16LE(5, 4)
  data.writeUInt32LE(1, 8)
  data.writeUInt32LE(0, 12)
  data.writeUInt32LE(0, 16)
  data.writeUInt32LE(1, 20)
  data.writeUInt32LE(2, 24)
  return data
}

function elf64WithSections(sections: Array<{ name: string; data: Buffer }>): Buffer {
  const nameOffsets = new Map<string, number>()
  let shstr = '\0'
  for (const section of [...sections.map((entry) => entry.name), '.shstrtab']) {
    nameOffsets.set(section, Buffer.byteLength(shstr))
    shstr += `${section}\0`
  }
  const shstrData = Buffer.from(shstr, 'utf8')

  let cursor = 64
  const placed = sections.map((section) => {
    cursor = align(cursor)
    const offset = cursor
    cursor += section.data.length
    return { ...section, offset }
  })
  cursor = align(cursor)
  const shstrOffset = cursor
  cursor += shstrData.length
  const shoff = align(cursor)
  const sectionCount = placed.length + 2
  const output = Buffer.alloc(shoff + sectionCount * 64)

  output.write('\x7fELF', 0, 'binary')
  output[4] = 2
  output[5] = 1
  output[6] = 1
  output.writeUInt16LE(1, 16)
  output.writeUInt16LE(62, 18)
  output.writeUInt32LE(1, 20)
  output.writeBigUInt64LE(BigInt(shoff), 40)
  output.writeUInt16LE(64, 52)
  output.writeUInt16LE(64, 58)
  output.writeUInt16LE(sectionCount, 60)
  output.writeUInt16LE(sectionCount - 1, 62)

  for (const section of placed) section.data.copy(output, section.offset)
  shstrData.copy(output, shstrOffset)

  function writeSectionHeader(
    index: number,
    name: string,
    type: number,
    offset: number,
    size: number
  ) {
    const base = shoff + index * 64
    output.writeUInt32LE(nameOffsets.get(name) ?? 0, base)
    output.writeUInt32LE(type, base + 4)
    output.writeBigUInt64LE(0n, base + 8)
    output.writeBigUInt64LE(0n, base + 16)
    output.writeBigUInt64LE(BigInt(offset), base + 24)
    output.writeBigUInt64LE(BigInt(size), base + 32)
    output.writeUInt32LE(0, base + 40)
    output.writeUInt32LE(0, base + 44)
    output.writeBigUInt64LE(1n, base + 48)
    output.writeBigUInt64LE(0n, base + 56)
  }

  placed.forEach((section, index) => {
    writeSectionHeader(index + 1, section.name, 1, section.offset, section.data.length)
  })
  writeSectionHeader(sectionCount - 1, '.shstrtab', 3, shstrOffset, shstrData.length)

  return output
}

function nativeDebugElfFixture(): Buffer {
  return elf64WithSections([
    { name: '.debug_info', data: dwarfInfoV5CompileUnit() },
    { name: '.debug_abbrev', data: dwarfAbbrevFixture() },
    {
      name: '.debug_str',
      data: Buffer.from(
        'src/main.c\0/home/user/project/src/lib.rs\0rustc 1.78\0clang version 18\0demo.dwo\0',
        'utf8'
      ),
    },
    { name: '.debug_line_str', data: Buffer.from('include/demo.h\0', 'utf8') },
    { name: '.debug_names', data: debugNamesFixture() },
    { name: '.debug_cu_index', data: Buffer.from([1, 0, 0, 0]) },
    { name: '.gnu_debuglink', data: Buffer.from('demo.debug\0', 'utf8') },
    { name: '.note.gnu.build-id', data: Buffer.from([1, 2, 3, 4]) },
    { name: '.ctf', data: ctfDictionaryFixture(true) },
  ])
}

describe('native-debug-types inventory', () => {
  test('declares passive DWARF and CTF inventory metadata', () => {
    expect(nativeDebugTypesPlugin.id).toBe('native-debug-types')
    expect(nativeDebugTypesPlugin.executionDomain).toBe('static')
    expect(nativeDebugTypesPlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['dwarf', 'dwo', 'dwp', 'ctf', 'debug-info', 'debug-types'])
    )
    expect(nativeDebugTypesInventoryToolDefinition.name).toBe('native.debug.types.inventory')
    expect(
      nativeDebugTypesInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toEqual(expect.arrayContaining([NATIVE_DEBUG_TYPES_ARTIFACT_TYPE]))
    const recipe = nativeDebugTypesInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'native.debug-types-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['native.debug.types.inventory'],
        producesArtifacts: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_external_tool',
          'no_symbol_server_download',
          'no_source_fetch',
        ]),
      })
    )
  })

  test('summarizes DWARF units, split DWARF sidecars, CTF, and source path hints', () => {
    const inventory = buildNativeDebugTypesInventoryFromBuffer(nativeDebugElfFixture(), {
      filename: 'demo.dwp',
    })

    expect(inventory.format).toBe('split-dwarf-package')
    expect(inventory.debug_sections).toEqual(
      expect.objectContaining({
        count: 9,
        ctf_present: true,
        debuglink_present: true,
        build_id_present: true,
      })
    )
    expect((inventory.debug_sections as any).names).toEqual(
      expect.arrayContaining(['.debug_info', '.debug_abbrev', '.debug_cu_index', '.ctf'])
    )
    expect((inventory.dwarf as any).units).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          version: 5,
          unit_type: 'DW_UT_compile',
          address_size: 8,
          abbrev_offset: 0,
        }),
      ])
    )
    expect((inventory.dwarf as any).abbrev_declarations).toEqual(
      expect.arrayContaining([expect.objectContaining({ tag: 'DW_TAG_compile_unit' })])
    )
    expect(inventory.split_dwarf).toEqual(
      expect.objectContaining({
        present: true,
        sections: expect.arrayContaining(['.debug_cu_index']),
        sidecar_hints: expect.arrayContaining(['demo.dwo']),
      })
    )
    expect(inventory.ctf).toEqual(
      expect.objectContaining({
        present: true,
        format: 'ctf-dictionary',
        compressed: true,
      })
    )
    expect((inventory.source_profile as any).languages).toEqual(
      expect.arrayContaining(['Rust', 'C++', 'C'])
    )
    expect((inventory.risk_flags as Array<Record<string, unknown>>).map((flag) => flag.id)).toEqual(
      expect.arrayContaining([
        'ctf.dictionary_compressed_not_expanded',
        'debug_metadata.source_path_exposure',
        'split_dwarf.sidecar_required',
      ])
    )
    expect((inventory.workflow_handoff as any).dynamic_boundary).toEqual(
      expect.objectContaining({
        external_tool_allowed: false,
        symbol_server_download_allowed: false,
        source_fetch_allowed: false,
        network_allowed: false,
      })
    )
    expect(inventory.symbol_server_plan).toEqual(
      expect.objectContaining({
        status: 'plan_only',
        symbol_server_download_performed: false,
        source_fetch_performed: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        external_tool_invoked_by_tool: false,
        network_used_by_tool: false,
      })
    )
  })

  test('detects raw CTF dictionaries without invoking libctf', () => {
    const inventory = buildNativeDebugTypesInventoryFromBuffer(ctfDictionaryFixture(), {
      filename: 'types.ctf',
    })

    expect(inventory.format).toBe('ctf')
    expect(inventory.ctf).toEqual(
      expect.objectContaining({
        present: true,
        format: 'ctf-dictionary',
        compressed: false,
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_external_tool: true,
        no_network: true,
      })
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createNativeDebugTypesInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
