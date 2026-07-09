/**
 * native.debug.types.inventory — passive native debug type metadata inventory.
 *
 * This tool reads bounded bytes and summarizes DWARF, split-DWARF, and CTF
 * evidence. It does not invoke readelf, dwarfdump, pahole, libctf, debuggers,
 * symbol servers, source fetchers, or native loaders.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'native.debug.types.inventory'
export const NATIVE_DEBUG_TYPES_ARTIFACT_TYPE = 'native_debug_type_inventory'
const DEFAULT_MAX_READ_BYTES = 6 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_SECTIONS = 256
const MAX_UNITS = 96
const MAX_ABBREV_DECLS = 240
const MAX_STRINGS = 160
const MAX_RISK_FLAGS = 80

const NATIVE_DEBUG_TYPES_EVIDENCE = [
  'structure',
  'symbols',
  'debug-metadata',
  'types',
  'source-map',
  'source-paths',
  'workflow',
  'provenance',
]

const NATIVE_DEBUG_TYPES_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'native.object.inventory',
  'windows.debug.metadata.inspect',
  'elf.structure.analyze',
  'macho.structure.analyze',
  'strings.extract',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const NATIVE_DEBUG_TYPES_SAFETY = [
  'passive',
  'no_execute',
  'no_debugger',
  'no_native_load',
  'no_external_tool',
  'no_symbol_server_download',
  'no_source_fetch',
  'no_network_by_default',
  'no_mutation',
]

export const nativeDebugTypesInventoryAspects = {
  formats: [
    'dwarf',
    'dwarf-debug',
    'dwarf5',
    'split-dwarf',
    'dwo',
    'dwp',
    'ctf',
    'compact-ctf',
    'elf',
    'elf-object',
    'linux-kernel-module',
    'macho',
    'dsym',
    'debug-file',
    'debug-section',
    'debug-info',
    'debug-types',
    'gnu-debuglink',
    'build-id',
    'type-graph',
  ],
  platforms: ['linux', 'macos', 'ios', 'windows', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
  execution: ['static', 'triage', 'correlation', 'workflow-plan'],
  safety: NATIVE_DEBUG_TYPES_SAFETY,
  capabilities: [
    'dwarf-section-inventory',
    'dwarf-unit-summary',
    'split-dwarf-inventory',
    'ctf-type-metadata',
    'compile-unit-profile',
    'source-path-profile',
    'type-graph-seeds',
    'workflow-routing',
  ],
  evidence: NATIVE_DEBUG_TYPES_EVIDENCE,
}

const NativeDebugTypesPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_debugger: z.literal(true),
  no_native_load: z.literal(true),
  no_external_tool: z.literal(true),
  no_symbol_server_download: z.literal(true),
  no_source_fetch: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const NativeDebugTypesInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.string(), z.any()),
  debug_sections: z.record(z.string(), z.any()),
  dwarf: z.record(z.string(), z.any()),
  split_dwarf: z.record(z.string(), z.any()),
  ctf: z.record(z.string(), z.any()),
  source_profile: z.record(z.string(), z.any()),
  type_graph_seeds: z.record(z.string(), z.any()),
  risk_flags: z.array(z.record(z.string(), z.any())),
  risk_summary: z.record(z.string(), z.any()),
  symbol_server_plan: z.record(z.string(), z.any()),
  policy: NativeDebugTypesPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
})

export const NativeDebugTypesInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive DWARF/CTF metadata inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist native debug type inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const NativeDebugTypesInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: NativeDebugTypesInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const nativeDebugTypesInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory DWARF, split-DWARF, and CTF native debug type metadata without debuggers, external dumpers, symbol servers, source fetch, or native loading.',
  inputSchema: NativeDebugTypesInventoryInputSchema,
  outputSchema: NativeDebugTypesInventoryOutputSchema,
  aspects: nativeDebugTypesInventoryAspects,
  artifacts: [
    {
      type: NATIVE_DEBUG_TYPES_ARTIFACT_TYPE,
      description:
        'Passive DWARF/split-DWARF/CTF section, compile-unit, source path, and type-graph seed inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE] },
    { category: 'debug-metadata', artifactTypes: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE] },
    { category: 'types', artifactTypes: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE] },
    { category: 'source-map', artifactTypes: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE] },
    { category: 'source-paths', artifactTypes: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'native.debug-types-static-inventory',
      title: 'Passive native debug type inventory',
      description:
        'Inventory DWARF, split-DWARF, and CTF debug metadata sections, compile units, source-path evidence, and type-graph seeds before routing to native object, structure, symbol, evidence graph, and report tools.',
      startsWith: [TOOL_NAME],
      nextTools: NATIVE_DEBUG_TYPES_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [NATIVE_DEBUG_TYPES_ARTIFACT_TYPE],
      evidence: NATIVE_DEBUG_TYPES_EVIDENCE,
      safety: NATIVE_DEBUG_TYPES_SAFETY,
    },
  ],
}

export type NativeDebugTypesInventory = z.infer<typeof NativeDebugTypesInventorySchema>

type Endian = 'le' | 'be'

interface ElfSection {
  name: string
  type: number
  flags: number
  offset: number
  size: number
  link: number
  entsize: number
}

interface ElfSummary {
  valid: boolean
  class?: 'ELF32' | 'ELF64'
  endian?: Endian
  machine?: string
  type?: number
  section_count?: number
  sections: ElfSection[]
  truncated?: boolean
  reason?: string
}

interface DwarfUnitSummary {
  offset: number
  length: number
  dwarf64: boolean
  version: number
  unit_type?: string
  address_size?: number
  abbrev_offset?: number
  header_size: number
  truncated: boolean
}

interface AbbrevSummary {
  offset: number
  code: number
  tag: string
  has_children: boolean
  attribute_count: number
  forms: string[]
}

interface CtfSummary {
  present: boolean
  format?: string
  offset?: number
  size?: number
  endian?: Endian
  version?: number
  flags?: number
  compressed?: boolean
  archive?: Record<string, unknown>
  dictionary?: Record<string, unknown>
  notes: string[]
}

const ELF_MACHINES: Record<number, string> = {
  3: 'x86',
  8: 'mips',
  20: 'ppc',
  40: 'arm',
  62: 'x64',
  183: 'arm64',
  243: 'riscv',
  247: 'ebpf',
}

const DWARF_UNIT_TYPES: Record<number, string> = {
  0x01: 'DW_UT_compile',
  0x02: 'DW_UT_type',
  0x03: 'DW_UT_partial',
  0x04: 'DW_UT_skeleton',
  0x05: 'DW_UT_split_compile',
  0x06: 'DW_UT_split_type',
  0x80: 'DW_UT_lo_user',
  0xff: 'DW_UT_hi_user',
}

const DWARF_TAGS: Record<number, string> = {
  0x01: 'DW_TAG_array_type',
  0x02: 'DW_TAG_class_type',
  0x03: 'DW_TAG_entry_point',
  0x04: 'DW_TAG_enumeration_type',
  0x05: 'DW_TAG_formal_parameter',
  0x0b: 'DW_TAG_lexical_block',
  0x0d: 'DW_TAG_member',
  0x0f: 'DW_TAG_pointer_type',
  0x10: 'DW_TAG_reference_type',
  0x11: 'DW_TAG_compile_unit',
  0x13: 'DW_TAG_structure_type',
  0x15: 'DW_TAG_subroutine_type',
  0x16: 'DW_TAG_typedef',
  0x17: 'DW_TAG_union_type',
  0x18: 'DW_TAG_unspecified_parameters',
  0x19: 'DW_TAG_variant',
  0x1d: 'DW_TAG_inlined_subroutine',
  0x24: 'DW_TAG_base_type',
  0x26: 'DW_TAG_const_type',
  0x2e: 'DW_TAG_subprogram',
  0x2f: 'DW_TAG_template_type_parameter',
  0x30: 'DW_TAG_template_value_parameter',
  0x34: 'DW_TAG_variable',
  0x35: 'DW_TAG_volatile_type',
  0x39: 'DW_TAG_namespace',
  0x3b: 'DW_TAG_imported_module',
  0x3c: 'DW_TAG_unspecified_type',
  0x3f: 'DW_TAG_ptr_to_member_type',
  0x40: 'DW_TAG_set_type',
  0x41: 'DW_TAG_subrange_type',
  0x42: 'DW_TAG_with_stmt',
  0x43: 'DW_TAG_access_declaration',
  0x44: 'DW_TAG_base_interface',
  0x45: 'DW_TAG_catch_block',
  0x46: 'DW_TAG_const_type',
  0x47: 'DW_TAG_constant',
  0x48: 'DW_TAG_enumerator',
  0x49: 'DW_TAG_file_type',
  0x4a: 'DW_TAG_friend',
  0x4b: 'DW_TAG_namelist',
  0x4c: 'DW_TAG_namelist_item',
  0x4d: 'DW_TAG_packed_type',
  0x4e: 'DW_TAG_subrange_type',
  0x4f: 'DW_TAG_template_alias',
  0x4109: 'DW_TAG_GNU_template_parameter_pack',
}

const DWARF_FORMS: Record<number, string> = {
  0x01: 'DW_FORM_addr',
  0x03: 'DW_FORM_block2',
  0x04: 'DW_FORM_block4',
  0x05: 'DW_FORM_data2',
  0x06: 'DW_FORM_data4',
  0x07: 'DW_FORM_data8',
  0x08: 'DW_FORM_string',
  0x09: 'DW_FORM_block',
  0x0a: 'DW_FORM_block1',
  0x0b: 'DW_FORM_data1',
  0x0c: 'DW_FORM_flag',
  0x0d: 'DW_FORM_sdata',
  0x0e: 'DW_FORM_strp',
  0x0f: 'DW_FORM_udata',
  0x10: 'DW_FORM_ref_addr',
  0x11: 'DW_FORM_ref1',
  0x12: 'DW_FORM_ref2',
  0x13: 'DW_FORM_ref4',
  0x14: 'DW_FORM_ref8',
  0x15: 'DW_FORM_ref_udata',
  0x16: 'DW_FORM_indirect',
  0x17: 'DW_FORM_sec_offset',
  0x18: 'DW_FORM_exprloc',
  0x19: 'DW_FORM_flag_present',
  0x1a: 'DW_FORM_strx',
  0x1b: 'DW_FORM_addrx',
  0x1c: 'DW_FORM_ref_sup4',
  0x1d: 'DW_FORM_strp_sup',
  0x1e: 'DW_FORM_data16',
  0x1f: 'DW_FORM_line_strp',
  0x20: 'DW_FORM_ref_sig8',
  0x21: 'DW_FORM_implicit_const',
  0x22: 'DW_FORM_loclistx',
  0x23: 'DW_FORM_rnglistx',
  0x24: 'DW_FORM_ref_sup8',
  0x25: 'DW_FORM_strx1',
  0x26: 'DW_FORM_strx2',
  0x27: 'DW_FORM_strx3',
  0x28: 'DW_FORM_strx4',
  0x29: 'DW_FORM_addrx1',
  0x2a: 'DW_FORM_addrx2',
  0x2b: 'DW_FORM_addrx3',
  0x2c: 'DW_FORM_addrx4',
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (base.endsWith('.dSYM'.toLowerCase())) return 'dsym'
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function readUInt16(data: Buffer, offset: number, endian: Endian): number {
  return endian === 'be' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
}

function readUInt32(data: Buffer, offset: number, endian: Endian): number {
  return endian === 'be' ? data.readUInt32BE(offset) : data.readUInt32LE(offset)
}

function readU64Number(data: Buffer, offset: number, endian: Endian): number {
  const value = endian === 'be' ? data.readBigUInt64BE(offset) : data.readBigUInt64LE(offset)
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : Number.MAX_SAFE_INTEGER
}

function readUleb128(
  data: Buffer,
  offset: number,
  end = data.length
): { value: number; next: number } | null {
  let result = 0
  let shift = 0
  let cursor = offset
  while (cursor < end && shift < 63) {
    const byte = data[cursor++]
    result += (byte & 0x7f) * 2 ** shift
    if ((byte & 0x80) === 0) return { value: result, next: cursor }
    shift += 7
  }
  return null
}

function readSleb128(
  data: Buffer,
  offset: number,
  end = data.length
): { value: number; next: number } | null {
  let result = 0
  let shift = 0
  let cursor = offset
  let byte = 0
  while (cursor < end && shift < 63) {
    byte = data[cursor++]
    result += (byte & 0x7f) * 2 ** shift
    shift += 7
    if ((byte & 0x80) === 0) break
  }
  if ((byte & 0x80) !== 0) return null
  if (shift < 63 && (byte & 0x40) !== 0) {
    result -= 2 ** shift
  }
  return { value: result, next: cursor }
}

function readCString(data: Buffer, offset: number, end = data.length): string | null {
  if (offset < 0 || offset >= end) return null
  const nul = data.indexOf(0, offset)
  const stop = nul >= 0 && nul < end ? nul : end
  const value = data.subarray(offset, stop).toString('utf8').trim()
  return value.length > 0 ? value : null
}

function safeSlice(data: Buffer, offset: number, size: number): Buffer {
  if (offset < 0 || size <= 0 || offset >= data.length) return Buffer.alloc(0)
  return data.subarray(offset, Math.min(data.length, offset + size))
}

function parseElfSections(data: Buffer): ElfSummary {
  if (data.length < 16 || data.subarray(0, 4).toString('binary') !== '\x7fELF') {
    return { valid: false, sections: [], reason: 'missing ELF magic' }
  }
  const elfClass = data[4] === 2 ? 'ELF64' : data[4] === 1 ? 'ELF32' : undefined
  const endian: Endian = data[5] === 2 ? 'be' : 'le'
  if (!elfClass || data.length < (elfClass === 'ELF64' ? 64 : 52)) {
    return { valid: false, class: elfClass, endian, sections: [], reason: 'truncated ELF header' }
  }

  const type = readUInt16(data, 16, endian)
  const machineValue = readUInt16(data, 18, endian)
  const shoff =
    elfClass === 'ELF64' ? readU64Number(data, 40, endian) : readUInt32(data, 32, endian)
  const shentsize = readUInt16(data, elfClass === 'ELF64' ? 58 : 46, endian)
  const shnum = readUInt16(data, elfClass === 'ELF64' ? 60 : 48, endian)
  const shstrndx = readUInt16(data, elfClass === 'ELF64' ? 62 : 50, endian)
  const sections: ElfSection[] = []
  if (!shoff || !shentsize || shnum === 0 || shoff >= data.length) {
    return {
      valid: true,
      class: elfClass,
      endian,
      type,
      machine: ELF_MACHINES[machineValue] ?? `elf-machine-${machineValue}`,
      section_count: shnum,
      sections,
      truncated: true,
    }
  }

  const shstrHeaderOffset = shoff + shstrndx * shentsize
  let shstr: Buffer = Buffer.alloc(0)
  if (shstrHeaderOffset + shentsize <= data.length) {
    const nameOffset = elfClass === 'ELF64' ? shstrHeaderOffset + 24 : shstrHeaderOffset + 16
    const sizeOffset = elfClass === 'ELF64' ? shstrHeaderOffset + 32 : shstrHeaderOffset + 20
    const off =
      elfClass === 'ELF64'
        ? readU64Number(data, nameOffset, endian)
        : readUInt32(data, nameOffset, endian)
    const size =
      elfClass === 'ELF64'
        ? readU64Number(data, sizeOffset, endian)
        : readUInt32(data, sizeOffset, endian)
    shstr = safeSlice(data, off, size)
  }

  const limit = Math.min(shnum, MAX_SECTIONS)
  let truncated = false
  for (let index = 0; index < limit; index += 1) {
    const offset = shoff + index * shentsize
    if (offset + shentsize > data.length) {
      truncated = true
      break
    }
    const nameIndex = readUInt32(data, offset, endian)
    const name = readCString(shstr, nameIndex, shstr.length) ?? `section_${index}`
    const sectionType = readUInt32(data, offset + 4, endian)
    const flags =
      elfClass === 'ELF64'
        ? readU64Number(data, offset + 8, endian)
        : readUInt32(data, offset + 8, endian)
    const sectionOffset =
      elfClass === 'ELF64'
        ? readU64Number(data, offset + 24, endian)
        : readUInt32(data, offset + 16, endian)
    const size =
      elfClass === 'ELF64'
        ? readU64Number(data, offset + 32, endian)
        : readUInt32(data, offset + 20, endian)
    const link = readUInt32(data, elfClass === 'ELF64' ? offset + 40 : offset + 24, endian)
    const entsize =
      elfClass === 'ELF64'
        ? readU64Number(data, offset + 56, endian)
        : readUInt32(data, offset + 36, endian)
    sections.push({ name, type: sectionType, flags, offset: sectionOffset, size, link, entsize })
  }

  return {
    valid: true,
    class: elfClass,
    endian,
    type,
    machine: ELF_MACHINES[machineValue] ?? `elf-machine-${machineValue}`,
    section_count: shnum,
    sections,
    truncated: truncated || shnum > MAX_SECTIONS,
  }
}

function buildSectionInventory(data: Buffer, sections: ElfSection[]) {
  const debugSections = sections.filter((section) =>
    /^\.z?debug_|^\.ctf$|^\.BTF|^\.gnu_debuglink$|^\.note\.gnu\.build-id$/.test(section.name)
  )
  const byName: Record<string, Record<string, unknown>> = {}
  for (const section of debugSections) {
    const available =
      section.offset < data.length ? Math.min(section.size, data.length - section.offset) : 0
    byName[section.name] = {
      offset: section.offset,
      size: section.size,
      available,
      compressed_name_hint: section.name.startsWith('.zdebug_'),
      truncated: available < section.size,
    }
  }
  const names = debugSections.map((section) => section.name)
  return {
    count: debugSections.length,
    names,
    by_name: byName,
    dwarf_section_count: names.filter((name) => /^\.z?debug_/.test(name)).length,
    ctf_present: names.includes('.ctf'),
    debuglink_present: names.includes('.gnu_debuglink'),
    build_id_present: names.includes('.note.gnu.build-id'),
    compressed_section_count: names.filter((name) => name.startsWith('.zdebug_')).length,
    total_declared_bytes: debugSections.reduce((sum, section) => sum + section.size, 0),
  }
}

function sectionBuffer(data: Buffer, sections: ElfSection[], name: string): Buffer {
  const section = sections.find((candidate) => candidate.name === name)
  if (!section) return Buffer.alloc(0)
  return safeSlice(data, section.offset, section.size)
}

function parseDwarfInfoUnits(debugInfo: Buffer, endian: Endian): DwarfUnitSummary[] {
  const units: DwarfUnitSummary[] = []
  let offset = 0
  while (offset + 11 <= debugInfo.length && units.length < MAX_UNITS) {
    const unitOffset = offset
    let length = readUInt32(debugInfo, offset, endian)
    offset += 4
    let dwarf64 = false
    if (length === 0xffffffff) {
      if (offset + 8 > debugInfo.length) break
      length = readU64Number(debugInfo, offset, endian)
      offset += 8
      dwarf64 = true
    }
    if (length === 0 || length > debugInfo.length - offset) {
      units.push({
        offset: unitOffset,
        length,
        dwarf64,
        version: 0,
        header_size: offset - unitOffset,
        truncated: true,
      })
      break
    }
    const end = offset + length
    if (offset + 2 > end) break
    const version = readUInt16(debugInfo, offset, endian)
    offset += 2
    let unitType: string | undefined
    let addressSize: number | undefined
    let abbrevOffset: number | undefined
    if (version >= 5) {
      if (offset + 2 > end) break
      const rawUnitType = debugInfo[offset++]
      unitType = DWARF_UNIT_TYPES[rawUnitType] ?? `DW_UT_${rawUnitType}`
      addressSize = debugInfo[offset++]
      const abbrevBytes = dwarf64 ? 8 : 4
      if (offset + abbrevBytes > end) break
      abbrevOffset = dwarf64
        ? readU64Number(debugInfo, offset, endian)
        : readUInt32(debugInfo, offset, endian)
      offset += abbrevBytes
    } else {
      const abbrevBytes = dwarf64 ? 8 : 4
      if (offset + abbrevBytes + 1 > end) break
      abbrevOffset = dwarf64
        ? readU64Number(debugInfo, offset, endian)
        : readUInt32(debugInfo, offset, endian)
      offset += abbrevBytes
      addressSize = debugInfo[offset++]
      unitType = 'legacy_compile_unit'
    }
    units.push({
      offset: unitOffset,
      length,
      dwarf64,
      version,
      unit_type: unitType,
      address_size: addressSize,
      abbrev_offset: abbrevOffset,
      header_size: offset - unitOffset,
      truncated: false,
    })
    offset = end
  }
  return units
}

function parseDwarfAbbrev(debugAbbrev: Buffer): AbbrevSummary[] {
  const abbrevs: AbbrevSummary[] = []
  let offset = 0
  while (offset < debugAbbrev.length && abbrevs.length < MAX_ABBREV_DECLS) {
    const declarationOffset = offset
    const code = readUleb128(debugAbbrev, offset)
    if (!code) break
    offset = code.next
    if (code.value === 0) continue
    const tag = readUleb128(debugAbbrev, offset)
    if (!tag || tag.next >= debugAbbrev.length) break
    offset = tag.next
    const hasChildren = debugAbbrev[offset++] !== 0
    const forms: string[] = []
    let attributeCount = 0
    while (offset < debugAbbrev.length) {
      const attr = readUleb128(debugAbbrev, offset)
      if (!attr) return abbrevs
      offset = attr.next
      const form = readUleb128(debugAbbrev, offset)
      if (!form) return abbrevs
      offset = form.next
      if (attr.value === 0 && form.value === 0) break
      attributeCount += 1
      forms.push(DWARF_FORMS[form.value] ?? `DW_FORM_${form.value}`)
      if (form.value === 0x21) {
        const implicit = readSleb128(debugAbbrev, offset)
        if (!implicit) return abbrevs
        offset = implicit.next
      }
      if (attributeCount > 96) break
    }
    abbrevs.push({
      offset: declarationOffset,
      code: code.value,
      tag: DWARF_TAGS[tag.value] ?? `DW_TAG_${tag.value}`,
      has_children: hasChildren,
      attribute_count: attributeCount,
      forms: Array.from(new Set(forms)).slice(0, 24),
    })
  }
  return abbrevs
}

function extractNullStrings(data: Buffer, limit = MAX_STRINGS): string[] {
  const strings: string[] = []
  let start = 0
  for (let index = 0; index <= data.length && strings.length < limit; index += 1) {
    if (index !== data.length && data[index] !== 0) continue
    if (index > start) {
      const raw = data.subarray(start, index)
      if (raw.length >= 2 && raw.length <= 300) {
        const value = raw.toString('utf8').trim()
        if (/^[\t\r\n -~]+$/.test(value)) strings.push(value)
      }
    }
    start = index + 1
  }
  return Array.from(new Set(strings))
}

function classifySourceStrings(strings: string[]) {
  const sourcePaths = strings.filter((value) =>
    /(?:^|[\\/])[^\\/]+\.(?:c|cc|cpp|cxx|h|hpp|hh|rs|go|swift|m|mm|s|S|asm)$/i.test(value)
  )
  const compilers = strings.filter((value) =>
    /\b(?:gcc|clang|rustc|go version|swiftlang|MSVC|GNU C|GNU C\+\+|LLVM)\b/i.test(value)
  )
  const languages = new Set<string>()
  for (const value of strings) {
    if (/\brustc\b|\.rs\b|cargo[\\/]/i.test(value)) languages.add('Rust')
    if (/\bgo version\b|\.go\b/i.test(value)) languages.add('Go')
    if (/\bswiftlang\b|\.swift\b/i.test(value)) languages.add('Swift')
    if (/\bGNU C\+\+|clang version|\.cpp\b|\.cc\b|\.cxx\b/i.test(value)) languages.add('C++')
    if (/\bGNU C\b|\.c\b/i.test(value)) languages.add('C')
  }
  const sensitive = sourcePaths.filter((value) =>
    /(?:Users|home|jenkins|runner|workspace|buildkite|github|private|secret|token|key)/i.test(value)
  )
  return {
    total_strings: strings.length,
    source_path_count: sourcePaths.length,
    compiler_hint_count: compilers.length,
    languages: Array.from(languages),
    source_path_hints: sourcePaths.slice(0, 40),
    compiler_hints: compilers.slice(0, 24),
    possible_sensitive_path_count: sensitive.length,
    possible_sensitive_path_examples: sensitive.slice(0, 12),
  }
}

function parseDebugNames(data: Buffer, endian: Endian) {
  if (data.length < 16) return { present: false }
  const unitLength = readUInt32(data, 0, endian)
  const dwarf64 = unitLength === 0xffffffff
  const headerOffset = dwarf64 ? 12 : 4
  if (data.length < headerOffset + 16) return { present: true, truncated: true }
  const version = readUInt16(data, headerOffset, endian)
  const padding = readUInt16(data, headerOffset + 2, endian)
  const compUnitCount = readUInt32(data, headerOffset + 4, endian)
  const localTypeUnitCount = readUInt32(data, headerOffset + 8, endian)
  const foreignTypeUnitCount = readUInt32(data, headerOffset + 12, endian)
  const bucketCount =
    data.length >= headerOffset + 20 ? readUInt32(data, headerOffset + 16, endian) : 0
  const nameCount =
    data.length >= headerOffset + 24 ? readUInt32(data, headerOffset + 20, endian) : 0
  return {
    present: true,
    unit_length: unitLength,
    dwarf64,
    version,
    padding,
    comp_unit_count: compUnitCount,
    local_type_unit_count: localTypeUnitCount,
    foreign_type_unit_count: foreignTypeUnitCount,
    bucket_count: bucketCount,
    name_count: nameCount,
  }
}

function parseCtfSection(data: Buffer, sections: ElfSection[], wholeFile: Buffer): CtfSummary {
  const section = sections.find((candidate) => candidate.name === '.ctf')
  const candidates = section
    ? [{ offset: section.offset, size: section.size, source: '.ctf section' }]
    : [{ offset: 0, size: Math.min(wholeFile.length, data.length), source: 'raw preview' }]

  for (const candidate of candidates) {
    const ctf = safeSlice(wholeFile, candidate.offset, candidate.size)
    if (ctf.length >= 40) {
      const archiveMagic = ctf.readBigUInt64LE(0)
      if (archiveMagic === 0x8b47f2a4d7623eebn) {
        return {
          present: true,
          format: 'ctf-archive',
          offset: candidate.offset,
          size: candidate.size,
          endian: 'le',
          archive: {
            model: readU64Number(ctf, 8, 'le'),
            file_count: readU64Number(ctf, 16, 'le'),
            names_offset: readU64Number(ctf, 24, 'le'),
            ctfs_offset: readU64Number(ctf, 32, 'le'),
          },
          notes: [`detected from ${candidate.source}`],
        }
      }
    }
    if (ctf.length >= 48) {
      const magicLe = ctf.readUInt16LE(0)
      const magicBe = ctf.readUInt16BE(0)
      if (magicLe === 0xdff2 || magicBe === 0xdff2) {
        const endian: Endian = magicLe === 0xdff2 ? 'le' : 'be'
        const version = ctf[2]
        const flags = ctf[3]
        const offsets = {
          label_offset: readUInt32(ctf, 16, endian),
          object_offset: readUInt32(ctf, 20, endian),
          function_offset: readUInt32(ctf, 24, endian),
          type_offset: readUInt32(ctf, 36, endian),
          string_offset: readUInt32(ctf, 40, endian),
          string_length: readUInt32(ctf, 44, endian),
        }
        return {
          present: true,
          format: 'ctf-dictionary',
          offset: candidate.offset,
          size: candidate.size,
          endian,
          version,
          flags,
          compressed: Boolean(flags & 0x1),
          dictionary: offsets,
          notes: [`detected from ${candidate.source}`],
        }
      }
    }
  }
  return { present: false, notes: [] }
}

function detectFormat(
  filename: string | undefined,
  elf: ElfSummary,
  sections: ElfSection[],
  ctf: CtfSummary
) {
  const ext = extensionOf(filename)
  const sectionNames = sections.map((section) => section.name)
  const detectedBy: string[] = []
  if (elf.valid) detectedBy.push('ELF section table')
  if (sectionNames.some((name) => /^\.z?debug_/.test(name))) detectedBy.push('DWARF debug sections')
  if (sectionNames.includes('.debug_cu_index') || sectionNames.includes('.debug_tu_index')) {
    detectedBy.push('split DWARF index sections')
  }
  if (ctf.present) detectedBy.push('CTF magic/section')
  if (['dwo', 'dwp', 'debug'].includes(ext)) detectedBy.push('filename extension')
  if (ext === 'ctf') detectedBy.push('filename extension')

  let format = 'debug-metadata'
  if (ctf.present && !sectionNames.some((name) => /^\.z?debug_/.test(name))) format = 'ctf'
  else if (ext === 'dwp' || sectionNames.includes('.debug_cu_index')) format = 'split-dwarf-package'
  else if (ext === 'dwo') format = 'split-dwarf-object'
  else if (sectionNames.some((name) => /^\.z?debug_/.test(name))) format = 'dwarf'
  else if (elf.valid) format = 'elf-debug-carrier'
  const confidence =
    sectionNames.some((name) => /^\.z?debug_(?:info|abbrev|str|line|names)$/.test(name)) ||
    ctf.present
      ? 'high'
      : detectedBy.length > 0
        ? 'medium'
        : 'low'
  return {
    format,
    detectedBy: detectedBy.length > 0 ? detectedBy : ['bounded preview'],
    confidence,
  }
}

function buildRiskFlags(options: {
  truncated: boolean
  compressedSections: number
  sensitivePaths: number
  ctfCompressed: boolean
  splitDwarf: boolean
}) {
  const flags: Array<Record<string, unknown>> = []
  if (options.truncated) {
    flags.push({
      id: 'debug_metadata.preview_truncated',
      severity: 'info',
      description: 'Bounded preview did not include all declared debug metadata bytes.',
    })
  }
  if (options.compressedSections > 0) {
    flags.push({
      id: 'debug_metadata.compressed_sections_not_expanded',
      severity: 'info',
      description:
        'Compressed debug sections were inventoried by header only; no external decompressor was invoked.',
    })
  }
  if (options.ctfCompressed) {
    flags.push({
      id: 'ctf.dictionary_compressed_not_expanded',
      severity: 'info',
      description: 'CTF dictionary advertises compression; libctf/zlib was not invoked.',
    })
  }
  if (options.sensitivePaths > 0) {
    flags.push({
      id: 'debug_metadata.source_path_exposure',
      severity: 'medium',
      description: 'Source path strings may expose build hosts, users, or CI workspace names.',
      count: options.sensitivePaths,
    })
  }
  if (options.splitDwarf) {
    flags.push({
      id: 'split_dwarf.sidecar_required',
      severity: 'info',
      description:
        'Split DWARF metadata references sidecar/package debug objects for full type reconstruction.',
    })
  }
  return flags.slice(0, MAX_RISK_FLAGS)
}

function buildWorkflowHandoff(inventory: NativeDebugTypesInventory) {
  return {
    schema: 'rikune.native_debug_types.workflow_handoff.v1',
    artifact_contract: {
      artifact_type: NATIVE_DEBUG_TYPES_ARTIFACT_TYPE,
      primary_sections: inventory.debug_sections,
      unit_count: (inventory.dwarf.units as DwarfUnitSummary[] | undefined)?.length ?? 0,
      ctf_present: Boolean(inventory.ctf.present),
      split_dwarf_present: Boolean(inventory.split_dwarf.present),
      source_profile: inventory.source_profile,
    },
    dynamic_boundary: {
      sample_execution_allowed: false,
      debugger_allowed: false,
      native_load_allowed: false,
      external_tool_allowed: false,
      symbol_server_download_allowed: false,
      source_fetch_allowed: false,
      network_allowed: false,
      mutation_allowed: false,
      sample_executed_by_tool: false,
      debugger_started_by_tool: false,
      native_loaded_by_tool: false,
      external_tool_invoked_by_tool: false,
      symbol_server_contacted: false,
      source_fetched: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
    routing: [
      {
        goal: 'correlate debug metadata with object/container context',
        recommended_tools: [
          'native.object.inventory',
          'elf.structure.analyze',
          'macho.structure.analyze',
        ],
      },
      {
        goal: 'review source path and symbol metadata without fetching sources',
        recommended_tools: [
          'strings.extract',
          'windows.debug.metadata.inspect',
          'analysis.evidence.graph',
        ],
      },
      {
        goal: 'summarize passive type inventory',
        recommended_tools: ['report.generate', 'artifact.read'],
      },
    ],
  }
}

function buildSummary(inventory: Omit<NativeDebugTypesInventory, 'summary'>): string {
  const sectionCount = Number((inventory.debug_sections as any).count ?? 0)
  const unitCount = Array.isArray((inventory.dwarf as any).units)
    ? (inventory.dwarf as any).units.length
    : 0
  const ctf = (inventory.ctf as any).present ? 'CTF present' : 'CTF absent'
  const split = (inventory.split_dwarf as any).present
    ? 'split DWARF present'
    : 'split DWARF absent'
  return `${inventory.format}: ${sectionCount} debug sections, ${unitCount} DWARF unit headers, ${ctf}, ${split}.`
}

export function buildNativeDebugTypesInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; sampleId?: string; maxReadBytes?: number } = {}
): NativeDebugTypesInventory {
  const maxReadBytes = Math.max(
    1024,
    Math.min(options.maxReadBytes ?? DEFAULT_MAX_READ_BYTES, MAX_PREVIEW_BYTES)
  )
  const preview = data.subarray(0, Math.min(data.length, maxReadBytes))
  const elf = parseElfSections(preview)
  const sections = elf.sections
  const debugSections = buildSectionInventory(preview, sections)
  const ctf = parseCtfSection(preview, sections, preview)
  const detected = detectFormat(options.filename, elf, sections, ctf)
  const endian = elf.endian ?? 'le'
  const debugInfo = sectionBuffer(preview, sections, '.debug_info')
  const debugAbbrev = sectionBuffer(preview, sections, '.debug_abbrev')
  const debugStr = sectionBuffer(preview, sections, '.debug_str')
  const debugLineStr = sectionBuffer(preview, sections, '.debug_line_str')
  const debugNames = sectionBuffer(preview, sections, '.debug_names')
  const units = debugInfo.length > 0 ? parseDwarfInfoUnits(debugInfo, endian) : []
  const abbrevs = debugAbbrev.length > 0 ? parseDwarfAbbrev(debugAbbrev) : []
  const strings = Array.from(
    new Set([...extractNullStrings(debugStr), ...extractNullStrings(debugLineStr)])
  )
  const sourceProfile = classifySourceStrings(strings)
  const splitDwarfSections = [
    '.debug_cu_index',
    '.debug_tu_index',
    '.debug_addr',
    '.debug_str_offsets',
    '.debug_rnglists',
    '.debug_loclists',
  ].filter((name) => sections.some((section) => section.name === name))
  const typeTags = abbrevs
    .filter((abbrev) =>
      /type|class|structure|union|member|typedef|subprogram|namespace/.test(abbrev.tag)
    )
    .map((abbrev) => abbrev.tag)
  const riskFlags = buildRiskFlags({
    truncated:
      preview.length < data.length ||
      Boolean(
        (debugSections as any).by_name &&
        Object.values((debugSections as any).by_name).some((entry: any) => entry.truncated)
      ),
    compressedSections: Number((debugSections as any).compressed_section_count ?? 0),
    sensitivePaths: Number(sourceProfile.possible_sensitive_path_count ?? 0),
    ctfCompressed: Boolean(ctf.compressed),
    splitDwarf:
      splitDwarfSections.length > 0 ||
      units.some((unit) => /split|skeleton/i.test(unit.unit_type ?? '')),
  })
  const base = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: detected.detectedBy,
    confidence: detected.confidence as 'low' | 'medium' | 'high',
    size: data.length,
    preview_size: preview.length,
    container: {
      kind: elf.valid ? 'elf' : 'raw-debug-preview',
      elf: {
        valid: elf.valid,
        class: elf.class,
        endian: elf.endian,
        machine: elf.machine,
        type: elf.type,
        section_count: elf.section_count,
        truncated: elf.truncated,
      },
      bounded_preview: {
        bytes_read: preview.length,
        max_read_bytes: maxReadBytes,
        truncated: preview.length < data.length,
      },
    },
    debug_sections: debugSections,
    dwarf: {
      present: debugInfo.length > 0 || debugAbbrev.length > 0,
      units,
      unit_count: units.length,
      versions: Array.from(new Set(units.map((unit) => unit.version).filter(Boolean))),
      unit_types: Array.from(new Set(units.map((unit) => unit.unit_type).filter(Boolean))),
      abbrev_declarations: abbrevs.slice(0, MAX_ABBREV_DECLS),
      abbrev_tag_counts: abbrevs.reduce<Record<string, number>>((acc, abbrev) => {
        acc[abbrev.tag] = (acc[abbrev.tag] ?? 0) + 1
        return acc
      }, {}),
      debug_names: parseDebugNames(debugNames, endian),
    },
    split_dwarf: {
      present:
        splitDwarfSections.length > 0 ||
        units.some((unit) => /split|skeleton/i.test(unit.unit_type ?? '')),
      sections: splitDwarfSections,
      skeleton_unit_count: units.filter((unit) => /skeleton/i.test(unit.unit_type ?? '')).length,
      split_unit_count: units.filter((unit) => /split/i.test(unit.unit_type ?? '')).length,
      sidecar_hints: strings.filter((value) => /\.(?:dwo|dwp|debug)\b/i.test(value)).slice(0, 24),
    },
    ctf,
    source_profile: sourceProfile,
    type_graph_seeds: {
      root_tags: Array.from(new Set(abbrevs.slice(0, 40).map((abbrev) => abbrev.tag))),
      type_related_tags: Array.from(new Set(typeTags)).slice(0, 40),
      compile_unit_count: units.length,
      source_languages: sourceProfile.languages,
      has_namespace_or_class_tags: typeTags.some((tag) => /namespace|class|structure/.test(tag)),
      has_subprogram_tags: typeTags.some((tag) => /subprogram/.test(tag)),
    },
    risk_flags: riskFlags,
    risk_summary: {
      risk_count: riskFlags.length,
      has_sensitive_source_paths: sourceProfile.possible_sensitive_path_count > 0,
      has_compressed_unexpanded_debug_sections:
        Number((debugSections as any).compressed_section_count ?? 0) > 0 || Boolean(ctf.compressed),
      has_split_dwarf_sidecars: splitDwarfSections.length > 0,
    },
    symbol_server_plan: {
      status: 'plan_only',
      symbol_server_download_performed: false,
      source_fetch_performed: false,
      recommended_tools: [
        'windows.debug.metadata.inspect',
        'native.object.inventory',
        'artifact.read',
      ],
      notes: [
        'Use explicit opt-in symbol/source workflows outside this passive inventory if source retrieval is required.',
      ],
    },
    policy: {
      passive: true as const,
      no_execute: true as const,
      no_debugger: true as const,
      no_native_load: true as const,
      no_external_tool: true as const,
      no_symbol_server_download: true as const,
      no_source_fetch: true as const,
      no_network: true as const,
      no_mutation: true as const,
    },
    recommended_next_tools: [...NATIVE_DEBUG_TYPES_FOLLOW_UP_TOOLS],
    next_actions: [
      'Correlate compile-unit/source path hints with native.object.inventory and structure analysis.',
      'Use artifact.read to review bounded JSON details before requesting any source or symbol-server workflow.',
      'If richer type recovery is required, explicitly opt into an external dwarfdump/pahole/libctf workflow outside this tool.',
    ],
    evidence_summary: {
      schema: 'rikune.native_debug_types.evidence_summary.v1',
      source_tool: TOOL_NAME,
      artifact_type: NATIVE_DEBUG_TYPES_ARTIFACT_TYPE,
      categories: NATIVE_DEBUG_TYPES_EVIDENCE,
      key_counts: {
        debug_sections: (debugSections as any).count,
        dwarf_units: units.length,
        abbrev_declarations: abbrevs.length,
        source_paths: sourceProfile.source_path_count,
        ctf_present: ctf.present,
      },
    },
    workflow_handoff: {},
    quality_gates: {
      schema: 'rikune.native_debug_types.quality_gates.v1',
      passive_static_inventory: true,
      sample_executed_by_tool: false,
      debugger_started_by_tool: false,
      native_loaded_by_tool: false,
      external_tool_invoked_by_tool: false,
      symbol_server_contacted: false,
      source_fetched: false,
      network_used_by_tool: false,
      mutation_performed: false,
      bounded_preview: true,
      best_effort_parser: true,
    },
  } satisfies Omit<NativeDebugTypesInventory, 'summary'>

  const inventory: NativeDebugTypesInventory = {
    ...base,
    summary: buildSummary(base),
    workflow_handoff: {} as Record<string, unknown>,
  }
  inventory.workflow_handoff = buildWorkflowHandoff(inventory)
  return inventory
}

export function createNativeDebugTypesInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = NativeDebugTypesInventoryInputSchema.parse(args)
      const resolver = deps.resolvePrimarySamplePath
      if (!resolver) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is unavailable'] }
      }

      const resolved = await resolver(deps.workspaceManager, input.sample_id)
      const stat = await fs.stat(resolved.samplePath)
      const maxReadBytes = Math.min(input.max_read_bytes, MAX_PREVIEW_BYTES)
      const handle = await fs.open(resolved.samplePath, 'r')
      try {
        const buffer = Buffer.alloc(Math.min(stat.size, maxReadBytes))
        await handle.read(buffer, 0, buffer.length, 0)
        const inventory = buildNativeDebugTypesInventoryFromBuffer(buffer, {
          filename: path.basename(resolved.samplePath),
          sampleId: input.sample_id,
          maxReadBytes,
        })
        inventory.size = stat.size
        inventory.container = {
          ...inventory.container,
          bounded_preview: {
            ...(inventory.container as any).bounded_preview,
            bytes_read: buffer.length,
            max_read_bytes: maxReadBytes,
            truncated: stat.size > buffer.length,
          },
        }

        const artifacts: ArtifactRef[] = []
        if (input.persist_artifact !== false) {
          const persist = deps.persistStaticAnalysisJsonArtifact
          if (persist) {
            artifacts.push(
              await persist(
                deps.workspaceManager,
                deps.database,
                input.sample_id,
                NATIVE_DEBUG_TYPES_ARTIFACT_TYPE,
                'native-debug-types',
                inventory,
                input.session_tag ?? null
              )
            )
          }
        }

        return {
          ok: true,
          data: inventory,
          artifacts,
          metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
        }
      } finally {
        await handle.close()
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
