/**
 * btf.type.inventory - passive BPF Type Format inventory.
 *
 * This tool parses bounded raw BTF data and ELF .BTF/.BTF.ext sections. It
 * never loads BPF programs, invokes libbpf/bpftool, calls bpf(), or contacts
 * the kernel verifier.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'btf.type.inventory'
export const BTF_TYPE_INVENTORY_ARTIFACT_TYPE = 'btf_type_inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const BTF_MAGIC = 0xeb9f
const MAX_TYPES = 4096
const MAX_TYPE_PREVIEW = 96
const MAX_STRINGS = 120
const MAX_EXT_GROUPS = 80

const BTF_EVIDENCE = ['structure', 'types', 'metadata', 'relocations', 'workflow', 'provenance']
const BTF_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'ebpf.bytecode.inventory',
  'native.object.inventory',
  'linux.binary.inventory',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]
const BTF_RUNTIME_FOLLOW_UP_TOOLS = ['linux.runtime.plan', 'tool.readiness']
const BTF_SAFETY = [
  'passive',
  'no_execute',
  'no_bpf_syscall',
  'no_kernel_verifier_run',
  'no_program_load',
  'no_libbpf',
  'no_bpftool',
  'no_runtime_start',
  'no_network_by_default',
]

const BTF_KIND_NAMES: Record<number, string> = {
  0: 'UNKNOWN',
  1: 'INT',
  2: 'PTR',
  3: 'ARRAY',
  4: 'STRUCT',
  5: 'UNION',
  6: 'ENUM',
  7: 'FWD',
  8: 'TYPEDEF',
  9: 'VOLATILE',
  10: 'CONST',
  11: 'RESTRICT',
  12: 'FUNC',
  13: 'FUNC_PROTO',
  14: 'VAR',
  15: 'DATASEC',
  16: 'FLOAT',
  17: 'DECL_TAG',
  18: 'TYPE_TAG',
  19: 'ENUM64',
}

const CORE_RELO_KIND_NAMES: Record<number, string> = {
  0: 'FIELD_BYTE_OFFSET',
  1: 'FIELD_BYTE_SIZE',
  2: 'FIELD_EXISTS',
  3: 'FIELD_SIGNED',
  4: 'FIELD_LSHIFT_U64',
  5: 'FIELD_RSHIFT_U64',
  6: 'TYPE_ID_LOCAL',
  7: 'TYPE_ID_TARGET',
  8: 'TYPE_EXISTS',
  9: 'TYPE_SIZE',
  10: 'ENUMVAL_EXISTS',
  11: 'ENUMVAL_VALUE',
  12: 'TYPE_MATCHES',
}

type Endianness = 'little' | 'big'

interface ElfSection {
  name: string
  type: number
  flags: string[]
  offset: number
  size: number
}

interface BtfHeader {
  magic: number
  version: number
  flags: number
  hdr_len: number
  type_off: number
  type_len: number
  str_off: number
  str_len: number
  endian: Endianness
  valid_bounds: boolean
}

interface BtfTypePreview {
  id: number
  kind: string
  name: string
  size_or_type: number
  vlen: number
  kind_flag: boolean
  offset: number
}

const BtfPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_bpf_syscall: z.literal(true),
  no_kernel_verifier_run: z.literal(true),
  no_program_load: z.literal(true),
  no_libbpf: z.literal(true),
  no_bpftool: z.literal(true),
  no_runtime_start: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const BtfInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.string(), z.any()),
  btf: z.record(z.string(), z.any()),
  btf_ext: z.record(z.string(), z.any()),
  string_table: z.record(z.string(), z.any()),
  risk_flags: z.array(z.record(z.string(), z.any())),
  risk_summary: z.record(z.string(), z.any()),
  policy: BtfPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
})

export const BtfTypeInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive BTF inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist BTF inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const BtfTypeInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: BtfInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const btfTypeInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory BPF Type Format metadata and .BTF.ext CO-RE relocation records without invoking bpftool, libbpf, bpf(), the kernel verifier, or runtime loading.',
  inputSchema: BtfTypeInventoryInputSchema,
  outputSchema: BtfTypeInventoryOutputSchema,
  aspects: {
    formats: ['btf', 'btf-ext', 'btf-elf', 'bpf-btf', 'core-relocations'],
    platforms: ['linux'],
    architectures: ['ebpf'],
    execution: ['static', 'triage', 'correlation', 'workflow-plan'],
    safety: BTF_SAFETY,
    capabilities: [
      'btf-type-inventory',
      'type-layout-summary',
      'core-relocation-inventory',
      'kernel-type-metadata',
      'ebpf-portability-handoff',
      'workflow-routing',
    ],
    evidence: BTF_EVIDENCE,
  },
  artifacts: [
    {
      type: BTF_TYPE_INVENTORY_ARTIFACT_TYPE,
      description: 'Passive BTF type metadata, string table, and CO-RE relocation inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [BTF_TYPE_INVENTORY_ARTIFACT_TYPE] },
    { category: 'types', artifactTypes: [BTF_TYPE_INVENTORY_ARTIFACT_TYPE] },
    { category: 'metadata', artifactTypes: [BTF_TYPE_INVENTORY_ARTIFACT_TYPE] },
    { category: 'relocations', artifactTypes: [BTF_TYPE_INVENTORY_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [BTF_TYPE_INVENTORY_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'btf.type-core-inventory',
      title: 'Passive BTF type and CO-RE inventory',
      description:
        'Inventory BPF Type Format type records, string table evidence, .BTF.ext function/line metadata, and CO-RE relocation groups before routing to eBPF bytecode, native object, evidence graph, or opt-in Linux runtime planning.',
      startsWith: [TOOL_NAME],
      nextTools: [...BTF_FOLLOW_UP_TOOLS, ...BTF_RUNTIME_FOLLOW_UP_TOOLS],
      requiredArtifacts: ['sample'],
      producesArtifacts: [BTF_TYPE_INVENTORY_ARTIFACT_TYPE],
      evidence: BTF_EVIDENCE,
      safety: BTF_SAFETY,
      runtimeBackends: ['linux-runtime'],
    },
  ],
}

export type BtfInventory = z.infer<typeof BtfInventorySchema>

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (base.endsWith('.btf.ext')) return 'btf.ext'
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function isElf(data: Buffer): boolean {
  return (
    data.length >= 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46
  )
}

function readUInt16(data: Buffer, offset: number, endian: Endianness): number {
  return endian === 'big' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
}

function readUInt32(data: Buffer, offset: number, endian: Endianness): number {
  return endian === 'big' ? data.readUInt32BE(offset) : data.readUInt32LE(offset)
}

function readBigUInt(data: Buffer, offset: number, endian: Endianness): bigint {
  return endian === 'big' ? data.readBigUInt64BE(offset) : data.readBigUInt64LE(offset)
}

function safeReadUInt32(data: Buffer, offset: number, endian: Endianness): number | undefined {
  if (offset < 0 || offset + 4 > data.length) return undefined
  return readUInt32(data, offset, endian)
}

function readCString(data: Buffer, offset: number): string {
  if (offset < 0 || offset >= data.length) return ''
  const end = data.indexOf(0, offset)
  return data
    .subarray(offset, end === -1 ? data.length : end)
    .toString('utf8')
    .replace(/[^\x20-\x7e]/g, '')
    .slice(0, 200)
}

function sectionFlags(value: bigint): string[] {
  const flags: string[] = []
  if (value & 0x1n) flags.push('write')
  if (value & 0x2n) flags.push('alloc')
  if (value & 0x4n) flags.push('execinstr')
  return flags
}

function parseElfSections(data: Buffer): {
  header?: Record<string, unknown>
  sections: ElfSection[]
  endian: Endianness
} {
  if (!isElf(data) || data.length < 20) return { sections: [], endian: 'little' }
  const elfClass = data[4] === 1 ? 32 : data[4] === 2 ? 64 : 0
  const endian: Endianness = data[5] === 2 ? 'big' : 'little'
  if (!elfClass) return { sections: [], endian }

  const type = readUInt16(data, 16, endian)
  const machine = readUInt16(data, 18, endian)
  const shoff = Number(
    elfClass === 64 ? readBigUInt(data, 40, endian) : BigInt(readUInt32(data, 32, endian))
  )
  const shentsize = readUInt16(data, elfClass === 64 ? 58 : 46, endian)
  const shnum = readUInt16(data, elfClass === 64 ? 60 : 48, endian)
  const shstrndx = readUInt16(data, elfClass === 64 ? 62 : 50, endian)
  const header = {
    class: elfClass === 64 ? 'ELF64' : 'ELF32',
    type,
    machine,
    machine_name: machine === 247 ? 'EM_BPF' : `EM_${machine}`,
    section_count: shnum,
    section_header_offset: shoff,
  }

  if (!shoff || !shentsize || shnum <= 0 || shoff + shentsize * shnum > data.length) {
    return { header, sections: [], endian }
  }

  const rawSections: Array<Record<string, number | bigint>> = []
  for (let i = 0; i < shnum; i += 1) {
    const offset = shoff + i * shentsize
    if (elfClass === 64) {
      rawSections.push({
        nameOffset: readUInt32(data, offset, endian),
        type: readUInt32(data, offset + 4, endian),
        flags: readBigUInt(data, offset + 8, endian),
        offset: Number(readBigUInt(data, offset + 24, endian)),
        size: Number(readBigUInt(data, offset + 32, endian)),
      })
    } else {
      rawSections.push({
        nameOffset: readUInt32(data, offset, endian),
        type: readUInt32(data, offset + 4, endian),
        flags: BigInt(readUInt32(data, offset + 8, endian)),
        offset: readUInt32(data, offset + 16, endian),
        size: readUInt32(data, offset + 20, endian),
      })
    }
  }

  const shstr = rawSections[shstrndx]
  const shstrOffset = Number(shstr?.offset ?? 0)
  const shstrSize = Number(shstr?.size ?? 0)
  const table =
    shstrOffset >= 0 && shstrOffset + shstrSize <= data.length
      ? data.subarray(shstrOffset, shstrOffset + shstrSize)
      : Buffer.alloc(0)

  return {
    header,
    endian,
    sections: rawSections.map((section) => ({
      name: readCString(table, Number(section.nameOffset)),
      type: Number(section.type),
      flags: sectionFlags(BigInt(section.flags ?? 0)),
      offset: Number(section.offset),
      size: Number(section.size),
    })),
  }
}

function findSection(sections: ElfSection[], name: string): ElfSection | undefined {
  return sections.find((section) => section.name === name)
}

function sectionData(data: Buffer, section?: ElfSection): Buffer | undefined {
  if (!section) return undefined
  if (section.offset < 0 || section.size < 0 || section.offset + section.size > data.length) {
    return undefined
  }
  return data.subarray(section.offset, section.offset + section.size)
}

function detectRawBtfEndian(data: Buffer): Endianness | undefined {
  if (data.length < 24) return undefined
  if (data.readUInt16LE(0) === BTF_MAGIC) return 'little'
  if (data.readUInt16BE(0) === BTF_MAGIC) return 'big'
  return undefined
}

function parseBtfHeader(data: Buffer, endian: Endianness): BtfHeader | undefined {
  if (data.length < 24) return undefined
  const header = {
    magic: readUInt16(data, 0, endian),
    version: data[2],
    flags: data[3],
    hdr_len: readUInt32(data, 4, endian),
    type_off: readUInt32(data, 8, endian),
    type_len: readUInt32(data, 12, endian),
    str_off: readUInt32(data, 16, endian),
    str_len: readUInt32(data, 20, endian),
    endian,
    valid_bounds: false,
  }
  const typeStart = header.hdr_len + header.type_off
  const strStart = header.hdr_len + header.str_off
  header.valid_bounds =
    header.magic === BTF_MAGIC &&
    header.hdr_len >= 24 &&
    typeStart + header.type_len <= data.length &&
    strStart + header.str_len <= data.length
  return header
}

function getStringTable(data: Buffer, header?: BtfHeader): Buffer {
  if (!header?.valid_bounds) return Buffer.alloc(0)
  const start = header.hdr_len + header.str_off
  return data.subarray(start, start + header.str_len)
}

function btfName(strings: Buffer, offset: number): string {
  return readCString(strings, offset)
}

function extraBytesForKind(kind: number, vlen: number): number | undefined {
  if (kind === 1) return 4
  if (kind === 2) return 0
  if (kind === 3) return 12
  if (kind === 4 || kind === 5) return vlen * 12
  if (kind === 6) return vlen * 8
  if (kind === 7 || kind === 8 || kind === 9 || kind === 10 || kind === 11 || kind === 12) return 0
  if (kind === 13) return vlen * 8
  if (kind === 14) return 4
  if (kind === 15) return vlen * 12
  if (kind === 16) return 0
  if (kind === 17) return 4
  if (kind === 18) return 0
  if (kind === 19) return vlen * 12
  if (kind === 0) return 0
  return undefined
}

function parseBtfTypes(data: Buffer, header?: BtfHeader) {
  if (!header?.valid_bounds) {
    return {
      decode_status: 'missing-or-invalid',
      type_count: 0,
      kind_counts: {},
      named_type_preview: [],
      struct_preview: [],
      function_preview: [],
      datasec_preview: [],
      type_preview_truncated: false,
    }
  }

  const strings = getStringTable(data, header)
  const start = header.hdr_len + header.type_off
  const end = start + header.type_len
  const kindCounts: Record<string, number> = {}
  const namedTypePreview: BtfTypePreview[] = []
  const structPreview: Array<Record<string, unknown>> = []
  const functionPreview: Array<Record<string, unknown>> = []
  const datasecPreview: Array<Record<string, unknown>> = []
  let cursor = start
  let id = 1
  let decodeStatus = 'parsed'

  while (cursor + 12 <= end && id <= MAX_TYPES) {
    const nameOff = readUInt32(data, cursor, header.endian)
    const info = readUInt32(data, cursor + 4, header.endian)
    const sizeOrType = readUInt32(data, cursor + 8, header.endian)
    const vlen = info & 0xffff
    const kind = (info >>> 24) & 0x1f
    const kindFlag = Boolean(info & 0x80000000)
    const kindName = BTF_KIND_NAMES[kind] ?? `KIND_${kind}`
    const extraBytes = extraBytesForKind(kind, vlen)
    if (extraBytes === undefined || cursor + 12 + extraBytes > end) {
      decodeStatus = 'truncated'
      break
    }

    kindCounts[kindName] = (kindCounts[kindName] ?? 0) + 1
    const name = btfName(strings, nameOff)
    const preview = {
      id,
      kind: kindName,
      name,
      size_or_type: sizeOrType,
      vlen,
      kind_flag: kindFlag,
      offset: cursor - start,
    }
    if (name && namedTypePreview.length < MAX_TYPE_PREVIEW) namedTypePreview.push(preview)

    if ((kind === 4 || kind === 5) && structPreview.length < 32) {
      const members: Array<Record<string, unknown>> = []
      let memberCursor = cursor + 12
      for (let i = 0; i < vlen && i < 24; i += 1) {
        const memberNameOff = readUInt32(data, memberCursor, header.endian)
        const memberType = readUInt32(data, memberCursor + 4, header.endian)
        const memberOffset = readUInt32(data, memberCursor + 8, header.endian)
        members.push({
          name: btfName(strings, memberNameOff),
          type_id: memberType,
          bit_offset: kindFlag ? memberOffset & 0xffffff : memberOffset,
          bitfield_size: kindFlag ? memberOffset >>> 24 : 0,
        })
        memberCursor += 12
      }
      structPreview.push({ id, kind: kindName, name, size: sizeOrType, members, vlen })
    }

    if (kind === 12 && functionPreview.length < 64) {
      functionPreview.push({ id, name, linkage: sizeOrType, proto_type_id: sizeOrType })
    }

    if (kind === 15 && datasecPreview.length < 24) {
      datasecPreview.push({ id, name, size: sizeOrType, entries: vlen })
    }

    cursor += 12 + extraBytes
    id += 1
  }

  if (id > MAX_TYPES) decodeStatus = 'limit-hit'
  if (cursor < end && decodeStatus === 'parsed') decodeStatus = 'partial'

  return {
    decode_status: decodeStatus,
    type_count: id - 1,
    kind_counts: kindCounts,
    named_type_preview: namedTypePreview,
    struct_preview: structPreview,
    function_preview: functionPreview,
    datasec_preview: datasecPreview,
    type_preview_truncated: namedTypePreview.length >= MAX_TYPE_PREVIEW,
  }
}

function extractStrings(strings: Buffer): string[] {
  const result: string[] = []
  let start = 0
  for (let i = 0; i <= strings.length; i += 1) {
    if (i === strings.length || strings[i] === 0) {
      if (i > start) {
        const value = strings
          .subarray(start, i)
          .toString('utf8')
          .replace(/[^\x20-\x7e]/g, '')
          .slice(0, 200)
        if (value.length > 0) result.push(value)
      }
      start = i + 1
    }
    if (result.length >= MAX_STRINGS) break
  }
  return result
}

function parseBtfExtHeader(data: Buffer, endian: Endianness) {
  if (data.length < 32) return undefined
  const magic = readUInt16(data, 0, endian)
  const hdrLen = readUInt32(data, 4, endian)
  const header = {
    magic,
    version: data[2],
    flags: data[3],
    hdr_len: hdrLen,
    func_info_off: readUInt32(data, 8, endian),
    func_info_len: readUInt32(data, 12, endian),
    line_info_off: readUInt32(data, 16, endian),
    line_info_len: readUInt32(data, 20, endian),
    core_relo_off: readUInt32(data, 24, endian),
    core_relo_len: readUInt32(data, 28, endian),
    endian,
  }
  const boundsValid =
    magic === BTF_MAGIC &&
    hdrLen >= 32 &&
    hdrLen + header.func_info_off + header.func_info_len <= data.length &&
    hdrLen + header.line_info_off + header.line_info_len <= data.length &&
    hdrLen + header.core_relo_off + header.core_relo_len <= data.length
  return { ...header, valid_bounds: boundsValid }
}

function parseExtGroups(input: {
  data: Buffer
  header: ReturnType<typeof parseBtfExtHeader>
  off: number
  len: number
  strings: Buffer
  section: 'func_info' | 'line_info' | 'core_relo'
}) {
  if (!input.header?.valid_bounds || input.len === 0) {
    return { record_size: 0, group_count: 0, record_count: 0, groups: [] }
  }
  const start = input.header.hdr_len + input.off
  const end = start + input.len
  if (start + 4 > end || end > input.data.length) {
    return { record_size: 0, group_count: 0, record_count: 0, groups: [], truncated: true }
  }
  const recSize = readUInt32(input.data, start, input.header.endian)
  let cursor = start + 4
  const groups: Array<Record<string, unknown>> = []
  let recordCount = 0
  let truncated = false

  while (cursor + 8 <= end && groups.length < MAX_EXT_GROUPS) {
    const secNameOff = readUInt32(input.data, cursor, input.header.endian)
    const numInfo = readUInt32(input.data, cursor + 4, input.header.endian)
    cursor += 8
    const recordsStart = cursor
    const recordsEnd = cursor + numInfo * recSize
    if (recSize === 0 || recordsEnd > end) {
      truncated = true
      break
    }
    const group: Record<string, unknown> = {
      section: btfName(input.strings, secNameOff),
      section_name_off: secNameOff,
      record_count: numInfo,
    }
    recordCount += numInfo

    if (input.section === 'core_relo') {
      const kindCounts: Record<string, number> = {}
      const accessors: string[] = []
      let recCursor = recordsStart
      for (let i = 0; i < numInfo && i < 48; i += 1) {
        const accessOff = safeReadUInt32(input.data, recCursor + 8, input.header.endian) ?? 0
        const kind = safeReadUInt32(input.data, recCursor + 12, input.header.endian) ?? 0
        const kindName = CORE_RELO_KIND_NAMES[kind] ?? `CORE_RELO_${kind}`
        kindCounts[kindName] = (kindCounts[kindName] ?? 0) + 1
        const accessor = btfName(input.strings, accessOff)
        if (accessor) accessors.push(accessor)
        recCursor += recSize
      }
      group.kind_counts = kindCounts
      group.accessor_preview = Array.from(new Set(accessors)).slice(0, 16)
    }

    groups.push(group)
    cursor = recordsEnd
  }

  if (cursor < end && !truncated) truncated = true
  return {
    record_size: recSize,
    group_count: groups.length,
    record_count: recordCount,
    groups,
    truncated,
  }
}

function parseBtfExt(data: Buffer | undefined, strings: Buffer, endian: Endianness) {
  if (!data || data.length === 0) {
    return {
      present: false,
      decode_status: 'missing',
      func_info: { record_size: 0, group_count: 0, record_count: 0, groups: [] },
      line_info: { record_size: 0, group_count: 0, record_count: 0, groups: [] },
      core_relocations: { record_size: 0, group_count: 0, record_count: 0, groups: [] },
    }
  }
  const header = parseBtfExtHeader(data, endian)
  const decodeStatus = header?.valid_bounds ? 'parsed' : 'invalid-header'
  return {
    present: true,
    decode_status: decodeStatus,
    header,
    func_info: parseExtGroups({
      data,
      header,
      off: header?.func_info_off ?? 0,
      len: header?.func_info_len ?? 0,
      strings,
      section: 'func_info',
    }),
    line_info: parseExtGroups({
      data,
      header,
      off: header?.line_info_off ?? 0,
      len: header?.line_info_len ?? 0,
      strings,
      section: 'line_info',
    }),
    core_relocations: parseExtGroups({
      data,
      header,
      off: header?.core_relo_off ?? 0,
      len: header?.core_relo_len ?? 0,
      strings,
      section: 'core_relo',
    }),
  }
}

function detectContainer(data: Buffer, filename?: string) {
  const extension = extensionOf(filename)
  if (isElf(data)) {
    const elf = parseElfSections(data)
    const btfSection = findSection(elf.sections, '.BTF')
    const btfExtSection = findSection(elf.sections, '.BTF.ext')
    return {
      format: btfSection ? 'btf-elf' : 'elf',
      detectedBy: [
        'magic:elf',
        ...(btfSection ? ['section:.BTF'] : []),
        ...(btfExtSection ? ['section:.BTF.ext'] : []),
      ],
      confidence: btfSection ? 'high' : 'low',
      container: {
        kind: 'elf',
        elf_header: elf.header,
        btf_section: btfSection ?? null,
        btf_ext_section: btfExtSection ?? null,
      },
      btfData: sectionData(data, btfSection),
      btfExtData: sectionData(data, btfExtSection),
      endian: elf.endian,
    } as const
  }

  const endian = detectRawBtfEndian(data)
  if (endian) {
    const header = parseBtfHeader(data, endian)
    const extHeader = parseBtfExtHeader(data, endian)
    const looksLikeExt =
      extension === 'btf.ext' || Boolean(extHeader?.valid_bounds && !header?.valid_bounds)
    return {
      format: looksLikeExt ? 'btf-ext' : 'btf',
      detectedBy: [looksLikeExt ? 'magic:btf-ext' : 'magic:btf'],
      confidence: 'high',
      container: { kind: looksLikeExt ? 'raw-btf-ext' : 'raw-btf' },
      btfData: looksLikeExt ? undefined : data,
      btfExtData: looksLikeExt ? data : undefined,
      endian,
    } as const
  }

  if (extension === 'btf' || extension === 'btf.ext') {
    return {
      format: extension === 'btf.ext' ? 'btf-ext' : 'btf',
      detectedBy: ['extension'],
      confidence: 'medium',
      container: { kind: 'extension-fallback' },
      btfData: extension === 'btf' ? data : undefined,
      btfExtData: extension === 'btf.ext' ? data : undefined,
      endian: 'little' as Endianness,
    } as const
  }

  return {
    format: 'unknown',
    detectedBy: [],
    confidence: 'low',
    container: { kind: 'unknown' },
    btfData: undefined,
    btfExtData: undefined,
    endian: 'little' as Endianness,
  } as const
}

function buildRiskFlags(input: {
  format: string
  confidence: string
  header?: BtfHeader
  btfDecodeStatus: string
  btfExt: ReturnType<typeof parseBtfExt>
}) {
  const flags: Array<Record<string, unknown>> = []
  if (input.format === 'unknown') {
    flags.push({
      id: 'unknown-btf-format',
      severity: 'medium',
      category: 'format',
      evidence: 'No BTF magic, extension, or ELF .BTF section was detected.',
    })
  }
  if (input.confidence === 'medium') {
    flags.push({
      id: 'extension-only-unverified',
      severity: 'low',
      category: 'format',
      evidence: 'BTF classification relies on file extension fallback.',
    })
  }
  if (input.header && !input.header.valid_bounds) {
    flags.push({
      id: 'btf-bounds-invalid',
      severity: 'high',
      category: 'structure',
      evidence: 'BTF header offsets do not fit inside the preview.',
    })
  }
  if (input.btfDecodeStatus === 'truncated' || input.btfDecodeStatus === 'partial') {
    flags.push({
      id: 'btf-type-parser-partial',
      severity: 'medium',
      category: 'parser',
      evidence: `BTF type parser status is ${input.btfDecodeStatus}.`,
    })
  }
  if (input.btfExt.present && input.btfExt.decode_status !== 'parsed') {
    flags.push({
      id: 'btf-ext-invalid',
      severity: 'medium',
      category: 'structure',
      evidence: `BTF.ext parser status is ${input.btfExt.decode_status}.`,
    })
  }
  if ((input.btfExt.core_relocations?.record_count ?? 0) > 0) {
    flags.push({
      id: 'core-relocations-present',
      severity: 'info',
      category: 'portability',
      evidence: 'CO-RE relocation records are present and require target kernel BTF matching.',
    })
  }
  return flags
}

function riskLevel(flags: Array<Record<string, unknown>>) {
  if (flags.some((flag) => flag.severity === 'high')) return 'high'
  if (flags.some((flag) => flag.severity === 'medium')) return 'medium'
  if (flags.length > 0) return 'low'
  return 'none'
}

function buildEvidenceSummary(input: {
  sampleId?: string
  filename?: string
  format: string
  typeCount: number
  kindCounts: Record<string, number>
  coreRelocationCount: number
  riskFlags: Array<Record<string, unknown>>
}) {
  return {
    schema: 'rikune.btf_type_inventory.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: input.sampleId ?? null,
    filename: input.filename ?? null,
    artifact_type: BTF_TYPE_INVENTORY_ARTIFACT_TYPE,
    format: input.format,
    route_terms: ['btf', 'bpf-type-format', 'co-re', 'core-relocation', 'ebpf-portability'],
    evidence_categories: BTF_EVIDENCE,
    counts: {
      types: input.typeCount,
      kinds: Object.keys(input.kindCounts).length,
      core_relocations: input.coreRelocationCount,
      risk_flags: input.riskFlags.length,
    },
    static_only: true,
  }
}

function buildWorkflowHandoff(input: { sampleId?: string; format: string }) {
  return {
    schema: 'rikune.btf_type_inventory.workflow_handoff.v1',
    handoff_mode: 'btf_type_inventory_to_ebpf_portability_triage',
    source_tool: TOOL_NAME,
    sample_id: input.sampleId ?? null,
    artifact_type: BTF_TYPE_INVENTORY_ARTIFACT_TYPE,
    format: input.format,
    recommended_next_tools: [...BTF_FOLLOW_UP_TOOLS, ...BTF_RUNTIME_FOLLOW_UP_TOOLS],
    routing: [
      {
        goal: 'ebpf-bytecode-correlation',
        priority: 'high',
        next_tools: ['ebpf.bytecode.inventory', 'native.object.inventory'],
        required_evidence: [BTF_TYPE_INVENTORY_ARTIFACT_TYPE, '.BTF or .BTF.ext section'],
      },
      {
        goal: 'core-portability-review',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: ['core relocation groups', 'BTF type names'],
      },
      {
        goal: 'runtime-compatibility-planning',
        priority: 'conditional',
        next_tools: ['linux.runtime.plan', 'tool.readiness'],
        required_evidence: ['CO-RE relocation records'],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      bpf_syscall_invoked_by_tool: false,
      kernel_verifier_invoked_by_tool: false,
      program_loaded_by_tool: false,
      libbpf_invoked_by_tool: false,
      bpftool_invoked_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildQualityGates(input: {
  format: string
  btfDecodeStatus: string
  btfExtStatus: string
}) {
  return {
    schema: 'rikune.btf_type_inventory.quality_gates.v1',
    passive_static_inventory: true,
    format_detected: input.format !== 'unknown',
    btf_type_decode_status: input.btfDecodeStatus,
    btf_ext_decode_status: input.btfExtStatus,
    sample_executed_by_tool: false,
    bpf_syscall_invoked_by_tool: false,
    kernel_verifier_invoked_by_tool: false,
    program_loaded_by_tool: false,
    libbpf_invoked_by_tool: false,
    bpftool_invoked_by_tool: false,
    runtime_started_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
  }
}

export function buildBtfInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; sampleId?: string; size?: number } = {}
): BtfInventory {
  const detected = detectContainer(data, options.filename)
  const btfEndian = detected.btfData ? detectRawBtfEndian(detected.btfData) : detected.endian
  const btfHeader =
    detected.btfData && btfEndian ? parseBtfHeader(detected.btfData, btfEndian) : undefined
  const strings = detected.btfData ? getStringTable(detected.btfData, btfHeader) : Buffer.alloc(0)
  const types = parseBtfTypes(detected.btfData ?? Buffer.alloc(0), btfHeader)
  const stringValues = extractStrings(strings)
  const btfExt = parseBtfExt(detected.btfExtData, strings, btfHeader?.endian ?? detected.endian)
  const riskFlags = buildRiskFlags({
    format: detected.format,
    confidence: detected.confidence,
    header: btfHeader,
    btfDecodeStatus: types.decode_status,
    btfExt,
  })
  const coreRelocationCount = btfExt.core_relocations?.record_count ?? 0
  const recommendedNextTools = Array.from(
    new Set([
      ...BTF_FOLLOW_UP_TOOLS,
      ...(coreRelocationCount > 0 ? BTF_RUNTIME_FOLLOW_UP_TOOLS : []),
    ])
  )

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: [...detected.detectedBy],
    confidence: detected.confidence,
    size: options.size ?? data.length,
    preview_size: data.length,
    container: detected.container,
    btf: {
      present: Boolean(detected.btfData),
      header: btfHeader,
      ...types,
    },
    btf_ext: btfExt,
    string_table: {
      present: strings.length > 0,
      byte_length: strings.length,
      preview: stringValues,
      preview_truncated: stringValues.length >= MAX_STRINGS,
      type_names: stringValues
        .filter((value) => /^(struct|union|enum)\s+/.test(value))
        .slice(0, 32),
    },
    risk_flags: riskFlags,
    risk_summary: {
      risk_level: riskLevel(riskFlags),
      flags: riskFlags.map((flag) => flag.id),
      count: riskFlags.length,
    },
    policy: {
      passive: true,
      no_execute: true,
      no_bpf_syscall: true,
      no_kernel_verifier_run: true,
      no_program_load: true,
      no_libbpf: true,
      no_bpftool: true,
      no_runtime_start: true,
      no_network: true,
      no_mutation: true,
    },
    summary: `Passive BTF inventory detected ${detected.format} with ${types.type_count} type(s), ${coreRelocationCount} CO-RE relocation(s), risk=${riskLevel(riskFlags)}.`,
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review BTF kind counts and named type previews before correlating eBPF bytecode.',
      'Use ebpf.bytecode.inventory and native.object.inventory for object-level correlation.',
      'Use linux.runtime.plan only when runtime compatibility validation is explicitly approved.',
    ],
    evidence_summary: buildEvidenceSummary({
      sampleId: options.sampleId,
      filename: options.filename,
      format: detected.format,
      typeCount: types.type_count,
      kindCounts: types.kind_counts,
      coreRelocationCount,
      riskFlags,
    }),
    workflow_handoff: buildWorkflowHandoff({ sampleId: options.sampleId, format: detected.format }),
    quality_gates: buildQualityGates({
      format: detected.format,
      btfDecodeStatus: types.decode_status,
      btfExtStatus: btfExt.decode_status,
    }),
  }
}

async function readPreview(
  filePath: string,
  maxReadBytes: number
): Promise<{ data: Buffer; size: number }> {
  const stat = await fs.stat(filePath)
  const handle = await fs.open(filePath, 'r')
  try {
    const length = Math.min(stat.size, maxReadBytes)
    const data = Buffer.alloc(length)
    await handle.read(data, 0, length, 0)
    return { data, size: stat.size }
  } finally {
    await handle.close()
  }
}

export function createBtfTypeInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof BtfTypeInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = BtfTypeInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildBtfInventoryFromBuffer(data, {
        filename: path.basename(samplePath),
        sampleId: input.sample_id,
        size,
      })

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
        try {
          const artifact = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            BTF_TYPE_INVENTORY_ARTIFACT_TYPE,
            'btf',
            inventory,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: inventory can still be returned without persistence.
        }
      }

      return {
        ok: true,
        data: inventory,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${error instanceof Error ? error.message : String(error)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
