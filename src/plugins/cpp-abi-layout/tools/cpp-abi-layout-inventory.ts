/**
 * cpp.abi.layout.inventory — passive C++ ABI class layout seed inventory.
 *
 * This tool reads bounded bytes and summarizes Itanium/MSVC C++ ABI evidence
 * such as vtables, RTTI/typeinfo names, EH personalities, and layout seeds. It
 * never executes, loads, links, debugs, demangles via external tools, contacts
 * symbol/source servers, or mutates samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'cpp.abi.layout.inventory'
export const CPP_ABI_LAYOUT_ARTIFACT_TYPE = 'cpp_abi_layout_inventory'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 6000
const MAX_EVIDENCE = 320
const MAX_HINTS = 160

const CPP_ABI_EVIDENCE = [
  'structure',
  'symbols',
  'rtti',
  'vtable',
  'classes',
  'exception-handling',
  'layout-seeds',
  'workflow',
  'provenance',
]

const CPP_ABI_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'native.object.inventory',
  'native.debug.types.inventory',
  'windows.debug.metadata.inspect',
  'pe.structure.analyze',
  'elf.structure.analyze',
  'macho.structure.analyze',
  'strings.extract',
  'code.xrefs.analyze',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const CPP_ABI_SAFETY = [
  'passive',
  'no_execute',
  'no_debugger',
  'no_native_load',
  'no_link',
  'no_external_demangler',
  'no_external_tool',
  'no_symbol_server_download',
  'no_source_fetch',
  'no_network_by_default',
  'no_mutation',
]

export const cppAbiLayoutInventoryAspects = {
  formats: [
    'cpp-abi',
    'cxx-abi',
    'itanium-abi',
    'msvc-abi',
    'rtti',
    'typeinfo',
    'vtable',
    'vftable',
    'vbtable',
    'class-layout',
    'virtual-dispatch',
    'exception-handling',
    'pe',
    'elf',
    'macho',
    'elf-object',
    'coff',
    'macho-object',
    'linux-kernel-module',
  ],
  platforms: ['linux', 'macos', 'ios', 'windows', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
  execution: ['static', 'triage', 'correlation', 'workflow-plan'],
  safety: CPP_ABI_SAFETY,
  capabilities: [
    'itanium-vtable-inventory',
    'itanium-rtti-inventory',
    'msvc-vftable-inventory',
    'msvc-rtti-inventory',
    'cxx-exception-profile',
    'class-layout-seeds',
    'virtual-dispatch-handoff',
    'workflow-routing',
  ],
  evidence: CPP_ABI_EVIDENCE,
  route_terms: [
    'c++ abi',
    'cpp abi',
    'cxx abi',
    'itanium abi',
    'msvc abi',
    'rtti',
    'typeinfo',
    'vtable',
    'vftable',
    'vbtable',
    'class layout',
    'virtual dispatch',
    'c++ exception',
    'eh typeinfo',
  ],
  search: [
    'C++ ABI layout',
    'RTTI inventory',
    'vtable and vftable discovery',
    'class hierarchy seed recovery',
  ],
}

const CppAbiPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_debugger: z.literal(true),
  no_native_load: z.literal(true),
  no_link: z.literal(true),
  no_external_demangler: z.literal(true),
  no_external_tool: z.literal(true),
  no_symbol_server_download: z.literal(true),
  no_source_fetch: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const CppAbiLayoutInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.string(), z.any()),
  abi_families: z.record(z.string(), z.any()),
  evidence: z.array(z.record(z.string(), z.any())),
  class_hints: z.array(z.record(z.string(), z.any())),
  vtable_hints: z.array(z.record(z.string(), z.any())),
  rtti_hints: z.array(z.record(z.string(), z.any())),
  exception_profile: z.record(z.string(), z.any()),
  layout_seeds: z.record(z.string(), z.any()),
  risk_flags: z.array(z.record(z.string(), z.any())),
  risk_summary: z.record(z.string(), z.any()),
  policy: CppAbiPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
})

export const CppAbiLayoutInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive C++ ABI layout inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist C++ ABI layout inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const CppAbiLayoutInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: CppAbiLayoutInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const cppAbiLayoutInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Itanium/MSVC C++ ABI layout evidence, including vtables, RTTI/typeinfo, EH personalities, and class-layout seeds without execution, native loading, debuggers, or external demanglers.',
  inputSchema: CppAbiLayoutInventoryInputSchema,
  outputSchema: CppAbiLayoutInventoryOutputSchema,
  aspects: cppAbiLayoutInventoryAspects,
  artifacts: [
    {
      type: CPP_ABI_LAYOUT_ARTIFACT_TYPE,
      description:
        'Passive C++ ABI vtable, RTTI/typeinfo, EH personality, virtual dispatch, and class-layout seed inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: CPP_ABI_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [CPP_ABI_LAYOUT_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'cpp.abi-layout-static-inventory',
      title: 'Passive C++ ABI layout inventory',
      description:
        'Inventory Itanium/MSVC C++ ABI vtable, RTTI/typeinfo, EH personality, and class-layout seed evidence before routing to native object, debug type, xref, evidence graph, and report tools.',
      startsWith: [TOOL_NAME],
      nextTools: CPP_ABI_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [CPP_ABI_LAYOUT_ARTIFACT_TYPE],
      evidence: CPP_ABI_EVIDENCE,
      safety: CPP_ABI_SAFETY,
    },
  ],
}

export type CppAbiLayoutInventory = z.infer<typeof CppAbiLayoutInventorySchema>

type AbiFamily = 'itanium' | 'msvc' | 'generic'
type Confidence = 'low' | 'medium' | 'high'
type Endian = 'le' | 'be'

interface BinaryString {
  value: string
  offset: number
}

interface BinarySection {
  name: string
  offset: number
  size: number
  virtual_address?: number
}

interface ContainerSummary {
  kind: string
  endian?: Endian
  sections: BinarySection[]
  bounded_preview: {
    bytes_read: number
    max_read_bytes: number
    truncated: boolean
  }
}

interface AbiEvidence {
  id: string
  abi: AbiFamily
  kind: string
  value: string
  offset: number
  section: string
  class_name?: string
  confidence: Confidence
  source: string
}

interface BuildOptions {
  filename?: string
  sampleId?: string
  maxReadBytes?: number
  size?: number
}

function clampMaxReadBytes(value?: number): number {
  return Math.max(1024, Math.min(value ?? DEFAULT_MAX_READ_BYTES, MAX_PREVIEW_BYTES))
}

function readUInt16(data: Buffer, offset: number, endian: Endian): number {
  return endian === 'le' ? data.readUInt16LE(offset) : data.readUInt16BE(offset)
}

function readUInt32(data: Buffer, offset: number, endian: Endian): number {
  return endian === 'le' ? data.readUInt32LE(offset) : data.readUInt32BE(offset)
}

function readUInt64Number(data: Buffer, offset: number, endian: Endian): number {
  const value = endian === 'le' ? data.readBigUInt64LE(offset) : data.readBigUInt64BE(offset)
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value)
}

function safeAscii(data: Buffer, offset: number, length: number): string {
  if (offset < 0 || length <= 0 || offset >= data.length) return ''
  return data
    .subarray(offset, Math.min(data.length, offset + length))
    .toString('ascii')
    .replace(/\0.*$/s, '')
    .trim()
}

function parseElfSections(data: Buffer): { sections: BinarySection[]; endian?: Endian } {
  if (
    data.length < 64 ||
    data[0] !== 0x7f ||
    data[1] !== 0x45 ||
    data[2] !== 0x4c ||
    data[3] !== 0x46
  ) {
    return { sections: [] }
  }
  const elfClass = data[4]
  const endian: Endian = data[5] === 2 ? 'be' : 'le'
  const is64 = elfClass === 2
  const shoff = is64 ? readUInt64Number(data, 40, endian) : readUInt32(data, 32, endian)
  const shentsize = readUInt16(data, is64 ? 58 : 46, endian)
  const shnum = readUInt16(data, is64 ? 60 : 48, endian)
  const shstrndx = readUInt16(data, is64 ? 62 : 50, endian)
  if (!shoff || !shentsize || !shnum || shnum > 4096) return { sections: [], endian }
  if (shoff + shnum * shentsize > data.length) return { sections: [], endian }

  const sectionHeaders = []
  for (let index = 0; index < shnum; index += 1) {
    const base = shoff + index * shentsize
    if (base + shentsize > data.length) break
    const nameOffset = readUInt32(data, base, endian)
    const offset = is64
      ? readUInt64Number(data, base + 24, endian)
      : readUInt32(data, base + 16, endian)
    const size = is64
      ? readUInt64Number(data, base + 32, endian)
      : readUInt32(data, base + 20, endian)
    const virtualAddress = is64
      ? readUInt64Number(data, base + 16, endian)
      : readUInt32(data, base + 12, endian)
    sectionHeaders.push({ nameOffset, offset, size, virtualAddress })
  }

  const shstr = sectionHeaders[shstrndx]
  const stringTable =
    shstr && shstr.offset + shstr.size <= data.length
      ? data.subarray(shstr.offset, shstr.offset + shstr.size)
      : Buffer.alloc(0)
  const sections: BinarySection[] = []
  for (const header of sectionHeaders) {
    if (!header.offset || !header.size || header.offset >= data.length) continue
    const name = readStringAt(stringTable, header.nameOffset, 128) || '<unnamed>'
    sections.push({
      name,
      offset: header.offset,
      size: Math.min(header.size, Math.max(0, data.length - header.offset)),
      virtual_address: header.virtualAddress,
    })
  }
  return { sections, endian }
}

function parsePeSections(data: Buffer): BinarySection[] {
  if (data.length < 0x100 || data.subarray(0, 2).toString('ascii') !== 'MZ') return []
  const peOffset = data.readUInt32LE(0x3c)
  if (peOffset <= 0 || peOffset + 24 > data.length) return []
  if (data.subarray(peOffset, peOffset + 4).toString('ascii') !== 'PE\0\0') return []
  const sectionCount = data.readUInt16LE(peOffset + 6)
  const optionalHeaderSize = data.readUInt16LE(peOffset + 20)
  const sectionTable = peOffset + 24 + optionalHeaderSize
  if (sectionCount > 256 || sectionTable + sectionCount * 40 > data.length) return []
  const sections: BinarySection[] = []
  for (let index = 0; index < sectionCount; index += 1) {
    const base = sectionTable + index * 40
    const name = safeAscii(data, base, 8) || `<section-${index}>`
    const virtualSize = data.readUInt32LE(base + 8)
    const virtualAddress = data.readUInt32LE(base + 12)
    const sizeOfRawData = data.readUInt32LE(base + 16)
    const pointerToRawData = data.readUInt32LE(base + 20)
    if (!pointerToRawData || pointerToRawData >= data.length) continue
    sections.push({
      name,
      offset: pointerToRawData,
      size: Math.min(sizeOfRawData || virtualSize, Math.max(0, data.length - pointerToRawData)),
      virtual_address: virtualAddress,
    })
  }
  return sections
}

function detectContainer(data: Buffer, maxReadBytes: number): ContainerSummary {
  let kind = 'raw-cpp-abi-preview'
  let endian: Endian | undefined
  let sections: BinarySection[] = []
  if (
    data.length >= 4 &&
    data[0] === 0x7f &&
    data[1] === 0x45 &&
    data[2] === 0x4c &&
    data[3] === 0x46
  ) {
    kind = 'elf'
    const parsed = parseElfSections(data)
    endian = parsed.endian
    sections = parsed.sections
  } else if (data.length >= 2 && data.subarray(0, 2).toString('ascii') === 'MZ') {
    kind = 'pe'
    sections = parsePeSections(data)
  } else if (data.length >= 4) {
    const magic = data.readUInt32LE(0)
    const fatMagic = data.readUInt32BE(0)
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic)) {
      kind = 'macho'
    } else if ([0xcafebabe, 0xcafebabf].includes(fatMagic)) {
      kind = 'macho-fat'
    } else if (data.subarray(0, 8).toString('ascii') === '!<arch>\n') {
      kind = 'ar-static-lib'
    }
  }
  return {
    kind,
    endian,
    sections,
    bounded_preview: {
      bytes_read: data.length,
      max_read_bytes: maxReadBytes,
      truncated: false,
    },
  }
}

function sectionNameForOffset(sections: BinarySection[], offset: number): string {
  const match = sections.find(
    (section) => offset >= section.offset && offset < section.offset + section.size
  )
  return match?.name ?? 'bounded-preview'
}

function isPrintableAscii(byte: number): boolean {
  return byte >= 0x20 && byte <= 0x7e
}

function extractBinaryStrings(data: Buffer): BinaryString[] {
  const strings: BinaryString[] = []
  let start = -1
  for (let index = 0; index <= data.length; index += 1) {
    const printable = index < data.length && isPrintableAscii(data[index])
    if (printable && start === -1) start = index
    if ((!printable || index === data.length) && start !== -1) {
      const length = index - start
      if (length >= 4) {
        strings.push({
          value: data.subarray(start, index).toString('latin1'),
          offset: start,
        })
        if (strings.length >= MAX_STRINGS) break
      }
      start = -1
    }
  }
  return strings
}

function readStringAt(data: Buffer, offset: number, maxLength = 256): string {
  if (offset < 0 || offset >= data.length) return ''
  let end = offset
  while (end < data.length && end - offset < maxLength && data[end] !== 0) end += 1
  return data.subarray(offset, end).toString('latin1')
}

function parseItaniumName(encoded: string): string | undefined {
  let cursor = 0
  if (encoded.startsWith('N')) cursor = 1
  const segments: string[] = []
  while (cursor < encoded.length && encoded[cursor] !== 'E') {
    if (encoded.startsWith('St', cursor)) {
      segments.push('std')
      cursor += 2
      continue
    }
    const digits = /^[0-9]+/.exec(encoded.slice(cursor))?.[0]
    if (!digits) break
    const length = Number(digits)
    cursor += digits.length
    if (!Number.isFinite(length) || length <= 0 || cursor + length > encoded.length) break
    segments.push(encoded.slice(cursor, cursor + length))
    cursor += length
    if (!encoded.startsWith('N') && segments.length >= 1) break
  }
  return segments.length ? segments.join('::') : undefined
}

function classNameFromItaniumSymbol(value: string): string | undefined {
  if (value.startsWith('vtable for ')) return value.slice('vtable for '.length).trim() || undefined
  if (value.startsWith('typeinfo for '))
    return value.slice('typeinfo for '.length).trim() || undefined
  const symbol = value.replace(/^.*?(_Z(?:TV|TI|TS|Th|Tv)[A-Za-z0-9_]+).*$/, '$1')
  if (!symbol.startsWith('_Z')) return undefined
  if (symbol.startsWith('_ZTV') || symbol.startsWith('_ZTI') || symbol.startsWith('_ZTS')) {
    return parseItaniumName(symbol.slice(4))
  }
  const nested = symbol.match(/N[0-9][A-Za-z0-9_]+.*E/)
  if (nested) return parseItaniumName(nested[0])
  return undefined
}

function decodeMsvcName(encoded: string): string | undefined {
  const clean = encoded
    .replace(/^\?A[VUW]/, '')
    .replace(/^\.?\?A[VUW]/, '')
    .replace(/@+$/g, '')
  const parts = clean.split('@').filter(Boolean)
  if (!parts.length) return undefined
  return parts.reverse().join('::')
}

function classNameFromMsvcSymbol(value: string): string | undefined {
  const vftable = /^\?\?_7([^@]+(?:@[^@]+)*)@@6B@?/.exec(value)
  if (vftable) return decodeMsvcName(vftable[1])
  const vbtable = /^\?\?_8([^@]+(?:@[^@]+)*)@@7B@?/.exec(value)
  if (vbtable) return decodeMsvcName(vbtable[1])
  const rtti0 = /^\?\?_R0\?A[VUW]([^@]+(?:@[^@]+)*)@@@8/.exec(value)
  if (rtti0) return decodeMsvcName(rtti0[1])
  const rttiOther = /^\?\?_R[1-4][^?]*\?A[VUW]([^@]+(?:@[^@]+)*)@@/.exec(value)
  if (rttiOther) return decodeMsvcName(rttiOther[1])
  const col = /^\?\?_R4([^@]+(?:@[^@]+)*)@@6B@?/.exec(value)
  if (col) return decodeMsvcName(col[1])
  const typeDescriptor = /\.?\?A[VUW]([^@]+(?:@[^@]+)*)@@/.exec(value)
  if (typeDescriptor) return decodeMsvcName(typeDescriptor[1])
  return undefined
}

function uniquePush<T>(items: T[], item: T, key: (value: T) => string): void {
  const itemKey = key(item)
  if (!items.some((existing) => key(existing) === itemKey)) items.push(item)
}

function confidenceForEvidence(kind: string): Confidence {
  if (/vtable|rtti|typeinfo|complete_object_locator|class_hierarchy/.test(kind)) return 'high'
  if (/personality|throw|pure_virtual|thunk|vbtable/.test(kind)) return 'medium'
  return 'low'
}

function addEvidence(
  evidence: AbiEvidence[],
  partial: Omit<AbiEvidence, 'id' | 'confidence'> & { confidence?: Confidence }
): void {
  if (evidence.length >= MAX_EVIDENCE) return
  const item: AbiEvidence = {
    ...partial,
    id: `abi-evidence-${evidence.length + 1}`,
    confidence: partial.confidence ?? confidenceForEvidence(partial.kind),
  }
  uniquePush(evidence, item, (value) => `${value.abi}:${value.kind}:${value.value}:${value.offset}`)
}

function collectAbiEvidence(strings: BinaryString[], sections: BinarySection[]): AbiEvidence[] {
  const evidence: AbiEvidence[] = []
  for (const entry of strings) {
    const value = entry.value
    const section = sectionNameForOffset(sections, entry.offset)
    const itaniumClass = classNameFromItaniumSymbol(value)
    if (/(?:^|[^A-Za-z0-9_])_ZTV[A-Za-z0-9_]/.test(value) || value.startsWith('vtable for ')) {
      addEvidence(evidence, {
        abi: 'itanium',
        kind: 'vtable',
        value,
        offset: entry.offset,
        section,
        class_name: itaniumClass,
        source: 'itanium_vtable_symbol',
      })
    }
    if (/(?:^|[^A-Za-z0-9_])_ZTI[A-Za-z0-9_]/.test(value) || value.startsWith('typeinfo for ')) {
      addEvidence(evidence, {
        abi: 'itanium',
        kind: 'typeinfo',
        value,
        offset: entry.offset,
        section,
        class_name: itaniumClass,
        source: 'itanium_typeinfo_symbol',
      })
    }
    if (/(?:^|[^A-Za-z0-9_])_ZTS[A-Za-z0-9_]/.test(value)) {
      addEvidence(evidence, {
        abi: 'itanium',
        kind: 'typeinfo_name',
        value,
        offset: entry.offset,
        section,
        class_name: itaniumClass,
        source: 'itanium_typeinfo_name_symbol',
      })
    }
    if (/(?:^|[^A-Za-z0-9_])_ZT[hv][A-Za-z0-9_]/.test(value)) {
      addEvidence(evidence, {
        abi: 'itanium',
        kind: 'adjustor_thunk',
        value,
        offset: entry.offset,
        section,
        class_name: itaniumClass,
        source: 'itanium_virtual_or_nonvirtual_thunk',
      })
    }
    if (value.includes('__cxxabiv1')) {
      addEvidence(evidence, {
        abi: 'itanium',
        kind: 'abi_namespace',
        value,
        offset: entry.offset,
        section,
        source: 'itanium_runtime_namespace',
        confidence: 'medium',
      })
    }
    if (
      ['__cxa_pure_virtual', '__cxa_throw', '__gxx_personality_v0'].some((needle) =>
        value.includes(needle)
      )
    ) {
      addEvidence(evidence, {
        abi: 'itanium',
        kind: value.includes('__gxx_personality')
          ? 'eh_personality'
          : value.includes('__cxa_throw')
            ? 'throw_helper'
            : 'pure_virtual',
        value,
        offset: entry.offset,
        section,
        class_name: itaniumClass,
        source: 'itanium_cxx_runtime_symbol',
      })
    }

    const msvcClass = classNameFromMsvcSymbol(value)
    if (/^\?\?_7/.test(value)) {
      addEvidence(evidence, {
        abi: 'msvc',
        kind: 'vftable',
        value,
        offset: entry.offset,
        section,
        class_name: msvcClass,
        source: 'msvc_vftable_symbol',
      })
    }
    if (/^\?\?_8/.test(value)) {
      addEvidence(evidence, {
        abi: 'msvc',
        kind: 'vbtable',
        value,
        offset: entry.offset,
        section,
        class_name: msvcClass,
        source: 'msvc_vbtable_symbol',
      })
    }
    if (/^\?\?_R0/.test(value) || /\.?\?A[VUW][^@]+@@/.test(value)) {
      addEvidence(evidence, {
        abi: 'msvc',
        kind: 'type_descriptor',
        value,
        offset: entry.offset,
        section,
        class_name: msvcClass,
        source: 'msvc_type_descriptor_symbol',
      })
    }
    if (/^\?\?_R4/.test(value) || /CompleteObjectLocator/i.test(value)) {
      addEvidence(evidence, {
        abi: 'msvc',
        kind: 'complete_object_locator',
        value,
        offset: entry.offset,
        section,
        class_name: msvcClass,
        source: 'msvc_complete_object_locator_hint',
      })
    }
    if (/^\?\?_R3/.test(value) || /ClassHierarchyDescriptor/i.test(value)) {
      addEvidence(evidence, {
        abi: 'msvc',
        kind: 'class_hierarchy_descriptor',
        value,
        offset: entry.offset,
        section,
        class_name: msvcClass,
        source: 'msvc_class_hierarchy_hint',
      })
    }
    if (
      [
        '__purecall',
        '__CxxFrameHandler3',
        '__CxxFrameHandler4',
        'CxxThrowException',
        '_CxxThrowException',
      ].some((needle) => value.includes(needle))
    ) {
      addEvidence(evidence, {
        abi: 'msvc',
        kind: value.includes('FrameHandler')
          ? 'eh_personality'
          : value.includes('ThrowException')
            ? 'throw_helper'
            : 'pure_virtual',
        value,
        offset: entry.offset,
        section,
        class_name: msvcClass,
        source: 'msvc_cxx_runtime_symbol',
      })
    }
    if (/\bRTTI\b|\bvftable\b|\bvbtable\b|\btype_info\b/i.test(value)) {
      addEvidence(evidence, {
        abi: 'generic',
        kind: 'cpp_abi_keyword',
        value,
        offset: entry.offset,
        section,
        source: 'cpp_abi_keyword_string',
        confidence: 'low',
      })
    }
  }
  return evidence.slice(0, MAX_EVIDENCE)
}

function buildClassHints(evidence: AbiEvidence[]): Array<Record<string, unknown>> {
  const classes = new Map<string, AbiEvidence[]>()
  for (const item of evidence) {
    if (!item.class_name) continue
    const key = `${item.abi}:${item.class_name}`
    const bucket = classes.get(key) ?? []
    bucket.push(item)
    classes.set(key, bucket)
  }
  return Array.from(classes.entries())
    .map(([key, items]) => {
      const [abi, ...classParts] = key.split(':')
      const kinds = Array.from(new Set(items.map((item) => item.kind)))
      const score =
        (kinds.some((kind) => /vtable|vftable/.test(kind)) ? 2 : 0) +
        (kinds.some((kind) =>
          /typeinfo|type_descriptor|complete_object_locator|class_hierarchy/.test(kind)
        )
          ? 2
          : 0) +
        (kinds.some((kind) => /thunk|vbtable/.test(kind)) ? 1 : 0)
      const confidence: Confidence = score >= 4 ? 'high' : score >= 2 ? 'medium' : 'low'
      return {
        abi,
        class_name: classParts.join(':'),
        confidence,
        evidence_ids: items.map((item) => item.id),
        evidence_kinds: kinds,
        vtable_evidence_count: items.filter((item) => /vtable|vftable/.test(item.kind)).length,
        rtti_evidence_count: items.filter((item) =>
          /typeinfo|type_descriptor|complete_object_locator|class_hierarchy/.test(item.kind)
        ).length,
        representative_section: items[0]?.section,
        candidate_only: true,
      }
    })
    .slice(0, MAX_HINTS)
}

function buildVtableHints(evidence: AbiEvidence[]): Array<Record<string, unknown>> {
  return evidence
    .filter((item) => /vtable|vftable|vbtable/.test(item.kind))
    .map((item) => ({
      abi: item.abi,
      kind: item.kind,
      class_name: item.class_name,
      symbol_or_string: item.value,
      offset: item.offset,
      section: item.section,
      confidence: item.confidence,
      evidence_id: item.id,
      candidate_only: true,
    }))
    .slice(0, MAX_HINTS)
}

function buildRttiHints(evidence: AbiEvidence[]): Array<Record<string, unknown>> {
  return evidence
    .filter((item) =>
      /typeinfo|type_descriptor|complete_object_locator|class_hierarchy/.test(item.kind)
    )
    .map((item) => ({
      abi: item.abi,
      kind: item.kind,
      class_name: item.class_name,
      symbol_or_string: item.value,
      offset: item.offset,
      section: item.section,
      confidence: item.confidence,
      evidence_id: item.id,
      candidate_only: true,
    }))
    .slice(0, MAX_HINTS)
}

function buildAbiFamilies(evidence: AbiEvidence[]): Record<string, unknown> {
  function family(abi: AbiFamily) {
    const items = evidence.filter((item) => item.abi === abi)
    const kinds = Array.from(new Set(items.map((item) => item.kind)))
    const classCount = new Set(items.map((item) => item.class_name).filter(Boolean)).size
    const highCount = items.filter((item) => item.confidence === 'high').length
    const confidence: Confidence =
      highCount >= 2 || (classCount > 0 && kinds.length >= 3)
        ? 'high'
        : items.length >= 2
          ? 'medium'
          : items.length
            ? 'low'
            : 'low'
    return {
      present: items.length > 0,
      confidence,
      evidence_count: items.length,
      evidence_kinds: kinds,
      candidate_class_count: classCount,
    }
  }
  return {
    itanium: family('itanium'),
    msvc: family('msvc'),
    generic: family('generic'),
  }
}

function buildExceptionProfile(
  evidence: AbiEvidence[],
  sections: BinarySection[]
): Record<string, unknown> {
  const names = sections.map((section) => section.name)
  return {
    itanium: {
      personality_present: evidence.some(
        (item) => item.abi === 'itanium' && item.kind === 'eh_personality'
      ),
      throw_helper_present: evidence.some(
        (item) => item.abi === 'itanium' && item.kind === 'throw_helper'
      ),
      gcc_except_table_present: names.includes('.gcc_except_table'),
      eh_frame_present: names.includes('.eh_frame') || names.includes('.eh_frame_hdr'),
    },
    msvc: {
      frame_handler_present: evidence.some(
        (item) => item.abi === 'msvc' && item.kind === 'eh_personality'
      ),
      throw_helper_present: evidence.some(
        (item) => item.abi === 'msvc' && item.kind === 'throw_helper'
      ),
      pdata_present: names.includes('.pdata'),
      xdata_present: names.includes('.xdata'),
    },
    evidence_ids: evidence
      .filter((item) => /eh_personality|throw_helper/.test(item.kind))
      .map((item) => item.id)
      .slice(0, 64),
  }
}

function buildLayoutSeeds(
  evidence: AbiEvidence[],
  classHints: Array<Record<string, unknown>>
): Record<string, unknown> {
  const itaniumThunkCount = evidence.filter(
    (item) => item.abi === 'itanium' && item.kind === 'adjustor_thunk'
  ).length
  const msvcVbtableCount = evidence.filter(
    (item) => item.abi === 'msvc' && item.kind === 'vbtable'
  ).length
  const vtableEvidence = evidence.filter((item) => /vtable|vftable/.test(item.kind))
  return {
    candidate_class_count: classHints.length,
    virtual_dispatch_present: vtableEvidence.length > 0,
    vtable_group_count: new Set(
      vtableEvidence.map((item) => `${item.abi}:${item.class_name ?? item.value}`)
    ).size,
    multiple_inheritance_indicators: {
      itanium_adjustor_thunk_count: itaniumThunkCount,
      msvc_vbtable_count: msvcVbtableCount,
      present: itaniumThunkCount > 0 || msvcVbtableCount > 0,
    },
    hierarchy_sources: Array.from(
      new Set(
        evidence
          .filter((item) => /class_hierarchy|complete_object_locator|typeinfo/.test(item.kind))
          .map((item) => item.source)
      )
    ),
    candidate_only: true,
    field_layout_recovered: false,
    notes: [
      'Layout seeds are ABI evidence for downstream analysis; this tool does not recover concrete field offsets.',
      'Use native.debug.types.inventory or backend-assisted decompilation for richer type layout recovery when explicitly requested.',
    ],
  }
}

function detectFormat(
  filename: string | undefined,
  container: ContainerSummary,
  evidence: AbiEvidence[]
): { format: string; detectedBy: string[]; confidence: Confidence } {
  const detectedBy = new Set<string>()
  if (container.kind !== 'raw-cpp-abi-preview') detectedBy.add(container.kind)
  if (evidence.some((item) => item.abi === 'itanium')) detectedBy.add('itanium-cxx-abi-evidence')
  if (evidence.some((item) => item.abi === 'msvc')) detectedBy.add('msvc-cxx-abi-evidence')
  if (filename && /\.(?:so|dylib|dll|exe|sys|o|obj|a|lib|ko)$/i.test(filename)) {
    detectedBy.add('native-binary-extension')
  }
  const highCount = evidence.filter((item) => item.confidence === 'high').length
  const confidence: Confidence =
    highCount >= 2 ? 'high' : evidence.length >= 2 ? 'medium' : evidence.length ? 'low' : 'low'
  const families = Array.from(
    new Set(evidence.map((item) => item.abi).filter((abi) => abi !== 'generic'))
  )
  const format =
    families.length === 2
      ? 'mixed-cpp-abi'
      : families[0] === 'itanium'
        ? 'itanium-cpp-abi'
        : families[0] === 'msvc'
          ? 'msvc-cpp-abi'
          : container.kind === 'raw-cpp-abi-preview'
            ? 'raw-cpp-abi-preview'
            : `${container.kind}-cpp-abi-preview`
  return {
    format,
    detectedBy: Array.from(detectedBy),
    confidence,
  }
}

function buildRiskFlags(
  data: Buffer,
  maxReadBytes: number,
  evidence: AbiEvidence[]
): Array<Record<string, unknown>> {
  const flags: Array<Record<string, unknown>> = []
  if (data.length >= maxReadBytes) {
    flags.push({
      id: 'bounded_preview.truncated',
      severity: 'info',
      message:
        'Input was scanned only up to max_read_bytes; additional ABI evidence may exist later.',
    })
  }
  if (evidence.length >= MAX_EVIDENCE) {
    flags.push({
      id: 'abi_evidence.limit_reached',
      severity: 'info',
      message: 'C++ ABI evidence output was capped to keep the artifact bounded.',
    })
  }
  if (evidence.length > 0) {
    flags.push({
      id: 'class_layout.candidate_only',
      severity: 'info',
      message:
        'Class/vtable/RTTI entries are static candidates and require downstream correlation.',
    })
  }
  return flags
}

function buildWorkflowHandoff(
  inventory: Omit<CppAbiLayoutInventory, 'workflow_handoff'>
): Record<string, unknown> {
  return {
    schema: 'rikune.cpp_abi_layout.workflow_handoff.v1',
    handoff_mode: 'cpp_abi_inventory_to_type_and_xref_analysis',
    artifact_contract: {
      consumes: ['sample'],
      produces: [CPP_ABI_LAYOUT_ARTIFACT_TYPE],
      mime: 'application/json',
      expected_consumers: CPP_ABI_FOLLOW_UP_TOOLS,
    },
    routing: [
      {
        goal: 'correlate ABI class seeds with debug type metadata',
        next_tools: ['native.debug.types.inventory', 'artifact.read'],
      },
      {
        goal: 'map vtable candidates to callsites and xrefs',
        next_tools: ['code.xrefs.analyze', 'analysis.evidence.graph'],
      },
      {
        goal: 'review native object symbols and section boundaries',
        next_tools: ['native.object.inventory', 'elf.structure.analyze', 'pe.structure.analyze'],
      },
      {
        goal: 'summarize C++ ABI layout evidence',
        next_tools: ['report.generate', 'artifact.read'],
      },
    ],
    dynamic_boundary: {
      activation_boundary: 'result-scoped',
      sample_execution_allowed: false,
      debugger_allowed: false,
      native_load_allowed: false,
      link_allowed: false,
      external_demangler_allowed: false,
      external_tool_allowed: false,
      symbol_server_download_allowed: false,
      source_fetch_allowed: false,
      network_allowed: false,
      mutation_allowed: false,
      sample_executed_by_tool: false,
      debugger_started_by_tool: false,
      native_loaded_by_tool: false,
      linked_by_tool: false,
      external_demangler_invoked_by_tool: false,
    },
    evidence_summary: inventory.evidence_summary,
  }
}

function buildSummary(
  inventory: Omit<CppAbiLayoutInventory, 'summary' | 'workflow_handoff'>
): string {
  const families = inventory.abi_families as any
  const present = ['itanium', 'msvc']
    .filter((family) => families[family]?.present)
    .map((family) => `${family}:${families[family]?.evidence_count ?? 0}`)
  const familySummary = present.length ? present.join(', ') : 'no ABI family evidence'
  return `${inventory.format}: ${familySummary}; ${inventory.class_hints.length} class candidates, ${inventory.vtable_hints.length} vtable candidates, ${inventory.rtti_hints.length} RTTI candidates.`
}

export function buildCppAbiLayoutInventoryFromBuffer(
  data: Buffer,
  options: BuildOptions = {}
): CppAbiLayoutInventory {
  const maxReadBytes = clampMaxReadBytes(options.maxReadBytes)
  const preview = data.subarray(0, Math.min(data.length, maxReadBytes))
  const container = detectContainer(preview, maxReadBytes)
  container.bounded_preview.truncated = (options.size ?? data.length) > preview.length
  const strings = extractBinaryStrings(preview)
  const evidence = collectAbiEvidence(strings, container.sections)
  const classHints = buildClassHints(evidence)
  const vtableHints = buildVtableHints(evidence)
  const rttiHints = buildRttiHints(evidence)
  const abiFamilies = buildAbiFamilies(evidence)
  const exceptionProfile = buildExceptionProfile(evidence, container.sections)
  const layoutSeeds = buildLayoutSeeds(evidence, classHints)
  const detected = detectFormat(options.filename, container, evidence)
  const riskFlags = buildRiskFlags(preview, maxReadBytes, evidence)
  const base = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: detected.detectedBy,
    confidence: detected.confidence,
    size: options.size ?? data.length,
    preview_size: preview.length,
    container,
    abi_families: abiFamilies,
    evidence,
    class_hints: classHints,
    vtable_hints: vtableHints,
    rtti_hints: rttiHints,
    exception_profile: exceptionProfile,
    layout_seeds: layoutSeeds,
    risk_flags: riskFlags,
    risk_summary: {
      risk_count: riskFlags.length,
      candidate_only: evidence.length > 0,
      bounded_preview_truncated: container.bounded_preview.truncated,
      evidence_limit_reached: evidence.length >= MAX_EVIDENCE,
    },
    policy: {
      passive: true as const,
      no_execute: true as const,
      no_debugger: true as const,
      no_native_load: true as const,
      no_link: true as const,
      no_external_demangler: true as const,
      no_external_tool: true as const,
      no_symbol_server_download: true as const,
      no_source_fetch: true as const,
      no_network: true as const,
      no_mutation: true as const,
    },
    recommended_next_tools: [...CPP_ABI_FOLLOW_UP_TOOLS],
    next_actions: [
      'Use artifact.read to inspect ABI evidence before launching any backend-assisted workflow.',
      'Correlate class/vtable seeds with native.debug.types.inventory, native.object.inventory, and code.xrefs.analyze.',
      'If concrete field layout is required, explicitly opt into a separate backend or debug-type workflow outside this passive inventory.',
    ],
    evidence_summary: {
      schema: 'rikune.cpp_abi_layout.evidence_summary.v1',
      source_tool: TOOL_NAME,
      sample_id: options.sampleId,
      artifact_type: CPP_ABI_LAYOUT_ARTIFACT_TYPE,
      categories: CPP_ABI_EVIDENCE,
      static_only: true,
      key_counts: {
        evidence: evidence.length,
        classes: classHints.length,
        vtables: vtableHints.length,
        rtti: rttiHints.length,
      },
    },
    quality_gates: {
      schema: 'rikune.cpp_abi_layout.quality_gates.v1',
      passive_static_inventory: true,
      bounded_preview_only: true,
      best_effort_parser: true,
      candidate_layout_only: true,
      field_layout_recovered: false,
      sample_executed_by_tool: false,
      debugger_started_by_tool: false,
      native_loaded_by_tool: false,
      linked_by_tool: false,
      external_demangler_invoked_by_tool: false,
      external_tool_invoked_by_tool: false,
      symbol_server_contacted: false,
      source_fetched: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
  } satisfies Omit<CppAbiLayoutInventory, 'summary' | 'workflow_handoff'>

  const inventory: CppAbiLayoutInventory = {
    ...base,
    summary: buildSummary(base),
    workflow_handoff: {},
  }
  inventory.workflow_handoff = buildWorkflowHandoff(inventory)
  return inventory
}

export function createCppAbiLayoutInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = CppAbiLayoutInventoryInputSchema.parse(args)
      const resolver = deps.resolvePrimarySamplePath
      if (!resolver) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is unavailable'] }
      }

      const resolved = await resolver(deps.workspaceManager, input.sample_id)
      const stat = await fs.stat(resolved.samplePath)
      const maxReadBytes = clampMaxReadBytes(input.max_read_bytes)
      const handle = await fs.open(resolved.samplePath, 'r')
      try {
        const buffer = Buffer.alloc(Math.min(stat.size, maxReadBytes))
        await handle.read(buffer, 0, buffer.length, 0)
        const inventory = buildCppAbiLayoutInventoryFromBuffer(buffer, {
          filename: path.basename(resolved.samplePath),
          sampleId: input.sample_id,
          maxReadBytes,
          size: stat.size,
        })

        const artifacts: ArtifactRef[] = []
        if (input.persist_artifact !== false) {
          const persist = deps.persistStaticAnalysisJsonArtifact
          if (persist) {
            artifacts.push(
              await persist(
                deps.workspaceManager,
                deps.database,
                input.sample_id,
                CPP_ABI_LAYOUT_ARTIFACT_TYPE,
                'cpp-abi-layout',
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
