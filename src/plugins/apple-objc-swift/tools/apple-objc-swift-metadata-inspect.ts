/**
 * apple.objc_swift.metadata.inspect - passive ObjC/Swift metadata inventory.
 *
 * This tool reads bounded bytes only. It does not run otool, nm, lipo,
 * class-dump, swift-demangle, codesign, LLDB, Frida, or any Apple runtime.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'apple.objc_swift.metadata.inspect'
export const APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE = 'apple_objc_swift_metadata_inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024
const MAX_LOAD_COMMANDS = 256
const MAX_SECTIONS = 512
const MAX_SYMBOLS = 800
const MAX_STRINGS = 1000
const MAX_HINTS = 240
const MAX_SECTION_STRING_BYTES = 512 * 1024

const MH_MAGIC = 0xfeedface
const MH_CIGAM = 0xcefaedfe
const MH_MAGIC_64 = 0xfeedfacf
const MH_CIGAM_64 = 0xcffaedfe
const FAT_MAGIC = 0xcafebabe
const FAT_CIGAM = 0xbebafeca
const FAT_MAGIC_64 = 0xcafebabf
const FAT_CIGAM_64 = 0xbfbafeca

const CPU_TYPES: Record<number, string> = {
  7: 'x86',
  12: 'arm',
  18: 'ppc',
  0x01000007: 'x64',
  0x0100000c: 'arm64',
}

const FILE_TYPES: Record<number, string> = {
  1: 'object',
  2: 'execute',
  3: 'fvmlib',
  4: 'core',
  5: 'preload',
  6: 'dylib',
  7: 'dylinker',
  8: 'bundle',
  9: 'dylib_stub',
  10: 'dsym',
  11: 'kext_bundle',
}

const OBJC_POINTER_SECTIONS: Record<string, string> = {
  __objc_classlist: 'classlist',
  __objc_nlclslist: 'non_lazy_classlist',
  __objc_catlist: 'category_list',
  __objc_nlcatlist: 'non_lazy_category_list',
  __objc_protolist: 'protocol_list',
  __objc_selrefs: 'selector_refs',
  __objc_classrefs: 'class_refs',
  __objc_superrefs: 'super_refs',
  __objc_ivar: 'ivar_offsets',
}

const OBJC_STRING_SECTIONS = new Set(['__objc_methname', '__objc_classname', '__objc_methtype'])

const SWIFT_SECTION_PREFIXES = ['__swift', '__swift5']

const APPLE_METADATA_EVIDENCE = [
  'structure',
  'symbols',
  'classes',
  'selectors',
  'protocols',
  'swift-metadata',
  'workflow',
  'provenance',
]

const APPLE_METADATA_SAFETY = [
  'passive',
  'no_execute',
  'no_debug_attach',
  'no_app_launch',
  'no_auto_mount',
  'no_external_tool',
  'no_runtime_start',
  'no_network_by_default',
  'no_mutation',
]

const APPLE_METADATA_FOLLOW_UP_TOOLS = [
  'macho.structure.analyze',
  'apple.signing.inspect',
  'apple.security.profile',
  'analysis.evidence.graph',
  'artifact.read',
  'strings.extract',
  'report.generate',
]

const APPLE_RUNTIME_PLAN_TOOLS = ['macos.runtime.plan', 'ios.runtime.plan', 'tool.readiness']

const AppleObjcSwiftPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_debug_attach: z.literal(true),
  no_app_launch: z.literal(true),
  no_auto_mount: z.literal(true),
  no_external_tool: z.literal(true),
  no_runtime_start: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const AppleMachOSectionSchema = z.object({
  segment: z.string(),
  section: z.string(),
  offset: z.number(),
  absolute_offset: z.number(),
  address: z.number(),
  size: z.number(),
  flags: z.number(),
  entry_hint_count: z.number(),
  present_in_preview: z.boolean(),
})

const AppleObjcSwiftInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  macho: z.object({
    valid_magic: z.boolean(),
    is_fat: z.boolean(),
    parsed_slice_offset: z.number().nullable(),
    slice_count: z.number(),
    architectures: z.array(z.record(z.any())),
    cputype: z.string().nullable(),
    filetype: z.string().nullable(),
    is_64: z.boolean().nullable(),
    endian: z.enum(['little', 'big']).nullable(),
    pointer_size: z.number(),
    load_command_count: z.number(),
    section_count: z.number(),
    sections: z.array(AppleMachOSectionSchema),
  }),
  objc: z.object({
    present: z.boolean(),
    section_counts: z.record(z.number()),
    pointer_reference_counts: z.record(z.number()),
    class_name_hints: z.array(z.string()),
    selector_hints: z.array(z.string()),
    protocol_hints: z.array(z.string()),
    symbol_hints: z.array(z.string()),
    runtime_api_hints: z.array(z.string()),
  }),
  swift: z.object({
    present: z.boolean(),
    standalone_metadata: z.boolean(),
    section_counts: z.record(z.number()),
    section_hints: z.array(z.string()),
    module_hints: z.array(z.string()),
    mangled_symbol_hints: z.array(z.string()),
    reflection_string_hints: z.array(z.string()),
    concurrency_hints: z.array(z.string()),
    abi_document_hints: z.array(z.string()),
  }),
  interop_hints: z.array(z.string()),
  capability_risk_summary: z.object({
    dynamic_dispatch: z.boolean(),
    reflection_or_selector_invocation: z.boolean(),
    native_library_loading: z.boolean(),
    keychain_or_security_api: z.boolean(),
    network_api: z.boolean(),
    filesystem_api: z.boolean(),
    privacy_sensitive_api: z.boolean(),
    risk_level: z.enum(['none', 'low', 'medium', 'high']),
  }),
  demangle_plan: z.object({
    status: z.literal('plan_only'),
    external_tool_invoked_by_tool: z.literal(false),
    recommended_tools: z.array(z.string()),
    notes: z.array(z.string()),
  }),
  runtime_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    handoff: z.object({
      primary_tools: z.array(z.string()),
      readiness_tool: z.literal('tool.readiness'),
      static_evidence_artifact_type: z.literal(APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE),
      runtime_policy: z.object({
        app_launch_allowed: z.literal(false),
        debugger_attach_allowed: z.literal(false),
        device_connection_allowed: z.literal(false),
        network_allowed: z.literal(false),
      }),
    }),
    notes: z.array(z.string()),
  }),
  policy: AppleObjcSwiftPolicySchema,
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const AppleObjcSwiftMetadataInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive ObjC/Swift metadata inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const AppleObjcSwiftMetadataInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: AppleObjcSwiftInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const appleObjcSwiftMetadataInspectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Objective-C and Swift runtime metadata from Mach-O sections, symbols, and standalone Swift metadata files without app launch, debugger attach, external Apple tooling, or runtime start.',
  inputSchema: AppleObjcSwiftMetadataInspectInputSchema,
  outputSchema: AppleObjcSwiftMetadataInspectOutputSchema,
  aspects: {
    formats: [
      'objc-metadata',
      'objective-c',
      'objc',
      'swift-metadata',
      'swift',
      'swiftmodule',
      'swiftinterface',
      'swiftdoc',
      'swift-abi',
      'swift-reflection',
      'macho',
      'mach-o',
      'mach-o-fat',
      'macho-object',
      'dylib',
      'framework',
      'xcframework',
      'app-bundle',
      'ipa',
      'dsym',
    ],
    platforms: ['macos', 'ios'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage', 'workflow-plan'],
    safety: APPLE_METADATA_SAFETY,
    capabilities: [
      'objc-runtime-metadata-inventory',
      'swift-abi-metadata-inventory',
      'selector-inventory',
      'class-protocol-inventory',
      'swift-reflection-hints',
      'demangle-plan',
      'runtime-handoff',
      'workflow-routing',
    ],
    evidence: APPLE_METADATA_EVIDENCE,
  },
  artifacts: [
    {
      type: APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE,
      description: 'Passive Objective-C and Swift runtime metadata inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE] },
    { category: 'classes', artifactTypes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE] },
    { category: 'selectors', artifactTypes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE] },
    { category: 'protocols', artifactTypes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE] },
    { category: 'swift-metadata', artifactTypes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'apple.objc-swift-metadata-static-inventory',
      title: 'Apple Objective-C and Swift metadata static inventory',
      description:
        'Route ObjC class/protocol/selector and Swift ABI/reflection metadata into Apple static correlation and opt-in runtime planning without app launch, debugger attach, external Apple tools, or device access.',
      startsWith: [TOOL_NAME],
      nextTools: [
        'macho.structure.analyze',
        'apple.signing.inspect',
        'apple.security.profile',
        'analysis.evidence.graph',
        'artifact.read',
        'strings.extract',
        'report.generate',
        'macos.runtime.plan',
        'ios.runtime.plan',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE],
      evidence: APPLE_METADATA_EVIDENCE,
      safety: APPLE_METADATA_SAFETY,
    },
  ],
}

export type AppleObjcSwiftMetadataInventory = z.infer<typeof AppleObjcSwiftInventorySchema>
type AppleMachOSection = z.infer<typeof AppleMachOSectionSchema>

type Endian = 'little' | 'big'

type ParsedMachO = {
  validMagic: boolean
  isFat: boolean
  parsedSliceOffset: number | null
  architectures: Array<Record<string, unknown>>
  cputype: string | null
  filetype: string | null
  is64: boolean | null
  endian: Endian | null
  pointerSize: number
  loadCommandCount: number
  sections: AppleMachOSection[]
  symbols: string[]
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  if (normalized.endsWith('.abi.json')) return 'abi.json'
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function readU32(data: Buffer, offset: number, endian: Endian): number {
  return endian === 'little' ? data.readUInt32LE(offset) : data.readUInt32BE(offset)
}

function readI32(data: Buffer, offset: number, endian: Endian): number {
  return endian === 'little' ? data.readInt32LE(offset) : data.readInt32BE(offset)
}

function readU64Number(data: Buffer, offset: number, endian: Endian): number {
  const value = endian === 'little' ? data.readBigUInt64LE(offset) : data.readBigUInt64BE(offset)
  return Number(value > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt(Number.MAX_SAFE_INTEGER) : value)
}

function readFixedName(data: Buffer, offset: number, length: number): string {
  return data
    .subarray(offset, offset + length)
    .toString('utf8')
    .replace(/\0.*$/s, '')
}

function readCString(data: Buffer, offset: number, limit: number): string {
  const max = Math.min(data.length, offset + Math.max(0, limit))
  let end = offset
  while (end < max && data[end] !== 0) end += 1
  return data
    .subarray(offset, end)
    .toString('utf8')
    .replace(/[\u0000-\u001f]+/g, '')
}

function addCount(target: Record<string, number>, key: string, value = 1): void {
  target[key] = (target[key] ?? 0) + value
}

function unique(values: string[], limit = MAX_HINTS): string[] {
  return Array.from(new Set(values.map((item) => item.trim()).filter(Boolean))).slice(0, limit)
}

function isPrintableHint(value: string): boolean {
  if (value.length < 2 || value.length > 180) return false
  let printable = 0
  for (const char of value) {
    const code = char.charCodeAt(0)
    if (code >= 0x20 && code <= 0x7e) printable += 1
  }
  return printable / value.length > 0.85
}

function extractCStringList(
  data: Buffer,
  offset: number,
  size: number,
  limit = MAX_HINTS
): string[] {
  if (offset >= data.length || size <= 0) return []
  const end = Math.min(data.length, offset + Math.min(size, MAX_SECTION_STRING_BYTES))
  return unique(
    data.subarray(offset, end).toString('utf8').split('\0').filter(isPrintableHint),
    limit
  )
}

function extractAsciiStrings(data: Buffer, limit = MAX_STRINGS): string[] {
  const strings: string[] = []
  let start = -1
  for (let i = 0; i <= data.length && strings.length < limit; i += 1) {
    const byte = i < data.length ? data[i] : 0
    const printable = byte >= 0x20 && byte <= 0x7e
    if (printable && start < 0) start = i
    if ((!printable || i === data.length) && start >= 0) {
      if (i - start >= 4) {
        const value = data.subarray(start, i).toString('ascii')
        if (isPrintableHint(value)) strings.push(value)
      }
      start = -1
    }
  }
  return unique(strings, limit)
}

function isSwiftMangledSymbol(value: string): boolean {
  const normalized = value.replace(/^_+/, '')
  return (
    normalized.startsWith('$s') ||
    normalized.startsWith('$S') ||
    normalized.startsWith('T0') ||
    normalized.startsWith('Tt') ||
    value.startsWith('_$s') ||
    value.startsWith('__T')
  )
}

function isObjcSymbol(value: string): boolean {
  return /(?:_OBJC_|OBJC_CLASS|OBJC_METACLASS|OBJC_PROTOCOL|_objc_|objc_msgSend)/.test(value)
}

function parseSwiftModuleFromSymbol(symbol: string): string | null {
  let value = symbol.replace(/^_+/, '')
  if (value.startsWith('$s') || value.startsWith('$S')) {
    value = value.slice(2)
  } else if (value.startsWith('T0') || value.startsWith('Tt')) {
    value = value.slice(2)
  } else {
    return null
  }

  const lengthMatch = value.match(/^(\d{1,3})([A-Za-z_][A-Za-z0-9_]*)/)
  if (!lengthMatch) return null
  const length = Number(lengthMatch[1])
  const name = lengthMatch[2].slice(0, length)
  return name.length === length ? name : null
}

function parseObjcSymbolName(symbol: string, marker: string): string | null {
  const index = symbol.indexOf(marker)
  if (index < 0) return null
  const value = symbol.slice(index + marker.length).replace(/^_+/, '')
  return value && /^[A-Za-z_][A-Za-z0-9_.$-]{0,160}$/.test(value) ? value : null
}

function parseFatHeader(data: Buffer): {
  isFat: boolean
  architectures: Array<Record<string, unknown>>
  firstSliceOffset: number | null
} {
  if (data.length < 8) return { isFat: false, architectures: [], firstSliceOffset: null }

  const magic = data.readUInt32BE(0)
  const magicLe = data.readUInt32LE(0)
  const isFat32 = magic === FAT_MAGIC || magicLe === FAT_MAGIC
  const isFat64 = magic === FAT_MAGIC_64 || magicLe === FAT_MAGIC_64
  const isCigam32 = magic === FAT_CIGAM || magicLe === FAT_CIGAM
  const isCigam64 = magic === FAT_CIGAM_64 || magicLe === FAT_CIGAM_64
  if (!isFat32 && !isFat64 && !isCigam32 && !isCigam64) {
    return { isFat: false, architectures: [], firstSliceOffset: null }
  }

  const endian: Endian = isCigam32 || isCigam64 ? 'little' : 'big'
  const arch64 = isFat64 || isCigam64
  const nfatArch = Math.min(readU32(data, 4, endian), 32)
  const archSize = arch64 ? 32 : 20
  const architectures: Array<Record<string, unknown>> = []
  let firstSliceOffset: number | null = null

  for (let index = 0; index < nfatArch; index += 1) {
    const offset = 8 + index * archSize
    if (offset + archSize > data.length) break
    const cpu = readI32(data, offset, endian)
    const cpuSubtype = readI32(data, offset + 4, endian)
    const sliceOffset = arch64
      ? readU64Number(data, offset + 8, endian)
      : readU32(data, offset + 8, endian)
    const sliceSize = arch64
      ? readU64Number(data, offset + 16, endian)
      : readU32(data, offset + 12, endian)
    const align = readU32(data, arch64 ? offset + 24 : offset + 16, endian)
    if (firstSliceOffset === null) firstSliceOffset = sliceOffset
    architectures.push({
      cputype: CPU_TYPES[cpu] ?? `cpu-${cpu}`,
      cpusubtype: cpuSubtype,
      offset: sliceOffset,
      size: sliceSize,
      align,
    })
  }

  return { isFat: true, architectures, firstSliceOffset }
}

function parseMachOHeader(data: Buffer, baseOffset: number) {
  if (baseOffset < 0 || baseOffset + 28 > data.length) return null
  const magic = data.readUInt32LE(baseOffset)
  const known = [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64]
  if (!known.includes(magic)) return null
  const is64 = magic === MH_MAGIC_64 || magic === MH_CIGAM_64
  const endian: Endian = magic === MH_CIGAM || magic === MH_CIGAM_64 ? 'big' : 'little'
  const headerSize = is64 ? 32 : 28
  if (baseOffset + headerSize > data.length) return null

  return {
    is64,
    endian,
    headerSize,
    cputype: readI32(data, baseOffset + 4, endian),
    filetype: readU32(data, baseOffset + 12, endian),
    ncmds: readU32(data, baseOffset + 16, endian),
    sizeofcmds: readU32(data, baseOffset + 20, endian),
  }
}

function parseSectionsFromSegment(
  data: Buffer,
  commandOffset: number,
  commandSize: number,
  baseOffset: number,
  endian: Endian,
  is64: boolean,
  pointerSize: number
): AppleMachOSection[] {
  const sections: AppleMachOSection[] = []
  const minCommandSize = is64 ? 72 : 56
  if (commandSize < minCommandSize || commandOffset + minCommandSize > data.length) return sections

  const nsects = Math.min(readU32(data, commandOffset + (is64 ? 64 : 48), endian), MAX_SECTIONS)
  const sectionOffset = commandOffset + (is64 ? 72 : 56)
  const sectionSize = is64 ? 80 : 68

  for (let index = 0; index < nsects && sections.length < MAX_SECTIONS; index += 1) {
    const offset = sectionOffset + index * sectionSize
    if (offset + sectionSize > data.length || offset + sectionSize > commandOffset + commandSize) {
      break
    }
    const section = readFixedName(data, offset, 16)
    const segment = readFixedName(data, offset + 16, 16)
    const address = is64
      ? readU64Number(data, offset + 32, endian)
      : readU32(data, offset + 32, endian)
    const size = is64
      ? readU64Number(data, offset + 40, endian)
      : readU32(data, offset + 36, endian)
    const fileOffset = readU32(data, offset + (is64 ? 48 : 40), endian)
    const flags = readU32(data, offset + (is64 ? 64 : 56), endian)
    const absoluteOffset = baseOffset + fileOffset
    sections.push({
      segment,
      section,
      offset: fileOffset,
      absolute_offset: absoluteOffset,
      address,
      size,
      flags,
      entry_hint_count: pointerSize > 0 ? Math.floor(size / pointerSize) : 0,
      present_in_preview: absoluteOffset < data.length,
    })
  }

  return sections
}

function parseMachOSymbols(
  data: Buffer,
  baseOffset: number,
  symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | null,
  endian: Endian,
  is64: boolean
): string[] {
  if (!symtab) return []
  const symbols: string[] = []
  const nlistSize = is64 ? 16 : 12
  const symbolOffset = baseOffset + symtab.symoff
  const stringOffset = baseOffset + symtab.stroff
  const count = Math.min(symtab.nsyms, MAX_SYMBOLS)

  if (stringOffset >= data.length || symtab.strsize <= 0) return []

  for (let index = 0; index < count; index += 1) {
    const offset = symbolOffset + index * nlistSize
    if (offset + nlistSize > data.length) break
    const nameOffset = readU32(data, offset, endian)
    if (nameOffset <= 0 || nameOffset >= symtab.strsize) continue
    const name = readCString(data, stringOffset + nameOffset, symtab.strsize - nameOffset)
    if (name && (isSwiftMangledSymbol(name) || isObjcSymbol(name))) symbols.push(name)
  }

  return unique(symbols, MAX_SYMBOLS)
}

function parseSingleMachO(
  data: Buffer,
  baseOffset: number,
  isFat: boolean,
  architectures: Array<Record<string, unknown>>
): ParsedMachO {
  const header = parseMachOHeader(data, baseOffset)
  if (!header) {
    return {
      validMagic: false,
      isFat,
      parsedSliceOffset: isFat ? baseOffset : null,
      architectures,
      cputype: null,
      filetype: null,
      is64: null,
      endian: null,
      pointerSize: 8,
      loadCommandCount: 0,
      sections: [],
      symbols: [],
    }
  }

  const sections: AppleMachOSection[] = []
  let symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | null = null
  let commandOffset = baseOffset + header.headerSize
  const commandEnd = Math.min(data.length, commandOffset + header.sizeofcmds)
  const commandCount = Math.min(header.ncmds, MAX_LOAD_COMMANDS)
  const pointerSize = header.is64 ? 8 : 4

  for (let index = 0; index < commandCount && commandOffset + 8 <= commandEnd; index += 1) {
    const cmd = readU32(data, commandOffset, header.endian)
    const cmdsize = readU32(data, commandOffset + 4, header.endian)
    if (cmdsize < 8 || commandOffset + cmdsize > data.length) break

    const strippedCmd = cmd & 0x7fffffff
    if (strippedCmd === 0x1 || strippedCmd === 0x19) {
      sections.push(
        ...parseSectionsFromSegment(
          data,
          commandOffset,
          cmdsize,
          baseOffset,
          header.endian,
          strippedCmd === 0x19,
          pointerSize
        )
      )
    } else if (strippedCmd === 0x2 && commandOffset + 24 <= data.length) {
      symtab = {
        symoff: readU32(data, commandOffset + 8, header.endian),
        nsyms: readU32(data, commandOffset + 12, header.endian),
        stroff: readU32(data, commandOffset + 16, header.endian),
        strsize: readU32(data, commandOffset + 20, header.endian),
      }
    }

    commandOffset += cmdsize
  }

  return {
    validMagic: true,
    isFat,
    parsedSliceOffset: isFat ? baseOffset : null,
    architectures,
    cputype: CPU_TYPES[header.cputype] ?? `cpu-${header.cputype}`,
    filetype: FILE_TYPES[header.filetype] ?? `filetype-${header.filetype}`,
    is64: header.is64,
    endian: header.endian,
    pointerSize,
    loadCommandCount: commandCount,
    sections: sections.slice(0, MAX_SECTIONS),
    symbols: parseMachOSymbols(data, baseOffset, symtab, header.endian, header.is64),
  }
}

function parseMachO(data: Buffer): ParsedMachO {
  const fat = parseFatHeader(data)
  if (fat.isFat && fat.firstSliceOffset !== null) {
    return parseSingleMachO(data, fat.firstSliceOffset, true, fat.architectures)
  }
  return parseSingleMachO(data, 0, false, [])
}

function detectFormat(data: Buffer, filename?: string): { format: string; detectedBy: string[] } {
  const extension = extensionOf(filename)
  const magic = data.length >= 4 ? data.readUInt32LE(0) : 0
  const magicBe = data.length >= 4 ? data.readUInt32BE(0) : 0
  const detectedBy: string[] = []

  if ([MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64].includes(magic)) {
    detectedBy.push('macho magic')
    return { format: 'macho', detectedBy }
  }
  if ([FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64].includes(magicBe)) {
    detectedBy.push('fat macho magic')
    return { format: 'mach-o-fat', detectedBy }
  }
  if (['swiftmodule', 'swiftinterface', 'swiftdoc', 'abi.json'].includes(extension)) {
    detectedBy.push('filename extension')
    return { format: extension === 'abi.json' ? 'swift-abi' : extension, detectedBy }
  }
  detectedBy.push('content scan')
  return { format: 'apple-objc-swift-metadata', detectedBy }
}

function stringsFromSections(
  data: Buffer,
  sections: AppleMachOSection[],
  predicate: (section: AppleMachOSection) => boolean
): string[] {
  return unique(
    sections.flatMap((section) =>
      predicate(section) ? extractCStringList(data, section.absolute_offset, section.size) : []
    )
  )
}

function buildObjcInventory(
  data: Buffer,
  sections: AppleMachOSection[],
  symbols: string[],
  asciiStrings: string[],
  pointerSize: number
): AppleObjcSwiftMetadataInventory['objc'] {
  const sectionCounts: Record<string, number> = {}
  const pointerReferenceCounts: Record<string, number> = {}

  for (const section of sections) {
    if (section.section.startsWith('__objc_')) {
      addCount(sectionCounts, section.section)
      const pointerKind = OBJC_POINTER_SECTIONS[section.section]
      if (pointerKind) {
        pointerReferenceCounts[pointerKind] = pointerSize
          ? Math.floor(section.size / pointerSize)
          : section.entry_hint_count
      }
    }
  }

  const classSectionStrings = stringsFromSections(
    data,
    sections,
    (section) => section.section === '__objc_classname'
  )
  const selectorSectionStrings = stringsFromSections(
    data,
    sections,
    (section) => section.section === '__objc_methname'
  )
  const typeSectionStrings = stringsFromSections(
    data,
    sections,
    (section) => section.section === '__objc_methtype'
  )
  const objcSymbols = symbols.filter(isObjcSymbol)
  const classNames = [
    ...classSectionStrings,
    ...objcSymbols
      .map((symbol) => parseObjcSymbolName(symbol, '_OBJC_CLASS_$_'))
      .filter((value): value is string => Boolean(value)),
  ]
  const protocolNames = objcSymbols
    .map((symbol) => parseObjcSymbolName(symbol, '_OBJC_PROTOCOL_$_'))
    .filter((value): value is string => Boolean(value))
  const selectorHints = [
    ...selectorSectionStrings,
    ...asciiStrings.filter((value) =>
      /^(?:set[A-Z]|init|viewDid|application:|tableView:|URLSession:|performSelector|respondsToSelector)/.test(
        value
      )
    ),
  ]
  const runtimeApiHints = unique(
    [...objcSymbols, ...asciiStrings].filter((value) =>
      /objc_msgSend|objc_getClass|NSClassFromString|performSelector|respondsToSelector|dlopen|dlsym/.test(
        value
      )
    )
  )

  return {
    present:
      Object.keys(sectionCounts).length > 0 ||
      objcSymbols.length > 0 ||
      classNames.length > 0 ||
      selectorHints.length > 0,
    section_counts: sectionCounts,
    pointer_reference_counts: pointerReferenceCounts,
    class_name_hints: unique(classNames),
    selector_hints: unique(selectorHints),
    protocol_hints: unique(protocolNames),
    symbol_hints: unique(objcSymbols),
    runtime_api_hints: runtimeApiHints,
  }
}

function buildSwiftInventory(
  data: Buffer,
  sections: AppleMachOSection[],
  symbols: string[],
  asciiStrings: string[],
  format: string
): AppleObjcSwiftMetadataInventory['swift'] {
  const sectionCounts: Record<string, number> = {}
  const swiftSections = sections.filter((section) =>
    SWIFT_SECTION_PREFIXES.some((prefix) => section.section.startsWith(prefix))
  )
  for (const section of swiftSections) {
    addCount(sectionCounts, section.section)
  }

  const swiftSymbols = unique(
    [
      ...symbols.filter(isSwiftMangledSymbol),
      ...asciiStrings.filter((value) => isSwiftMangledSymbol(value) || /\bSwift\./.test(value)),
    ],
    MAX_SYMBOLS
  )
  const reflectionStrings = stringsFromSections(
    data,
    swiftSections,
    (section) => section.section === '__swift5_reflstr' || section.section === '__swift5_typeref'
  )
  const moduleHints = unique(
    swiftSymbols
      .map(parseSwiftModuleFromSymbol)
      .filter((value): value is string => Boolean(value))
      .concat(
        asciiStrings
          .map((value) => value.match(/\bmodule\s+([A-Za-z_][A-Za-z0-9_.-]{1,80})/)?.[1])
          .filter((value): value is string => Boolean(value))
      )
  )
  const concurrencyHints = unique(
    [...swiftSymbols, ...asciiStrings].filter((value) =>
      /(?:_Concurrency|Swift\.Task|AsyncSequence|MainActor|TaskGroup|async|await)/.test(value)
    )
  )
  const abiHints = unique(
    asciiStrings.filter((value) =>
      /(?:swiftinterface|swiftmodule|swift-abi|abi\.json|target\s+.+apple|swift-version)/i.test(
        value
      )
    )
  )
  const standalone = ['swiftmodule', 'swiftinterface', 'swiftdoc', 'swift-abi'].includes(format)

  return {
    present:
      swiftSections.length > 0 ||
      swiftSymbols.length > 0 ||
      standalone ||
      abiHints.length > 0 ||
      reflectionStrings.length > 0,
    standalone_metadata: standalone,
    section_counts: sectionCounts,
    section_hints: swiftSections.map((section) => `${section.segment}.${section.section}`),
    module_hints: moduleHints,
    mangled_symbol_hints: swiftSymbols,
    reflection_string_hints: unique(reflectionStrings),
    concurrency_hints: concurrencyHints,
    abi_document_hints: abiHints,
  }
}

function summarizeRisk(
  objc: AppleObjcSwiftMetadataInventory['objc'],
  swift: AppleObjcSwiftMetadataInventory['swift']
): AppleObjcSwiftMetadataInventory['capability_risk_summary'] {
  const corpus = [
    ...objc.selector_hints,
    ...objc.symbol_hints,
    ...objc.runtime_api_hints,
    ...swift.mangled_symbol_hints,
    ...swift.reflection_string_hints,
    ...swift.abi_document_hints,
  ].join('\n')
  const dynamicDispatch = objc.selector_hints.length > 0 || /objc_msgSend/.test(corpus)
  const reflection = /NSClassFromString|performSelector|respondsToSelector|Selector\(/.test(corpus)
  const nativeLoading = /dlopen|dlsym|NSBundle|loadAndReturnError/.test(corpus)
  const keychain = /SecItem|Keychain|Security\.framework|LAContext|CryptoKit|CommonCrypto/.test(
    corpus
  )
  const network = /URLSession|NSURLSession|CFNetwork|Network\.framework|NWConnection|http/i.test(
    corpus
  )
  const filesystem =
    /FileManager|NSFileManager|writeToFile|contentsOfDirectory|URLForDirectory/.test(corpus)
  const privacy = /CLLocation|AVCapture|Photos|Contacts|HealthKit|Bluetooth|Microphone|Camera/.test(
    corpus
  )
  const score = [reflection, nativeLoading, keychain, network, filesystem, privacy].filter(
    Boolean
  ).length
  const riskLevel =
    nativeLoading || score >= 4 ? 'high' : score >= 2 ? 'medium' : dynamicDispatch ? 'low' : 'none'

  return {
    dynamic_dispatch: dynamicDispatch,
    reflection_or_selector_invocation: reflection,
    native_library_loading: nativeLoading,
    keychain_or_security_api: keychain,
    network_api: network,
    filesystem_api: filesystem,
    privacy_sensitive_api: privacy,
    risk_level: riskLevel,
  }
}

function buildRuntimePlan(
  riskLevel: string,
  platformHint: string
): AppleObjcSwiftMetadataInventory['runtime_plan'] {
  const primaryTools = platformHint === 'ios' ? ['ios.runtime.plan'] : ['macos.runtime.plan']
  return {
    status: 'plan_only',
    recommended_tools: [...primaryTools, 'tool.readiness', 'apple.security.profile'],
    handoff: {
      primary_tools: primaryTools,
      readiness_tool: 'tool.readiness',
      static_evidence_artifact_type: APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE,
      runtime_policy: {
        app_launch_allowed: false,
        debugger_attach_allowed: false,
        device_connection_allowed: false,
        network_allowed: false,
      },
    },
    notes: [
      'Runtime validation is an explicit follow-up plan only; this tool does not launch apps or attach debuggers.',
      'Review selectors, class/protocol hints, entitlements, and signing inventory before any LLDB/Frida/device plan.',
      `Metadata capability risk level: ${riskLevel}.`,
    ],
  }
}

function buildDemanglePlan(): AppleObjcSwiftMetadataInventory['demangle_plan'] {
  return {
    status: 'plan_only',
    external_tool_invoked_by_tool: false,
    recommended_tools: ['artifact.read', 'strings.extract', 'analysis.evidence.graph'],
    notes: [
      'Swift symbols are reported as mangled hints only.',
      'No swift-demangle, xcrun, nm, otool, class-dump, or lipo process is invoked.',
      'If demangling is required, route it through an explicit future backend with readiness and policy gates.',
    ],
  }
}

function platformHintFromFilename(filename?: string): string {
  const normalized = (filename ?? '').toLowerCase()
  return normalized.includes('.ipa') || normalized.includes('payload/') ? 'ios' : 'macos'
}

export function buildAppleObjcSwiftMetadataFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): AppleObjcSwiftMetadataInventory {
  const detected = detectFormat(data, options.filename)
  const macho = parseMachO(data)
  const asciiStrings = extractAsciiStrings(data)
  const objc = buildObjcInventory(
    data,
    macho.sections,
    macho.symbols,
    asciiStrings,
    macho.pointerSize
  )
  const swift = buildSwiftInventory(
    data,
    macho.sections,
    macho.symbols,
    asciiStrings,
    detected.format
  )
  const interopHints = unique(
    [
      objc.present && swift.present ? 'objc-swift-interop' : '',
      objc.class_name_hints.some((name) => name.includes('.')) ? 'swift-objc-class-names' : '',
      swift.mangled_symbol_hints.length > 0 && objc.selector_hints.length > 0
        ? 'swift-symbols-and-objc-selectors'
        : '',
    ].filter(Boolean)
  )
  const risk = summarizeRisk(objc, swift)
  const platformHint = platformHintFromFilename(options.filename)
  const runtimePlan = buildRuntimePlan(risk.risk_level, platformHint)
  const objcSignalCount =
    objc.class_name_hints.length +
    objc.selector_hints.length +
    objc.protocol_hints.length +
    objc.symbol_hints.length
  const swiftSignalCount =
    swift.section_hints.length +
    swift.mangled_symbol_hints.length +
    swift.module_hints.length +
    swift.reflection_string_hints.length

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: detected.detectedBy,
    size: options.size ?? data.length,
    macho: {
      valid_magic: macho.validMagic,
      is_fat: macho.isFat,
      parsed_slice_offset: macho.parsedSliceOffset,
      slice_count: macho.isFat ? macho.architectures.length : macho.validMagic ? 1 : 0,
      architectures: macho.architectures,
      cputype: macho.cputype,
      filetype: macho.filetype,
      is_64: macho.is64,
      endian: macho.endian,
      pointer_size: macho.pointerSize,
      load_command_count: macho.loadCommandCount,
      section_count: macho.sections.length,
      sections: macho.sections,
    },
    objc,
    swift,
    interop_hints: interopHints,
    capability_risk_summary: risk,
    demangle_plan: buildDemanglePlan(),
    runtime_plan: runtimePlan,
    policy: {
      passive: true,
      no_execute: true,
      no_debug_attach: true,
      no_app_launch: true,
      no_auto_mount: true,
      no_external_tool: true,
      no_runtime_start: true,
      no_network: true,
      no_mutation: true,
    },
    evidence_summary: {
      schema: 'rikune.apple_objc_swift_metadata.evidence_summary.v1',
      source_tool: TOOL_NAME,
      artifact_type: APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE,
      sample_id: options.sampleId ?? null,
      evidence_categories: APPLE_METADATA_EVIDENCE,
      counts: {
        macho_sections: macho.sections.length,
        macho_symbols: macho.symbols.length,
        objc_sections: Object.keys(objc.section_counts).length,
        objc_signal_count: objcSignalCount,
        swift_sections: Object.keys(swift.section_counts).length,
        swift_signal_count: swiftSignalCount,
      },
      static_only: true,
      sample_executed_by_tool: false,
      runtime_started_by_tool: false,
      external_tool_invoked_by_tool: false,
      debugger_attached_by_tool: false,
      app_launched_by_tool: false,
      dmg_mounted_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
    workflow_handoff: {
      schema: 'rikune.apple_objc_swift_metadata.workflow_handoff.v1',
      handoff_mode: 'apple_objc_swift_metadata_to_static_correlation_and_runtime_plan',
      artifact_type: APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE,
      recommended_next_tools: [...APPLE_METADATA_FOLLOW_UP_TOOLS, ...APPLE_RUNTIME_PLAN_TOOLS],
      artifact_contract: {
        consumes: ['sample'],
        produces: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE],
        expected_consumers: [
          'workflow.search',
          'artifact.read',
          'macho.structure.analyze',
          'apple.signing.inspect',
          'apple.security.profile',
          'analysis.evidence.graph',
          'report.generate',
        ],
      },
      routing: [
        {
          goal: 'objc-selector-class-protocol-review',
          priority: objcSignalCount > 0 ? 'high' : 'conditional',
          next_tools: ['macho.structure.analyze', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: ['classes', 'selectors', 'protocols'],
          consumes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE],
          produces: ['apple_objc_metadata_graph'],
        },
        {
          goal: 'swift-abi-reflection-review',
          priority: swiftSignalCount > 0 ? 'high' : 'conditional',
          next_tools: ['strings.extract', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: ['swift-metadata', 'symbols'],
          consumes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE],
          produces: ['apple_swift_metadata_graph'],
        },
        {
          goal: 'apple-runtime-validation-planning',
          priority: risk.risk_level === 'none' ? 'conditional' : 'normal',
          next_tools: runtimePlan.handoff.primary_tools,
          required_evidence: ['workflow', 'selectors', 'swift-metadata'],
          consumes: [APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE, 'apple_security_profile'],
          produces: ['apple_runtime_plan'],
        },
      ],
      dynamic_boundary: {
        app_launch_allowed: false,
        debugger_attach_allowed: false,
        device_connection_allowed: false,
        external_tool_allowed: false,
        network_allowed: false,
        mutation_allowed: false,
        sample_executed_by_tool: false,
        runtime_started_by_tool: false,
      },
    },
    quality_gates: {
      schema: 'rikune.apple_objc_swift_metadata.quality_gates.v1',
      passive_static_inventory: true,
      bounded_preview: true,
      sample_executed_by_tool: false,
      runtime_started_by_tool: false,
      external_tool_invoked_by_tool: false,
      debugger_attached_by_tool: false,
      app_launched_by_tool: false,
      dmg_mounted_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
      objc_metadata_detected: objc.present,
      swift_metadata_detected: swift.present,
    },
    summary: `Passive Apple ObjC/Swift metadata inventory found ${objcSignalCount} Objective-C hint(s), ${swiftSignalCount} Swift hint(s), and ${macho.sections.length} Mach-O section(s).`,
    recommended_next_tools: [...APPLE_METADATA_FOLLOW_UP_TOOLS, ...runtimePlan.recommended_tools],
    next_actions: [
      'Review Objective-C class, protocol, selector, and Swift symbol/section hints as static evidence.',
      'Correlate this artifact with Mach-O structure, signing, and entitlement inventories before runtime planning.',
      'Do not launch apps, mount images, attach debuggers, connect devices, or run Apple external tooling during static triage.',
    ],
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

export function createAppleObjcSwiftMetadataInspectHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (
    args: z.infer<typeof AppleObjcSwiftMetadataInspectInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = AppleObjcSwiftMetadataInspectInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildAppleObjcSwiftMetadataFromBuffer(data, {
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
            APPLE_OBJC_SWIFT_METADATA_ARTIFACT_TYPE,
            'apple-objc-swift-metadata',
            inventory,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Artifact persistence is best-effort for passive inventory.
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
