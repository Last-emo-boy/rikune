/**
 * compiler.codegen.fingerprint — passive compiler/codegen provenance inventory.
 *
 * This tool reads bounded bytes and summarizes static evidence for compiler,
 * linker, language runtime, optimization, LTO/PGO, debug provenance, and
 * code-generation style. It never executes samples, invokes compilers/linkers,
 * contacts symbol/source servers, starts runtime analysis, or mutates samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'compiler.codegen.fingerprint'
export const COMPILER_CODEGEN_FINGERPRINT_ARTIFACT_TYPE = 'compiler_codegen_fingerprint'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 7000
const MAX_EVIDENCE = 360
const MAX_FEATURES = 180

const COMPILER_CODEGEN_EVIDENCE = [
  'provenance',
  'compiler',
  'linker',
  'language-runtime',
  'debug-metadata',
  'section-layout',
  'optimization',
  'workflow',
]

const COMPILER_CODEGEN_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'native.object.inventory',
  'native.debug.types.inventory',
  'windows.debug.metadata.inspect',
  'cpp.abi.layout.inventory',
  'pe.structure.analyze',
  'elf.structure.analyze',
  'macho.structure.analyze',
  'strings.extract',
  'compiler.packer.detect',
  'sbom.provenance.graph',
  'sample.family.cluster',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const COMPILER_CODEGEN_SAFETY = [
  'passive',
  'no_execute',
  'no_native_load',
  'no_debugger',
  'no_compiler_invocation',
  'no_linker_invocation',
  'no_external_tool',
  'no_symbol_server_download',
  'no_source_fetch',
  'no_network_by_default',
  'no_mutation',
]

const CompilerCodegenPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_native_load: z.literal(true),
  no_debugger: z.literal(true),
  no_compiler_invocation: z.literal(true),
  no_linker_invocation: z.literal(true),
  no_external_tool: z.literal(true),
  no_symbol_server_download: z.literal(true),
  no_source_fetch: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const CompilerCodegenFingerprintSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.any()),
  compiler_candidates: z.array(z.record(z.any())),
  linker_candidates: z.array(z.record(z.any())),
  language_runtime_hints: z.array(z.record(z.any())),
  optimization_hints: z.array(z.record(z.any())),
  codegen_features: z.array(z.record(z.any())),
  provenance_markers: z.array(z.record(z.any())),
  section_layout: z.record(z.any()),
  risk_flags: z.array(z.record(z.any())),
  policy: CompilerCodegenPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const CompilerCodegenFingerprintInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive compiler/codegen fingerprinting.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist compiler/codegen fingerprint JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const CompilerCodegenFingerprintOutputSchema = z.object({
  ok: z.boolean(),
  data: CompilerCodegenFingerprintSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const compilerCodegenFingerprintAspects = {
  formats: [
    'compiler-codegen',
    'codegen',
    'compiler-provenance',
    'toolchain-provenance',
    'build-provenance',
    'optimization-level',
    'lto',
    'pgo',
    'rich-header',
    'codeview',
    'pe',
    'elf',
    'macho',
    'coff',
    'object',
    'static-lib',
    'native',
  ],
  platforms: ['windows', 'linux', 'macos', 'ios', 'android', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv', 'wasm32'],
  execution: ['static', 'triage', 'correlation', 'workflow-plan'],
  safety: COMPILER_CODEGEN_SAFETY,
  capabilities: [
    'compiler-codegen-fingerprint',
    'toolchain-provenance-inventory',
    'compiler-family-candidate-ranking',
    'linker-family-candidate-ranking',
    'language-runtime-hints',
    'optimization-lto-pgo-hints',
    'debug-provenance-hints',
    'section-layout-fingerprint',
    'workflow-routing',
  ],
  evidence: COMPILER_CODEGEN_EVIDENCE,
  route_terms: [
    'compiler codegen',
    'compiler fingerprint',
    'compiler provenance',
    'toolchain provenance',
    'build provenance',
    'optimization level',
    'lto',
    'pgo',
    'rich header',
    'codeview',
    'dwarf producer',
    'go build id',
    'rustc',
    'clang version',
    'gcc comment',
  ],
  search: [
    'compiler code generation fingerprint',
    'toolchain provenance inventory',
    'compiler family and linker hints',
    'optimization LTO PGO evidence',
  ],
}

export const compilerCodegenFingerprintToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively fingerprint compiler/codegen provenance across PE, ELF, Mach-O, COFF, and native objects using bounded static evidence such as PE Rich/CodeView, ELF .comment/build-id, language runtime markers, linker hints, section layout, and optimization/LTO/PGO signals without execution or external tools.',
  inputSchema: CompilerCodegenFingerprintInputSchema,
  outputSchema: CompilerCodegenFingerprintOutputSchema,
  aspects: compilerCodegenFingerprintAspects,
  artifacts: [
    {
      type: COMPILER_CODEGEN_FINGERPRINT_ARTIFACT_TYPE,
      description:
        'Passive compiler, linker, language runtime, optimization, and code-generation provenance fingerprint inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: COMPILER_CODEGEN_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [COMPILER_CODEGEN_FINGERPRINT_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'compiler.codegen-fingerprint-static-inventory',
      title: 'Passive compiler/codegen provenance fingerprint',
      description:
        'Inventory compiler, linker, language runtime, debug provenance, section layout, and optimization/LTO/PGO evidence before routing to native object, debug type, SBOM provenance, clustering, evidence graph, and reporting tools.',
      startsWith: [TOOL_NAME],
      nextTools: COMPILER_CODEGEN_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [COMPILER_CODEGEN_FINGERPRINT_ARTIFACT_TYPE],
      evidence: COMPILER_CODEGEN_EVIDENCE,
      safety: COMPILER_CODEGEN_SAFETY,
    },
  ],
}

export type CompilerCodegenFingerprint = z.infer<typeof CompilerCodegenFingerprintSchema>

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
  pe?: Record<string, unknown>
  elf?: Record<string, unknown>
  macho?: Record<string, unknown>
  bounded_preview: {
    bytes_read: number
    max_read_bytes: number
    truncated: boolean
  }
}

interface CodegenEvidence {
  id: string
  family: string
  category: string
  kind: string
  value: string
  source: string
  offset?: number
  section?: string
  confidence: Confidence
  weight: number
}

interface BuildOptions {
  sampleId?: string
  filename?: string
  maxReadBytes?: number
  totalSize?: number
}

function readUInt16(data: Buffer, offset: number, endian: Endian): number {
  if (offset < 0 || offset + 2 > data.length) return 0
  return endian === 'be' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
}

function readUInt32(data: Buffer, offset: number, endian: Endian): number {
  if (offset < 0 || offset + 4 > data.length) return 0
  return endian === 'be' ? data.readUInt32BE(offset) : data.readUInt32LE(offset)
}

function readUInt64Number(data: Buffer, offset: number, endian: Endian): number {
  if (offset < 0 || offset + 8 > data.length) return 0
  const value = endian === 'be' ? data.readBigUInt64BE(offset) : data.readBigUInt64LE(offset)
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? 0 : Number(value)
}

function safeAscii(data: Buffer, offset: number, length: number): string {
  if (offset < 0 || offset >= data.length) return ''
  return data
    .subarray(offset, Math.min(offset + length, data.length))
    .toString('latin1')
    .replace(/\0+$/g, '')
    .trim()
}

function readStringAt(data: Buffer, offset: number, maxLength = 256): string {
  if (offset < 0 || offset >= data.length) return ''
  let end = offset
  while (end < data.length && end - offset < maxLength && data[end] !== 0) end += 1
  return data.subarray(offset, end).toString('latin1')
}

function parseElfSections(data: Buffer): {
  sections: BinarySection[]
  endian?: Endian
  elf?: Record<string, unknown>
} {
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
  const elfType = readUInt16(data, 16, endian)
  const machine = readUInt16(data, 18, endian)
  const shoff = is64 ? readUInt64Number(data, 40, endian) : readUInt32(data, 32, endian)
  const shentsize = readUInt16(data, is64 ? 58 : 46, endian)
  const shnum = readUInt16(data, is64 ? 60 : 48, endian)
  const shstrndx = readUInt16(data, is64 ? 62 : 50, endian)
  if (!shoff || !shentsize || !shnum || shnum > 4096) {
    return {
      sections: [],
      endian,
      elf: { class: is64 ? 'ELF64' : 'ELF32', type: elfType, machine },
    }
  }
  if (shoff + shnum * shentsize > data.length) {
    return {
      sections: [],
      endian,
      elf: { class: is64 ? 'ELF64' : 'ELF32', type: elfType, machine },
    }
  }

  const sectionHeaders = []
  for (let index = 0; index < shnum; index += 1) {
    const base = shoff + index * shentsize
    if (base + shentsize > data.length) break
    const nameOffset = readUInt32(data, base, endian)
    const sectionType = readUInt32(data, base + 4, endian)
    const offset = is64
      ? readUInt64Number(data, base + 24, endian)
      : readUInt32(data, base + 16, endian)
    const size = is64
      ? readUInt64Number(data, base + 32, endian)
      : readUInt32(data, base + 20, endian)
    const virtualAddress = is64
      ? readUInt64Number(data, base + 16, endian)
      : readUInt32(data, base + 12, endian)
    sectionHeaders.push({ nameOffset, sectionType, offset, size, virtualAddress })
  }

  const shstr = sectionHeaders[shstrndx]
  const stringTable =
    shstr && shstr.offset + shstr.size <= data.length
      ? data.subarray(shstr.offset, shstr.offset + shstr.size)
      : Buffer.alloc(0)
  const sections: BinarySection[] = []
  for (const header of sectionHeaders) {
    if (header.offset < 0 || header.offset >= data.length) continue
    const name = readStringAt(stringTable, header.nameOffset, 128) || '<unnamed>'
    sections.push({
      name,
      offset: header.offset,
      size: Math.min(header.size, Math.max(0, data.length - header.offset)),
      virtual_address: header.virtualAddress,
    })
  }
  return {
    sections,
    endian,
    elf: {
      class: is64 ? 'ELF64' : 'ELF32',
      type: elfType,
      machine,
      section_count: sections.length,
      has_comment: sections.some((section) => section.name === '.comment'),
      has_build_id: sections.some((section) => section.name === '.note.gnu.build-id'),
    },
  }
}

function parsePeSections(data: Buffer): {
  sections: BinarySection[]
  pe?: Record<string, unknown>
} {
  if (data.length < 0x100 || data.subarray(0, 2).toString('ascii') !== 'MZ') return { sections: [] }
  const peOffset = data.readUInt32LE(0x3c)
  if (peOffset <= 0 || peOffset + 24 > data.length) return { sections: [] }
  if (data.subarray(peOffset, peOffset + 4).toString('ascii') !== 'PE\0\0') return { sections: [] }
  const machine = data.readUInt16LE(peOffset + 4)
  const sectionCount = data.readUInt16LE(peOffset + 6)
  const timestamp = data.readUInt32LE(peOffset + 8)
  const optionalHeaderSize = data.readUInt16LE(peOffset + 20)
  const optionalHeader = peOffset + 24
  const optionalMagic =
    optionalHeader + 2 <= data.length ? data.readUInt16LE(optionalHeader) : undefined
  const linkerVersion =
    optionalHeader + 4 <= data.length
      ? `${data[optionalHeader + 2]}.${data[optionalHeader + 3]}`
      : undefined
  const sectionTable = optionalHeader + optionalHeaderSize
  if (sectionCount > 256 || sectionTable + sectionCount * 40 > data.length) {
    return {
      sections: [],
      pe: { machine, timestamp, optional_magic: optionalMagic, linker_version: linkerVersion },
    }
  }
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
  const richOffset = data.indexOf(Buffer.from('Rich', 'ascii'), 0, 'latin1')
  return {
    sections,
    pe: {
      machine,
      timestamp,
      optional_magic: optionalMagic,
      linker_version: linkerVersion,
      section_count: sections.length,
      rich_header_marker_present: richOffset >= 0 && richOffset < peOffset,
      codeview_marker_present:
        data.indexOf(Buffer.from('RSDS', 'ascii')) >= 0 ||
        data.indexOf(Buffer.from('NB10', 'ascii')) >= 0,
    },
  }
}

function detectMacho(data: Buffer): Record<string, unknown> | undefined {
  if (data.length < 4) return undefined
  const magicLe = data.readUInt32LE(0)
  const magicBe = data.readUInt32BE(0)
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magicLe)) {
    return {
      magic: `0x${magicLe.toString(16)}`,
      kind: magicLe === 0xfeedfacf || magicLe === 0xcffaedfe ? 'macho64' : 'macho32',
      endian: magicLe === 0xcefaedfe || magicLe === 0xcffaedfe ? 'be' : 'le',
    }
  }
  if ([0xcafebabe, 0xcafebabf].includes(magicBe)) {
    return { magic: `0x${magicBe.toString(16)}`, kind: 'macho-fat', endian: 'be' }
  }
  return undefined
}

function detectContainer(data: Buffer, maxReadBytes: number): ContainerSummary {
  let kind = 'raw-codegen-preview'
  let endian: Endian | undefined
  let sections: BinarySection[] = []
  let pe: Record<string, unknown> | undefined
  let elf: Record<string, unknown> | undefined
  let macho: Record<string, unknown> | undefined
  if (
    data.length >= 4 &&
    data[0] === 0x7f &&
    data[1] === 0x45 &&
    data[2] === 0x4c &&
    data[3] === 0x46
  ) {
    kind = 'elf'
    const parsed = parseElfSections(data)
    sections = parsed.sections
    endian = parsed.endian
    elf = parsed.elf
  } else if (data.length >= 2 && data.subarray(0, 2).toString('ascii') === 'MZ') {
    kind = 'pe'
    const parsed = parsePeSections(data)
    sections = parsed.sections
    pe = parsed.pe
  } else if (data.subarray(0, 8).toString('ascii') === '!<arch>\n') {
    kind = 'ar-static-lib'
  } else {
    macho = detectMacho(data)
    if (macho) kind = String(macho.kind ?? 'macho')
  }

  return {
    kind,
    endian,
    sections,
    pe,
    elf,
    macho,
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

function extractAsciiStrings(data: Buffer): BinaryString[] {
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

function uniquePush<T>(items: T[], item: T, key: (value: T) => string): void {
  const itemKey = key(item)
  if (!items.some((existing) => key(existing) === itemKey)) items.push(item)
}

function addEvidence(evidence: CodegenEvidence[], partial: Omit<CodegenEvidence, 'id'>): void {
  if (evidence.length >= MAX_EVIDENCE) return
  const item: CodegenEvidence = {
    ...partial,
    id: `codegen-evidence-${evidence.length + 1}`,
  }
  uniquePush(
    evidence,
    item,
    (value) => `${value.family}:${value.kind}:${value.value}:${value.offset}`
  )
}

type PatternSpec = {
  family: string
  category: string
  kind: string
  source: string
  pattern: RegExp
  confidence: Confidence
  weight: number
}

const STRING_PATTERNS: PatternSpec[] = [
  {
    family: 'msvc',
    category: 'compiler',
    kind: 'codeview',
    source: 'codeview_marker',
    pattern: /\b(?:RSDS|NB10)\b|\.pdb\b/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'msvc',
    category: 'compiler',
    kind: 'rich-header',
    source: 'pe_rich_header_marker',
    pattern: /\bRich\b/,
    confidence: 'medium',
    weight: 3,
  },
  {
    family: 'msvc',
    category: 'compiler',
    kind: 'msvc-runtime',
    source: 'msvc_runtime_symbol',
    pattern:
      /__CxxFrameHandler[34]|__security_cookie|__chkstk|vcruntime|ucrtbase|msvcrt|libcmt|msvcp/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'mingw',
    category: 'compiler',
    kind: 'mingw-runtime',
    source: 'mingw_runtime_string',
    pattern: /mingw|msys-2\.0|libmingw|crt2\.o/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'gcc',
    category: 'compiler',
    kind: 'gcc-comment',
    source: 'elf_comment_or_string',
    pattern: /\bGCC:\s*\(?GNU\)?|GNU C(?:\+\+)?|__gcc_register_frame|libgcc|libstdc\+\+/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'clang',
    category: 'compiler',
    kind: 'clang-version',
    source: 'compiler_version_string',
    pattern: /clang version|Apple clang|LLVM|__clang_call_terminate|\.llvm_addrsig/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'go',
    category: 'language-runtime',
    kind: 'go-runtime',
    source: 'go_runtime_marker',
    pattern: /Go build ID:|Go buildinf:|runtime\.goexit|runtime\.main|gopclntab|go1\.[0-9]+/i,
    confidence: 'high',
    weight: 5,
  },
  {
    family: 'rust',
    category: 'language-runtime',
    kind: 'rust-runtime',
    source: 'rust_runtime_marker',
    pattern: /rustc|rust_begin_unwind|core::panicking|panic_unwind|std::rt::lang_start|\.rustc/i,
    confidence: 'high',
    weight: 5,
  },
  {
    family: 'swift',
    category: 'language-runtime',
    kind: 'swift-runtime',
    source: 'swift_runtime_marker',
    pattern: /libswiftCore|swift_(?:retain|release)|__swift|_\$s[A-Za-z0-9_]+/i,
    confidence: 'high',
    weight: 5,
  },
  {
    family: 'delphi',
    category: 'language-runtime',
    kind: 'delphi-runtime',
    source: 'delphi_runtime_marker',
    pattern: /Borland Delphi|Embarcadero|Delphi|@SysInit|System\.@(?:LStr|UStr|Class)/i,
    confidence: 'high',
    weight: 5,
  },
  {
    family: 'dotnet',
    category: 'language-runtime',
    kind: 'clr-runtime',
    source: 'clr_marker',
    pattern: /BSJB|mscoree\.dll|System\.Reflection|\.NETCoreApp|mscorlib/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'zig',
    category: 'compiler',
    kind: 'zig-runtime',
    source: 'zig_marker',
    pattern: /\bzig\b|builtin\.zig|std\.start/i,
    confidence: 'medium',
    weight: 3,
  },
  {
    family: 'dlang',
    category: 'language-runtime',
    kind: 'd-runtime',
    source: 'dlang_marker',
    pattern: /\bDMD\b|\bLDC\b|druntime|_Dmain|core\.runtime/i,
    confidence: 'medium',
    weight: 3,
  },
  {
    family: 'lld',
    category: 'linker',
    kind: 'lld-linker',
    source: 'linker_string',
    pattern: /\bLLD\b|Linker: LLD|ld\.lld|lld-link/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'gnu-ld',
    category: 'linker',
    kind: 'gnu-linker',
    source: 'linker_string',
    pattern: /GNU ld|ld\.gold|gold linker|collect2/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'ms-link',
    category: 'linker',
    kind: 'ms-linker',
    source: 'linker_string',
    pattern: /Microsoft \(R\) Incremental Linker|LINK :|link\.exe/i,
    confidence: 'high',
    weight: 4,
  },
  {
    family: 'lto',
    category: 'optimization',
    kind: 'lto',
    source: 'lto_marker',
    pattern: /thinlto|\.llvm\.lto|__gnu_lto|lto\.tmp|LLVM bitcode/i,
    confidence: 'high',
    weight: 3,
  },
  {
    family: 'pgo',
    category: 'optimization',
    kind: 'pgo',
    source: 'pgo_marker',
    pattern: /__llvm_prf|__profc_|__profd_|PGO|Profile Guided|\.pgd\b/i,
    confidence: 'high',
    weight: 3,
  },
  {
    family: 'debug-build',
    category: 'optimization',
    kind: 'debug-runtime-checks',
    source: 'debug_runtime_marker',
    pattern:
      /_RTC_CheckEsp|_RTC_InitBase|assertion failed|AddressSanitizer|UndefinedBehaviorSanitizer/i,
    confidence: 'medium',
    weight: 2,
  },
]

function collectStringEvidence(
  strings: BinaryString[],
  sections: BinarySection[]
): CodegenEvidence[] {
  const evidence: CodegenEvidence[] = []
  for (const entry of strings) {
    for (const spec of STRING_PATTERNS) {
      if (!spec.pattern.test(entry.value)) continue
      addEvidence(evidence, {
        family: spec.family,
        category: spec.category,
        kind: spec.kind,
        value: entry.value.slice(0, 240),
        source: spec.source,
        offset: entry.offset,
        section: sectionNameForOffset(sections, entry.offset),
        confidence: spec.confidence,
        weight: spec.weight,
      })
    }
  }
  return evidence
}

function collectContainerEvidence(container: ContainerSummary, data: Buffer): CodegenEvidence[] {
  const evidence: CodegenEvidence[] = []
  if (container.pe?.rich_header_marker_present) {
    addEvidence(evidence, {
      family: 'msvc',
      category: 'compiler',
      kind: 'rich-header',
      value: 'PE Rich header marker present',
      source: 'pe_header',
      confidence: 'medium',
      weight: 3,
    })
  }
  if (container.pe?.codeview_marker_present) {
    addEvidence(evidence, {
      family: 'msvc',
      category: 'debug-metadata',
      kind: 'codeview',
      value: 'CodeView RSDS/NB10 marker present',
      source: 'pe_debug_directory_or_string',
      confidence: 'high',
      weight: 4,
    })
  }
  if (container.pe?.linker_version) {
    addEvidence(evidence, {
      family: 'pe-linker',
      category: 'linker',
      kind: 'pe-linker-version',
      value: `PE optional header linker version ${container.pe.linker_version}`,
      source: 'pe_optional_header',
      confidence: 'medium',
      weight: 2,
    })
  }
  if (container.elf?.has_comment) {
    addEvidence(evidence, {
      family: 'elf-comment',
      category: 'provenance',
      kind: 'elf-comment-section',
      value: '.comment section present',
      source: 'elf_section_table',
      confidence: 'medium',
      weight: 2,
    })
  }
  if (container.elf?.has_build_id) {
    addEvidence(evidence, {
      family: 'build-id',
      category: 'provenance',
      kind: 'gnu-build-id',
      value: '.note.gnu.build-id section present',
      source: 'elf_section_table',
      confidence: 'medium',
      weight: 2,
    })
  }

  const names = new Set(container.sections.map((section) => section.name))
  const sectionEvidence: Array<[string, string, string, string, Confidence, number]> = [
    ['.llvm_addrsig', 'clang', 'compiler', 'llvm-addrsig-section', 'high', 4],
    ['.llvm.call-graph-profile', 'clang', 'optimization', 'llvm-callgraph-profile', 'medium', 3],
    ['.gcc_except_table', 'gcc', 'compiler', 'gcc-exception-table', 'medium', 2],
    ['.eh_frame', 'gcc', 'compiler', 'eh-frame', 'low', 1],
    ['.pdata', 'msvc', 'compiler', 'pdata-unwind', 'low', 1],
    ['.xdata', 'msvc', 'compiler', 'xdata-unwind', 'low', 1],
    ['.gopclntab', 'go', 'language-runtime', 'go-pclntab-section', 'high', 5],
    ['.rustc', 'rust', 'language-runtime', 'rustc-section', 'high', 5],
    ['__swift5_types', 'swift', 'language-runtime', 'swift5-section', 'high', 5],
  ]
  for (const [name, family, category, kind, confidence, weight] of sectionEvidence) {
    if (!names.has(name)) continue
    addEvidence(evidence, {
      family,
      category,
      kind,
      value: `${name} section present`,
      source: 'section_table',
      section: name,
      confidence,
      weight,
    })
  }

  if (data.indexOf(Buffer.from([0x42, 0x43, 0xc0, 0xde])) >= 0) {
    addEvidence(evidence, {
      family: 'llvm',
      category: 'optimization',
      kind: 'embedded-llvm-bitcode',
      value: 'Embedded LLVM bitcode magic present',
      source: 'raw_magic_scan',
      confidence: 'high',
      weight: 4,
    })
  }

  return evidence
}

function scoreCandidates(
  evidence: CodegenEvidence[],
  category: 'compiler' | 'linker' | 'language-runtime'
): Array<Record<string, unknown>> {
  const buckets = new Map<string, CodegenEvidence[]>()
  for (const item of evidence) {
    if (item.category !== category) continue
    const bucket = buckets.get(item.family) ?? []
    bucket.push(item)
    buckets.set(item.family, bucket)
  }
  return Array.from(buckets.entries())
    .map(([family, items]) => {
      const score = items.reduce((total, item) => total + item.weight, 0)
      const highCount = items.filter((item) => item.confidence === 'high').length
      const confidence: Confidence =
        score >= 8 || highCount >= 2 ? 'high' : score >= 4 || items.length >= 2 ? 'medium' : 'low'
      return {
        family,
        confidence,
        score,
        evidence_count: items.length,
        evidence_ids: items.map((item) => item.id).slice(0, 32),
        evidence_kinds: Array.from(new Set(items.map((item) => item.kind))),
        candidate_only: true,
      }
    })
    .sort(
      (a, b) =>
        Number(b.score) - Number(a.score) || String(a.family).localeCompare(String(b.family))
    )
    .slice(0, 12)
}

function buildOptimizationHints(evidence: CodegenEvidence[]): Array<Record<string, unknown>> {
  const items = evidence.filter((item) => item.category === 'optimization')
  const byKind = new Map<string, CodegenEvidence[]>()
  for (const item of items) {
    const bucket = byKind.get(item.kind) ?? []
    bucket.push(item)
    byKind.set(item.kind, bucket)
  }
  return Array.from(byKind.entries())
    .map(([kind, bucket]) => ({
      kind,
      confidence: bucket.some((item) => item.confidence === 'high') ? 'high' : 'medium',
      evidence_count: bucket.length,
      evidence_ids: bucket.map((item) => item.id).slice(0, 24),
      interpretation:
        kind === 'lto'
          ? 'Link-time optimization evidence is present.'
          : kind === 'pgo'
            ? 'Profile-guided optimization evidence is present.'
            : kind === 'debug-runtime-checks'
              ? 'Debug or sanitizer runtime checks may be present.'
              : 'Optimization-related evidence is present.',
      candidate_only: true,
    }))
    .slice(0, 16)
}

function buildCodegenFeatures(
  evidence: CodegenEvidence[],
  container: ContainerSummary
): Array<Record<string, unknown>> {
  const features: Array<Record<string, unknown>> = []
  const names = new Set(container.sections.map((section) => section.name))
  const add = (
    name: string,
    present: boolean,
    source: string,
    detail?: Record<string, unknown>
  ) => {
    if (!present || features.length >= MAX_FEATURES) return
    features.push({ name, source, ...detail })
  }
  add('pe-rich-header-marker', Boolean(container.pe?.rich_header_marker_present), 'pe_header')
  add('pe-codeview-marker', Boolean(container.pe?.codeview_marker_present), 'pe_debug_metadata')
  add('elf-comment-section', Boolean(container.elf?.has_comment), 'elf_section_table')
  add('gnu-build-id-section', Boolean(container.elf?.has_build_id), 'elf_section_table')
  add('cxx-eh-frame', names.has('.eh_frame') || names.has('.gcc_except_table'), 'section_table')
  add('windows-unwind-pdata', names.has('.pdata') || names.has('.xdata'), 'section_table')
  add(
    'llvm-provenance',
    evidence.some((item) => item.family === 'clang' || item.family === 'llvm'),
    'evidence'
  )
  add(
    'go-runtime-provenance',
    evidence.some((item) => item.family === 'go'),
    'evidence'
  )
  add(
    'rust-runtime-provenance',
    evidence.some((item) => item.family === 'rust'),
    'evidence'
  )
  add(
    'swift-runtime-provenance',
    evidence.some((item) => item.family === 'swift'),
    'evidence'
  )
  add(
    'lto-marker',
    evidence.some((item) => item.kind === 'lto' || item.kind === 'embedded-llvm-bitcode'),
    'evidence'
  )
  add(
    'pgo-marker',
    evidence.some((item) => item.kind === 'pgo'),
    'evidence'
  )
  return features
}

function buildProvenanceMarkers(evidence: CodegenEvidence[]): Array<Record<string, unknown>> {
  return evidence
    .filter((item) =>
      ['provenance', 'debug-metadata', 'compiler', 'linker'].includes(item.category)
    )
    .map((item) => ({
      id: item.id,
      family: item.family,
      category: item.category,
      kind: item.kind,
      value: item.value,
      source: item.source,
      offset: item.offset,
      section: item.section,
      confidence: item.confidence,
    }))
    .slice(0, MAX_EVIDENCE)
}

function buildSectionLayout(container: ContainerSummary): Record<string, unknown> {
  const sectionNames = container.sections.map((section) => section.name)
  return {
    section_count: container.sections.length,
    section_names: sectionNames.slice(0, 128),
    common_codegen_sections: {
      eh_frame: sectionNames.includes('.eh_frame'),
      gcc_except_table: sectionNames.includes('.gcc_except_table'),
      pdata: sectionNames.includes('.pdata'),
      xdata: sectionNames.includes('.xdata'),
      llvm_addrsig: sectionNames.includes('.llvm_addrsig'),
      comment: sectionNames.includes('.comment'),
      build_id: sectionNames.includes('.note.gnu.build-id'),
      gopclntab: sectionNames.includes('.gopclntab'),
      rustc: sectionNames.includes('.rustc'),
      swift5: sectionNames.some((name) => name.startsWith('__swift5')),
    },
    linker_layout_hints: {
      pe_linker_version: container.pe?.linker_version,
      pe_section_count: container.pe?.section_count,
      elf_section_count: container.elf?.section_count,
      macho_kind: container.macho?.kind,
    },
  }
}

function buildRiskFlags(
  compilerCandidates: Array<Record<string, unknown>>,
  optimizationHints: Array<Record<string, unknown>>,
  evidence: CodegenEvidence[]
): Array<Record<string, unknown>> {
  const flags: Array<Record<string, unknown>> = []
  if (compilerCandidates.length === 0 && evidence.length === 0) {
    flags.push({
      id: 'no-codegen-evidence',
      severity: 'info',
      summary: 'No strong compiler/codegen evidence was detected in the bounded preview.',
    })
  }
  if (compilerCandidates.length >= 2) {
    flags.push({
      id: 'mixed-toolchain-candidates',
      severity: 'info',
      summary:
        'Multiple compiler families have evidence; this may reflect mixed objects, static linking, or library code.',
      families: compilerCandidates.map((candidate) => candidate.family).slice(0, 6),
    })
  }
  if (optimizationHints.some((item) => item.kind === 'lto')) {
    flags.push({
      id: 'lto-present',
      severity: 'info',
      summary: 'LTO evidence can reduce symbol locality and complicate source-level attribution.',
    })
  }
  if (optimizationHints.some((item) => item.kind === 'pgo')) {
    flags.push({
      id: 'pgo-present',
      severity: 'info',
      summary: 'PGO evidence may affect layout, hot/cold splitting, and function ordering.',
    })
  }
  if (evidence.some((item) => item.kind === 'debug-runtime-checks')) {
    flags.push({
      id: 'debug-or-sanitizer-runtime',
      severity: 'info',
      summary:
        'Debug runtime checks or sanitizer strings may indicate a non-release build or instrumented artifact.',
    })
  }
  return flags
}

function confidenceFromCandidates(
  compilerCandidates: Array<Record<string, unknown>>,
  runtimeHints: Array<Record<string, unknown>>,
  evidence: CodegenEvidence[]
): Confidence {
  const topScore = Math.max(
    0,
    ...compilerCandidates.map((candidate) => Number(candidate.score ?? 0)),
    ...runtimeHints.map((candidate) => Number(candidate.score ?? 0))
  )
  const highEvidence = evidence.filter((item) => item.confidence === 'high').length
  if (topScore >= 8 || highEvidence >= 3) return 'high'
  if (topScore >= 4 || evidence.length >= 3) return 'medium'
  return evidence.length ? 'low' : 'low'
}

function detectFormat(
  filename: string | undefined,
  container: ContainerSummary,
  evidence: CodegenEvidence[]
): { format: string; detectedBy: string[]; confidence: Confidence } {
  const detectedBy = new Set<string>()
  if (container.kind !== 'raw-codegen-preview') detectedBy.add(container.kind)
  if (container.pe?.rich_header_marker_present) detectedBy.add('pe-rich-header')
  if (container.pe?.codeview_marker_present) detectedBy.add('codeview')
  if (container.elf?.has_comment) detectedBy.add('elf-comment')
  if (container.elf?.has_build_id) detectedBy.add('gnu-build-id')
  for (const item of evidence) detectedBy.add(item.kind)
  if (filename && /\.(?:exe|dll|sys|so|dylib|o|obj|a|lib|ko)$/i.test(filename)) {
    detectedBy.add('native-binary-extension')
  }
  const language = evidence.find((item) => item.category === 'language-runtime')?.family
  const compiler = evidence.find((item) => item.category === 'compiler')?.family
  const format = language
    ? `${language}-codegen-fingerprint`
    : compiler
      ? `${compiler}-codegen-fingerprint`
      : `${container.kind}-codegen-fingerprint`
  const compilerCandidates = scoreCandidates(evidence, 'compiler')
  const runtimeHints = scoreCandidates(evidence, 'language-runtime')
  return {
    format,
    detectedBy: Array.from(detectedBy).slice(0, 64),
    confidence: confidenceFromCandidates(compilerCandidates, runtimeHints, evidence),
  }
}

function buildSummary(
  compilerCandidates: Array<Record<string, unknown>>,
  linkerCandidates: Array<Record<string, unknown>>,
  runtimeHints: Array<Record<string, unknown>>,
  optimizationHints: Array<Record<string, unknown>>,
  confidence: Confidence
): string {
  const topCompiler = compilerCandidates[0]?.family
  const topRuntime = runtimeHints[0]?.family
  const topLinker = linkerCandidates[0]?.family
  const top = topRuntime ?? topCompiler ?? topLinker ?? 'unknown toolchain'
  const extras = [
    topCompiler ? `compiler=${topCompiler}` : undefined,
    topLinker ? `linker=${topLinker}` : undefined,
    topRuntime ? `runtime=${topRuntime}` : undefined,
    optimizationHints.length
      ? `optimization=${optimizationHints.map((item) => item.kind).join(',')}`
      : undefined,
  ].filter(Boolean)
  return `Passive compiler/codegen fingerprint suggests ${top} with ${confidence} confidence${extras.length ? ` (${extras.join('; ')})` : ''}.`
}

export function buildCompilerCodegenFingerprintFromBuffer(
  data: Buffer,
  options: BuildOptions = {}
): CompilerCodegenFingerprint {
  const maxReadBytes = options.maxReadBytes ?? data.length
  const container = detectContainer(data, maxReadBytes)
  const strings = extractAsciiStrings(data)
  const evidence = [
    ...collectContainerEvidence(container, data),
    ...collectStringEvidence(strings, container.sections),
  ].slice(0, MAX_EVIDENCE)
  const compilerCandidates = scoreCandidates(evidence, 'compiler')
  const linkerCandidates = scoreCandidates(evidence, 'linker')
  const runtimeHints = scoreCandidates(evidence, 'language-runtime')
  const optimizationHints = buildOptimizationHints(evidence)
  const codegenFeatures = buildCodegenFeatures(evidence, container)
  const provenanceMarkers = buildProvenanceMarkers(evidence)
  const sectionLayout = buildSectionLayout(container)
  const formatInfo = detectFormat(options.filename, container, evidence)
  const riskFlags = buildRiskFlags(compilerCandidates, optimizationHints, evidence)

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: formatInfo.format,
    detected_by: formatInfo.detectedBy,
    confidence: formatInfo.confidence,
    size: options.totalSize,
    preview_size: data.length,
    container,
    compiler_candidates: compilerCandidates,
    linker_candidates: linkerCandidates,
    language_runtime_hints: runtimeHints,
    optimization_hints: optimizationHints,
    codegen_features: codegenFeatures,
    provenance_markers: provenanceMarkers,
    section_layout: sectionLayout,
    risk_flags: riskFlags,
    policy: {
      passive: true,
      no_execute: true,
      no_native_load: true,
      no_debugger: true,
      no_compiler_invocation: true,
      no_linker_invocation: true,
      no_external_tool: true,
      no_symbol_server_download: true,
      no_source_fetch: true,
      no_network: true,
      no_mutation: true,
    },
    summary: buildSummary(
      compilerCandidates,
      linkerCandidates,
      runtimeHints,
      optimizationHints,
      formatInfo.confidence
    ),
    recommended_next_tools: COMPILER_CODEGEN_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use native.debug.types.inventory or windows.debug.metadata.inspect to corroborate producer/debug provenance when available.',
      'Use sbom.provenance.graph and sample.family.cluster to compare toolchain evidence across related samples.',
      'Use compiler.packer.detect only for packer/protector attribution; this inventory focuses on codegen provenance.',
      'Escalate to backend-assisted disassembly only after reviewing passive evidence and workflow.search routing.',
    ],
    evidence_summary: {
      total_evidence: evidence.length,
      compiler_candidate_count: compilerCandidates.length,
      linker_candidate_count: linkerCandidates.length,
      language_runtime_candidate_count: runtimeHints.length,
      optimization_hint_count: optimizationHints.length,
      feature_count: codegenFeatures.length,
      bounded_preview: container.bounded_preview,
      candidate_only: true,
    },
    workflow_handoff: {
      static_corroboration: [
        'native.object.inventory',
        'native.debug.types.inventory',
        'windows.debug.metadata.inspect',
        'cpp.abi.layout.inventory',
        'sbom.provenance.graph',
      ],
      clustering_handoff: ['sample.family.cluster', 'analysis.evidence.graph'],
      packer_detector_boundary: {
        tool: 'compiler.packer.detect',
        use_for: 'packer/protector/compiler label cross-check only',
        this_tool_focus: 'code-generation and toolchain provenance evidence',
      },
      runtime_boundary: {
        required: false,
        guidance:
          'Runtime is not needed for this passive fingerprint. Use workflow.search to select explicit runtime plans only when behavior validation is requested.',
      },
    },
    quality_gates: {
      passive_static_inventory: true,
      sample_executed_by_tool: false,
      compiler_or_linker_invoked_by_tool: false,
      native_loader_invoked_by_tool: false,
      external_tool_invoked_by_tool: false,
      symbol_server_contacted_by_tool: false,
      source_fetched_by_tool: false,
      network_used_by_tool: false,
      bounded_read_bytes: data.length,
      max_read_bytes: maxReadBytes,
      truncated: options.totalSize ? options.totalSize > data.length : false,
      candidate_only: true,
    },
  }
}

export function createCompilerCodegenFingerprintHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (
    input: z.infer<typeof CompilerCodegenFingerprintInputSchema>
  ): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const parsed = CompilerCodegenFingerprintInputSchema.parse(input)
      if (!deps.resolvePrimarySamplePath) {
        return {
          ok: false,
          errors: [
            'resolvePrimarySamplePath dependency is unavailable for compiler.codegen.fingerprint',
          ],
          metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
        }
      }
      const resolved = await deps.resolvePrimarySamplePath(deps.workspaceManager, parsed.sample_id)
      const stat = await fs.stat(resolved.samplePath)
      const maxReadBytes = Math.min(parsed.max_read_bytes, MAX_PREVIEW_BYTES)
      const file = await fs.open(resolved.samplePath, 'r')
      let data: Buffer
      try {
        const readSize = Math.max(0, Math.min(stat.size, maxReadBytes))
        data = Buffer.alloc(readSize)
        await file.read(data, 0, readSize, 0)
      } finally {
        await file.close()
      }
      const inventory = buildCompilerCodegenFingerprintFromBuffer(data, {
        sampleId: parsed.sample_id,
        filename: path.basename(resolved.samplePath),
        maxReadBytes,
        totalSize: stat.size,
      })

      const artifacts: ArtifactRef[] = []
      if (parsed.persist_artifact !== false && deps.persistStaticAnalysisJsonArtifact) {
        const artifact = await deps.persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          parsed.sample_id,
          COMPILER_CODEGEN_FINGERPRINT_ARTIFACT_TYPE,
          'compiler-codegen-fingerprint',
          inventory,
          parsed.session_tag ?? null
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: inventory as unknown as Record<string, unknown>,
        artifacts,
        metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
      }
    }
  }
}
