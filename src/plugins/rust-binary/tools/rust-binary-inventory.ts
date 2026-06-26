/**
 * rust.binary.inventory - passive Rust binary metadata inventory.
 *
 * This tool reads bounded bytes and summarizes static evidence for Rust
 * language/runtime provenance: v0 and legacy mangled symbol candidates, rustc
 * and Cargo markers, crate/version/source path hints, panic/unwind profile,
 * allocator/runtime markers, target triples, and workflow handoff. It never
 * invokes rustc, cargo, external demanglers, native loaders, or runtime tools.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'rust.binary.inventory'
export const RUST_BINARY_INVENTORY_ARTIFACT_TYPE = 'rust_binary_inventory'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 8000
const MAX_SYMBOLS = 180
const MAX_EVIDENCE = 300
const MAX_CRATES = 120

type Confidence = 'low' | 'medium' | 'high'
type ContainerKind = 'elf' | 'pe' | 'macho' | 'archive' | 'rust-metadata' | 'raw'

const RUST_BINARY_EVIDENCE = [
  'symbols',
  'language-runtime',
  'provenance',
  'package-metadata',
  'panic',
  'allocator',
  'target',
  'workflow',
]

const RUST_BINARY_FOLLOW_UP_TOOLS = [
  'compiler.codegen.fingerprint',
  'native.object.inventory',
  'native.debug.types.inventory',
  'strings.extract',
  'sbom.provenance.graph',
  'sample.family.cluster',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const RUST_BINARY_SAFETY = [
  'passive',
  'no_execute',
  'no_native_load',
  'no_rustc_invocation',
  'no_cargo_invocation',
  'no_external_demangler',
  'no_external_tool',
  'no_symbol_server_download',
  'no_source_fetch',
  'no_network_by_default',
  'no_mutation',
]

const RustBinaryPolicySchema = z.object({
  passive: z.literal(true),
  read_only: z.literal(true),
  no_execute: z.literal(true),
  no_native_load: z.literal(true),
  no_rustc_invocation: z.literal(true),
  no_cargo_invocation: z.literal(true),
  no_external_demangler: z.literal(true),
  no_external_tool: z.literal(true),
  no_symbol_server_download: z.literal(true),
  no_source_fetch: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const RustBinaryInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.any()),
  rustc_candidates: z.array(z.record(z.any())),
  cargo_markers: z.array(z.record(z.any())),
  crate_candidates: z.array(z.record(z.any())),
  target_triples: z.array(z.record(z.any())),
  symbol_mangling: z.record(z.any()),
  runtime_markers: z.array(z.record(z.any())),
  panic_profile: z.record(z.any()),
  ecosystem_markers: z.array(z.record(z.any())),
  provenance_markers: z.array(z.record(z.any())),
  risk_flags: z.array(z.record(z.any())),
  policy: RustBinaryPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const RustBinaryInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive Rust binary inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist Rust inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const RustBinaryInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: RustBinaryInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const rustBinaryInventoryAspects = {
  formats: [
    'rust-binary',
    'rust',
    'rustc',
    'cargo',
    'cargo-crate',
    'rust-crate',
    'rust-mangled',
    'rust-v0-mangled',
    'rust-legacy-mangled',
    'panic-unwind',
    'panic-abort',
    'rlib',
    'rmeta',
    'rust-rlib',
    'rust-rmeta',
    'pe',
    'elf',
    'macho',
    'coff',
    'object',
    'static-lib',
    'native',
  ],
  platforms: ['windows', 'linux', 'macos', 'ios', 'android', 'wasm', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'riscv', 'wasm32'],
  execution: ['static', 'triage', 'correlation', 'workflow-plan'],
  safety: RUST_BINARY_SAFETY,
  capabilities: [
    'rust-binary-inventory',
    'rust-v0-mangled-symbol-inventory',
    'rust-legacy-mangled-symbol-inventory',
    'rustc-cargo-provenance-hints',
    'rust-crate-candidate-inventory',
    'rust-panic-unwind-profile',
    'rust-allocator-runtime-hints',
    'rust-target-triple-hints',
    'workflow-routing',
  ],
  evidence: RUST_BINARY_EVIDENCE,
  route_terms: [
    'rust binary',
    'rustc',
    'cargo crate',
    'rust mangled symbol',
    'rust v0 mangling',
    'legacy rust symbol',
    'core::panicking',
    'panic unwind',
    'panic abort',
    'rust allocator',
    'target triple',
  ],
  search: [
    'rust binary static inventory',
    'rustc cargo crate provenance',
    'rust v0 legacy mangled symbols',
    'rust panic unwind allocator target triples',
  ],
}

export const rustBinaryInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Rust binary metadata across ELF, PE, Mach-O, object, rlib, and rmeta artifacts using bounded static evidence for v0/legacy mangled symbols, rustc/Cargo/crate hints, panic/unwind profile, allocator/runtime markers, and target triples without demangling or execution.',
  inputSchema: RustBinaryInventoryInputSchema,
  outputSchema: RustBinaryInventoryOutputSchema,
  aspects: rustBinaryInventoryAspects,
  artifacts: [
    {
      type: RUST_BINARY_INVENTORY_ARTIFACT_TYPE,
      description:
        'Passive Rust binary language/runtime provenance, crate, mangling, panic, and target inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: RUST_BINARY_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [RUST_BINARY_INVENTORY_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'rust.binary-static-inventory',
      title: 'Passive Rust binary inventory',
      description:
        'Inventory Rust language/runtime metadata, v0 and legacy mangled symbol candidates, rustc/Cargo/crate hints, panic/unwind profile, allocator markers, and target triples before routing to compiler provenance, debug type, SBOM, clustering, evidence graph, and reporting tools.',
      startsWith: [TOOL_NAME],
      nextTools: RUST_BINARY_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [RUST_BINARY_INVENTORY_ARTIFACT_TYPE],
      evidence: RUST_BINARY_EVIDENCE,
      safety: RUST_BINARY_SAFETY,
    },
  ],
}

export type RustBinaryInventory = z.infer<typeof RustBinaryInventorySchema>

type BuildOptions = {
  sampleId?: string
  filename?: string
  maxReadBytes?: number
  totalSize?: number
}

type StringEvidence = {
  value: string
  offset?: number
}

type RustEvidence = {
  id: string
  category: string
  value: string
  source: string
  confidence: Confidence
  offset?: number
  details?: Record<string, unknown>
}

const TARGET_TRIPLE_RE =
  /\b(?:x86_64|i686|aarch64|armv7|thumbv7em|riscv64gc|riscv64|wasm32|wasm64)-(?:unknown|pc|apple|linux|wrs|fortanix|uwp|none|uefi|nintendo|sony|fuchsia|redox|espressif)-(?:linux-gnu|linux-musl|windows-msvc|windows-gnu|darwin|ios|android|unknown|none|elf|sgx|uefi|fuchsia|redox|wasi|wasip1|wasip2)\b/g
const RUSTC_RE = /\brustc\s+(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?)/gi
const CARGO_PACKAGE_RE = /\b([A-Za-z0-9_.-]+)\s+v(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?)\b/g
const CARGO_REGISTRY_RE =
  /(?:^|[\\/])(?:\.cargo[\\/])?registry[\\/]src[\\/][^\\/]+[\\/]([A-Za-z0-9_.-]+)-(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?)(?:[\\/]|$)/gi
const RUST_SOURCE_PATH_RE =
  /(?:^|[\\/])(?:src|library)[\\/]([A-Za-z0-9_.-]+)[\\/](?:src[\\/])?([A-Za-z0-9_.-]+\.rs)\b/gi
const V0_MANGLED_RE = /(?:^|[^A-Za-z0-9_])(_R[A-Za-z0-9_.$]{8,})/g
const LEGACY_MANGLED_PREFIX = '_ZN'
const LEGACY_MANGLED_HASH_PREFIX = '17h'
const LEGACY_MANGLED_HASH_LENGTH = 16
const LEGACY_MANGLED_MAX_SYMBOL_LENGTH = 512
const LEGACY_MANGLED_MAX_SEGMENTS = 64
const LEGACY_MANGLED_MAX_SEGMENT_LENGTH = 240

const RUNTIME_MARKERS = [
  { id: 'std.lang-start', pattern: 'std::rt::lang_start', category: 'runtime' },
  { id: 'core.panicking', pattern: 'core::panicking', category: 'panic' },
  { id: 'rust.begin-unwind', pattern: 'rust_begin_unwind', category: 'panic' },
  { id: 'rust.eh-personality', pattern: 'rust_eh_personality', category: 'panic' },
  { id: 'rust.alloc', pattern: '__rust_alloc', category: 'allocator' },
  { id: 'rust.dealloc', pattern: '__rust_dealloc', category: 'allocator' },
  { id: 'rust.realloc', pattern: '__rust_realloc', category: 'allocator' },
  { id: 'rust.rdl-alloc', pattern: '__rdl_alloc', category: 'allocator' },
  { id: 'rust.oom', pattern: 'rust_oom', category: 'allocator' },
  { id: 'alloc.vec', pattern: 'alloc::vec', category: 'runtime' },
  { id: 'core.fmt', pattern: 'core::fmt', category: 'runtime' },
]

const ECOSYSTEM_MARKERS = [
  { id: 'tokio', patterns: ['tokio::runtime', 'tokio::task', 'tokio::net'] },
  { id: 'serde', patterns: ['serde::de', 'serde::ser', 'serde_json'] },
  { id: 'reqwest', patterns: ['reqwest::', 'hyper::client'] },
  { id: 'clap', patterns: ['clap_builder', 'clap::parser'] },
  { id: 'anyhow', patterns: ['anyhow::Error'] },
  { id: 'tracing', patterns: ['tracing_core', 'tracing_subscriber'] },
  { id: 'openssl', patterns: ['openssl::ssl', 'rustls::'] },
  { id: 'wasm-bindgen', patterns: ['wasm_bindgen', '__wbindgen'] },
]

const CORE_CRATES = new Set(['std', 'core', 'alloc', 'proc_macro', 'test'])

const ELF_MACHINES: Record<number, string> = {
  3: 'x86',
  8: 'mips',
  20: 'ppc',
  40: 'arm',
  62: 'x64',
  183: 'arm64',
  243: 'riscv',
}

const COFF_MACHINES: Record<number, string> = {
  0x014c: 'x86',
  0x8664: 'x64',
  0x01c0: 'arm',
  0x01c4: 'arm',
  0xaa64: 'arm64',
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items.filter(Boolean)))
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  if (base.endsWith('.tar.gz')) return 'tar.gz'
  return base.slice(base.lastIndexOf('.') + 1)
}

function extractStrings(data: Buffer): StringEvidence[] {
  const results: StringEvidence[] = []
  let start = -1
  for (let i = 0; i <= data.length; i += 1) {
    const byte = i < data.length ? data[i] : 0
    const printable = byte >= 0x20 && byte <= 0x7e
    if (printable && start < 0) start = i
    if ((!printable || i === data.length) && start >= 0) {
      if (i - start >= 4) {
        results.push({ value: data.subarray(start, i).toString('ascii'), offset: start })
        if (results.length >= MAX_STRINGS) break
      }
      start = -1
    }
  }
  return results
}

function readAscii(data: Buffer, offset: number, size: number): string {
  return data
    .subarray(offset, Math.min(data.length, offset + size))
    .toString('ascii')
    .replace(/\0.*$/g, '')
}

function readElfHeader(data: Buffer): Record<string, unknown> {
  if (data.length < 20 || data.subarray(0, 4).toString('binary') !== '\x7fELF') return {}
  const is64 = data[4] === 2
  const endian = data[5] === 2 ? 'be' : 'le'
  const readUInt16 = (offset: number) =>
    endian === 'be' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
  const type = readUInt16(16)
  const machineRaw = readUInt16(18)
  return {
    kind: 'elf',
    format_detail: `${is64 ? 'elf64' : 'elf32'}-${endian}`,
    type,
    arch: ELF_MACHINES[machineRaw] ?? `elf-machine-${machineRaw}`,
  }
}

function readPeHeader(data: Buffer): Record<string, unknown> {
  if (data.length < 0x40 || data.subarray(0, 2).toString('ascii') !== 'MZ') return {}
  const peOffset = data.readUInt32LE(0x3c)
  if (peOffset <= 0 || peOffset + 24 > data.length) return { kind: 'pe', format_detail: 'mz' }
  if (data.subarray(peOffset, peOffset + 4).toString('binary') !== 'PE\0\0') {
    return { kind: 'pe', format_detail: 'mz' }
  }
  const machineRaw = data.readUInt16LE(peOffset + 4)
  const optionalMagic = peOffset + 24 + 2 <= data.length ? data.readUInt16LE(peOffset + 24) : 0
  return {
    kind: 'pe',
    format_detail: optionalMagic === 0x20b ? 'pe32+' : optionalMagic === 0x10b ? 'pe32' : 'pe',
    arch: COFF_MACHINES[machineRaw] ?? `coff-machine-${machineRaw}`,
  }
}

function readMachOHeader(data: Buffer): Record<string, unknown> {
  if (data.length < 16) return {}
  const magic = data.readUInt32LE(0)
  if (![0xfeedface, 0xfeedfacf, 0xcafebabe, 0xbebafeca].includes(magic)) return {}
  const cpu = magic === 0xcafebabe || magic === 0xbebafeca ? 0 : data.readUInt32LE(4)
  const arch =
    cpu === 0x01000007
      ? 'x64'
      : cpu === 0x0100000c
        ? 'arm64'
        : cpu === 7
          ? 'x86'
          : cpu === 12
            ? 'arm'
            : magic === 0xcafebabe || magic === 0xbebafeca
              ? 'fat'
              : `macho-cpu-${cpu}`
  return {
    kind: 'macho',
    format_detail:
      magic === 0xfeedfacf ? 'mach-o-64' : magic === 0xfeedface ? 'mach-o-32' : 'mach-o-fat',
    arch,
  }
}

function detectContainer(data: Buffer, filename?: string): Record<string, unknown> {
  const ext = extensionOf(filename)
  if (ext === 'rmeta') {
    return { kind: 'rust-metadata', format_detail: 'rmeta', arch: 'unknown', bounded_preview: true }
  }
  if (ext === 'rlib') {
    return { kind: 'archive', format_detail: 'rlib', arch: 'unknown', bounded_preview: true }
  }
  if (data.subarray(0, 8).toString('ascii') === '!<arch>\n') {
    return {
      kind: 'archive',
      format_detail: ext === 'a' ? 'ar' : 'archive',
      arch: 'unknown',
      bounded_preview: true,
    }
  }
  const elf = readElfHeader(data)
  if (elf.kind) return { ...elf, bounded_preview: true }
  const pe = readPeHeader(data)
  if (pe.kind) return { ...pe, bounded_preview: true }
  const macho = readMachOHeader(data)
  if (macho.kind) return { ...macho, bounded_preview: true }
  return { kind: 'raw', format_detail: ext || 'raw-bytes', arch: 'unknown', bounded_preview: true }
}

function addEvidence(
  evidence: RustEvidence[],
  id: string,
  category: string,
  value: string,
  source: string,
  confidence: Confidence,
  offset?: number,
  details?: Record<string, unknown>
) {
  if (evidence.length >= MAX_EVIDENCE) return
  const key = `${id}:${value}:${source}`
  if (evidence.some((item) => `${item.id}:${item.value}:${item.source}` === key)) return
  evidence.push({ id, category, value, source, confidence, offset, details })
}

function collectRegexMatches(
  evidence: RustEvidence[],
  strings: StringEvidence[],
  regex: RegExp,
  id: string,
  category: string,
  source: string,
  confidence: Confidence,
  valueGroup = 0
) {
  for (const item of strings) {
    regex.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = regex.exec(item.value)) && evidence.length < MAX_EVIDENCE) {
      addEvidence(
        evidence,
        id,
        category,
        match[valueGroup],
        source,
        confidence,
        item.offset === undefined ? undefined : item.offset + match.index
      )
    }
  }
}

function isAsciiDigit(value: string, index: number): boolean {
  const code = value.charCodeAt(index)
  return code >= 48 && code <= 57
}

function isHexDigit(value: string, index: number): boolean {
  const code = value.charCodeAt(index)
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102)
}

function isLegacySegmentChar(value: string, index: number): boolean {
  const code = value.charCodeAt(index)
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 36 ||
    code === 46 ||
    code === 95
  )
}

function hasLegacyHashSuffix(value: string, index: number): boolean {
  if (!value.startsWith(LEGACY_MANGLED_HASH_PREFIX, index)) return false
  const hashStart = index + LEGACY_MANGLED_HASH_PREFIX.length
  const hashEnd = hashStart + LEGACY_MANGLED_HASH_LENGTH
  if (hashEnd >= value.length || value[hashEnd] !== 'E') return false
  for (let cursor = hashStart; cursor < hashEnd; cursor += 1) {
    if (!isHexDigit(value, cursor)) return false
  }
  return true
}

function findLegacyMangledSymbols(value: string): Array<{ value: string; index: number }> {
  const matches: Array<{ value: string; index: number }> = []
  let searchFrom = 0

  while (searchFrom < value.length && matches.length < MAX_EVIDENCE) {
    const start = value.indexOf(LEGACY_MANGLED_PREFIX, searchFrom)
    if (start === -1) break

    let cursor = start + LEGACY_MANGLED_PREFIX.length
    let segments = 0
    const maxEnd = Math.min(value.length, start + LEGACY_MANGLED_MAX_SYMBOL_LENGTH)
    let matchedEnd: number | undefined

    while (cursor < maxEnd && segments < LEGACY_MANGLED_MAX_SEGMENTS) {
      const lengthStart = cursor
      while (cursor < maxEnd && isAsciiDigit(value, cursor)) cursor += 1
      if (cursor === lengthStart) break

      const segmentLength = Number(value.slice(lengthStart, cursor))
      if (
        !Number.isSafeInteger(segmentLength) ||
        segmentLength <= 0 ||
        segmentLength > LEGACY_MANGLED_MAX_SEGMENT_LENGTH
      ) {
        break
      }

      const segmentEnd = cursor + segmentLength
      if (segmentEnd > maxEnd) break

      let validSegment = true
      for (let index = cursor; index < segmentEnd; index += 1) {
        if (!isLegacySegmentChar(value, index)) {
          validSegment = false
          break
        }
      }
      if (!validSegment) break

      cursor = segmentEnd
      segments += 1
      if (hasLegacyHashSuffix(value, cursor)) {
        matchedEnd =
          cursor + LEGACY_MANGLED_HASH_PREFIX.length + LEGACY_MANGLED_HASH_LENGTH + 'E'.length
        break
      }
    }

    if (matchedEnd !== undefined) {
      matches.push({ value: value.slice(start, matchedEnd), index: start })
      searchFrom = matchedEnd
    } else {
      searchFrom = start + LEGACY_MANGLED_PREFIX.length
    }
  }

  return matches
}

function collectLegacyMangledMatches(evidence: RustEvidence[], strings: StringEvidence[]) {
  for (const item of strings) {
    for (const match of findLegacyMangledSymbols(item.value)) {
      addEvidence(
        evidence,
        'rust.legacy-mangled-symbol',
        'symbols',
        match.value,
        'string',
        'high',
        item.offset === undefined ? undefined : item.offset + match.index
      )
    }
  }
}

function collectRustEvidence(strings: StringEvidence[]): RustEvidence[] {
  const evidence: RustEvidence[] = []
  collectRegexMatches(evidence, strings, RUSTC_RE, 'rustc.version', 'provenance', 'string', 'high')
  collectRegexMatches(
    evidence,
    strings,
    CARGO_REGISTRY_RE,
    'cargo.registry-crate',
    'package-metadata',
    'string',
    'high'
  )
  collectRegexMatches(
    evidence,
    strings,
    CARGO_PACKAGE_RE,
    'cargo.package-version',
    'package-metadata',
    'string',
    'medium'
  )
  collectRegexMatches(
    evidence,
    strings,
    RUST_SOURCE_PATH_RE,
    'rust.source-path',
    'provenance',
    'string',
    'medium'
  )
  collectRegexMatches(
    evidence,
    strings,
    TARGET_TRIPLE_RE,
    'rust.target-triple',
    'target',
    'string',
    'high'
  )
  collectLegacyMangledMatches(evidence, strings)
  collectRegexMatches(
    evidence,
    strings,
    V0_MANGLED_RE,
    'rust.v0-mangled-symbol',
    'symbols',
    'string',
    'high',
    1
  )

  for (const item of strings) {
    const value = item.value
    for (const marker of RUNTIME_MARKERS) {
      if (value.includes(marker.pattern)) {
        addEvidence(
          evidence,
          marker.id,
          marker.category,
          marker.pattern,
          'string',
          'high',
          item.offset === undefined ? undefined : item.offset + value.indexOf(marker.pattern)
        )
      }
    }
    for (const marker of ECOSYSTEM_MARKERS) {
      const matched = marker.patterns.find((pattern) => value.includes(pattern))
      if (matched) {
        addEvidence(
          evidence,
          `crate.${marker.id}`,
          'package-metadata',
          matched,
          'string',
          'medium',
          item.offset === undefined ? undefined : item.offset + value.indexOf(matched),
          { crate: marker.id }
        )
      }
    }
    if (value.includes('panicked at')) {
      addEvidence(
        evidence,
        'rust.panic-location',
        'panic',
        value.slice(0, 160),
        'string',
        'medium',
        item.offset
      )
    }
    if (value.includes('panic_unwind')) {
      addEvidence(
        evidence,
        'rust.panic-unwind',
        'panic',
        'panic_unwind',
        'string',
        'high',
        item.offset
      )
    }
    if (value.includes('panic_abort')) {
      addEvidence(
        evidence,
        'rust.panic-abort',
        'panic',
        'panic_abort',
        'string',
        'high',
        item.offset
      )
    }
    if (value.includes('Cargo.toml') || value.includes('Cargo.lock')) {
      addEvidence(
        evidence,
        'cargo.manifest',
        'package-metadata',
        value.slice(0, 160),
        'string',
        'medium',
        item.offset
      )
    }
  }

  return evidence
}

function parseLegacySegments(symbol: string): string[] {
  const trimmed = symbol.replace(/^_ZN/, '').replace(/17h[0-9a-fA-F]{16}E$/, '')
  const segments: string[] = []
  let index = 0
  while (index < trimmed.length && segments.length < 12) {
    const digits = /^\d+/.exec(trimmed.slice(index))
    if (!digits) break
    const length = Number(digits[0])
    index += digits[0].length
    if (!Number.isFinite(length) || length <= 0 || index + length > trimmed.length) break
    segments.push(trimmed.slice(index, index + length))
    index += length
  }
  return segments
}

function crateNameFromPath(value: string): { name?: string; version?: string; source?: string } {
  CARGO_REGISTRY_RE.lastIndex = 0
  const registry = CARGO_REGISTRY_RE.exec(value)
  if (registry)
    return {
      name: registry[1].replace(/-/g, '_'),
      version: registry[2],
      source: 'cargo-registry-path',
    }

  RUST_SOURCE_PATH_RE.lastIndex = 0
  const sourcePath = RUST_SOURCE_PATH_RE.exec(value)
  if (sourcePath) return { name: sourcePath[1].replace(/-/g, '_'), source: 'rust-source-path' }

  return {}
}

function buildRustcCandidates(evidence: RustEvidence[]) {
  const candidates = new Map<string, Record<string, unknown>>()
  for (const item of evidence.filter((entry) => entry.id === 'rustc.version')) {
    RUSTC_RE.lastIndex = 0
    const match = RUSTC_RE.exec(item.value)
    const version = match?.[1] ?? item.value.replace(/^rustc\s+/i, '')
    candidates.set(version, {
      version,
      source: item.source,
      confidence: item.confidence,
      evidence: item.value,
      offset: item.offset,
    })
  }
  return Array.from(candidates.values())
}

function buildCargoMarkers(evidence: RustEvidence[]) {
  return evidence
    .filter((item) => item.id.startsWith('cargo.'))
    .slice(0, 80)
    .map((item) => ({
      id: item.id,
      value: item.value,
      confidence: item.confidence,
      offset: item.offset,
    }))
}

function buildCrateCandidates(evidence: RustEvidence[], strings: StringEvidence[]) {
  const counts = new Map<
    string,
    { name: string; version?: string; sources: Set<string>; count: number }
  >()

  function add(name: string, source: string, version?: string) {
    const normalized = name.replace(/-/g, '_').replace(/[^A-Za-z0-9_]/g, '')
    if (!normalized || normalized.length < 2) return
    const existing = counts.get(normalized) ?? {
      name: normalized,
      version,
      sources: new Set<string>(),
      count: 0,
    }
    existing.count += 1
    if (version && !existing.version) existing.version = version
    existing.sources.add(source)
    counts.set(normalized, existing)
  }

  for (const item of evidence) {
    if (item.id === 'rust.legacy-mangled-symbol') {
      const [first] = parseLegacySegments(item.value)
      if (first) add(first, 'legacy-mangled-symbol')
    }
    if (item.id === 'rust.source-path' || item.id === 'cargo.registry-crate') {
      const parsed = crateNameFromPath(item.value)
      if (parsed.name) add(parsed.name, parsed.source ?? item.id, parsed.version)
    }
    if (item.details?.crate && typeof item.details.crate === 'string') {
      add(item.details.crate, 'ecosystem-marker')
    }
  }

  for (const item of strings) {
    for (const segment of item.value.match(
      /\b(?:std|core|alloc|proc_macro|test)::[A-Za-z0-9_:]+/g
    ) ?? []) {
      add(segment.slice(0, segment.indexOf('::')), 'rust-path')
    }
  }

  return Array.from(counts.values())
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, MAX_CRATES)
    .map((item) => ({
      name: item.name,
      version: item.version,
      sources: Array.from(item.sources),
      count: item.count,
      first_party_candidate: !CORE_CRATES.has(item.name) && item.count >= 2,
      confidence: item.version || item.count >= 3 ? 'high' : item.count >= 2 ? 'medium' : 'low',
    }))
}

function buildTargetTriples(evidence: RustEvidence[]) {
  const triples = unique(
    evidence.filter((item) => item.id === 'rust.target-triple').map((item) => item.value)
  )
  return triples.map((triple) => ({
    triple,
    platform: triple.includes('windows')
      ? 'windows'
      : triple.includes('apple')
        ? 'apple'
        : triple.includes('linux')
          ? 'linux'
          : triple.includes('wasi') || triple.startsWith('wasm')
            ? 'wasm'
            : triple.includes('android')
              ? 'android'
              : 'unknown',
    confidence: 'high',
  }))
}

function buildSymbolMangling(evidence: RustEvidence[]) {
  const legacy = evidence
    .filter((item) => item.id === 'rust.legacy-mangled-symbol')
    .slice(0, MAX_SYMBOLS)
  const v0 = evidence.filter((item) => item.id === 'rust.v0-mangled-symbol').slice(0, MAX_SYMBOLS)
  return {
    legacy_count: legacy.length,
    v0_count: v0.length,
    total_count: legacy.length + v0.length,
    legacy_examples: legacy.slice(0, 10).map((item) => item.value),
    v0_examples: v0.slice(0, 10).map((item) => item.value),
    demangling_performed: false,
    external_demangler_invoked: false,
    notes:
      'Symbols are reported as candidates only. This tool intentionally does not invoke rustfilt, rustc, llvm-cxxfilt, or external demanglers.',
  }
}

function buildRuntimeMarkers(evidence: RustEvidence[]) {
  return evidence
    .filter((item) => ['runtime', 'allocator'].includes(item.category))
    .slice(0, 100)
    .map((item) => ({
      id: item.id,
      category: item.category,
      value: item.value,
      confidence: item.confidence,
      offset: item.offset,
    }))
}

function buildPanicProfile(evidence: RustEvidence[]) {
  const panicEvidence = evidence.filter((item) => item.category === 'panic')
  const hasUnwind = panicEvidence.some((item) =>
    ['rust.eh-personality', 'rust.panic-unwind'].includes(item.id)
  )
  const hasAbort = panicEvidence.some((item) => item.id === 'rust.panic-abort')
  return {
    panic_markers: panicEvidence.slice(0, 80).map((item) => ({
      id: item.id,
      value: item.value,
      confidence: item.confidence,
      offset: item.offset,
    })),
    unwind_candidate: hasUnwind,
    abort_candidate: hasAbort,
    panic_runtime: hasAbort && !hasUnwind ? 'panic-abort' : hasUnwind ? 'panic-unwind' : 'unknown',
    candidate_only: true,
  }
}

function buildEcosystemMarkers(evidence: RustEvidence[]) {
  return evidence
    .filter((item) => item.id.startsWith('crate.'))
    .slice(0, 80)
    .map((item) => ({
      crate: item.details?.crate ?? item.id.replace(/^crate\./, ''),
      marker: item.value,
      confidence: item.confidence,
      offset: item.offset,
    }))
}

function buildProvenanceMarkers(evidence: RustEvidence[]) {
  return evidence
    .filter((item) => ['provenance', 'package-metadata', 'target'].includes(item.category))
    .slice(0, 140)
    .map((item) => ({
      id: item.id,
      category: item.category,
      value: item.value,
      confidence: item.confidence,
      offset: item.offset,
    }))
}

function buildRiskFlags(
  symbolMangling: ReturnType<typeof buildSymbolMangling>,
  panicProfile: ReturnType<typeof buildPanicProfile>,
  cargoMarkers: Array<Record<string, unknown>>,
  crateCandidates: Array<Record<string, unknown>>,
  rustcCandidates: Array<Record<string, unknown>>
) {
  const flags: Array<Record<string, unknown>> = []
  if (symbolMangling.total_count === 0 && (panicProfile.panic_markers as unknown[]).length > 0) {
    flags.push({
      id: 'rust.stripped-symbols-likely',
      severity: 'info',
      description:
        'Rust panic/runtime evidence exists but no Rust mangled symbols were observed in the bounded preview.',
    })
  }
  if (panicProfile.abort_candidate) {
    flags.push({
      id: 'rust.panic-abort-candidate',
      severity: 'info',
      description:
        'panic_abort evidence may reduce unwind metadata available for static call recovery.',
    })
  }
  if (cargoMarkers.length === 0 && crateCandidates.some((item) => item.first_party_candidate)) {
    flags.push({
      id: 'rust.crate-provenance-incomplete',
      severity: 'info',
      description:
        'Crate names were inferred from symbols or paths, but Cargo registry/package metadata was not observed.',
    })
  }
  if (rustcCandidates.length === 0) {
    flags.push({
      id: 'rust.rustc-version-missing',
      severity: 'info',
      description: 'No rustc version string was found in the bounded preview.',
    })
  }
  return flags
}

function detectFormat(
  container: Record<string, unknown>,
  filename: string | undefined,
  evidence: RustEvidence[],
  symbolMangling: ReturnType<typeof buildSymbolMangling>
) {
  const kind = (container.kind as ContainerKind | undefined) ?? 'raw'
  const hasRust = evidence.length > 0 || symbolMangling.total_count > 0
  const ext = extensionOf(filename)
  const format =
    ext === 'rlib'
      ? 'rust-rlib-inventory'
      : ext === 'rmeta'
        ? 'rust-rmeta-inventory'
        : kind === 'elf'
          ? 'elf-rust-binary-inventory'
          : kind === 'pe'
            ? 'pe-rust-binary-inventory'
            : kind === 'macho'
              ? 'macho-rust-binary-inventory'
              : kind === 'archive'
                ? 'rust-archive-inventory'
                : hasRust
                  ? 'rust-binary-candidate'
                  : 'rust-binary-unconfirmed'

  const strongEvidence = evidence.filter((item) => item.confidence === 'high').length
  const confidence: Confidence =
    symbolMangling.total_count >= 2 || strongEvidence >= 3
      ? 'high'
      : symbolMangling.total_count > 0 || strongEvidence > 0 || evidence.length >= 3
        ? 'medium'
        : 'low'

  return {
    format,
    confidence,
    detectedBy: unique([
      `container:${kind}`,
      container.format_detail ? `format:${container.format_detail}` : '',
      container.arch ? `arch:${container.arch}` : '',
      ext ? `extension:${ext}` : '',
      symbolMangling.v0_count > 0 ? 'rust-v0-mangled-symbol' : '',
      symbolMangling.legacy_count > 0 ? 'rust-legacy-mangled-symbol' : '',
      ...evidence.slice(0, 20).map((item) => item.id),
    ]).slice(0, 64),
  }
}

function buildSummary(
  format: string,
  confidence: Confidence,
  symbolMangling: ReturnType<typeof buildSymbolMangling>,
  crateCandidates: Array<Record<string, unknown>>,
  rustcCandidates: Array<Record<string, unknown>>,
  panicProfile: ReturnType<typeof buildPanicProfile>
) {
  const topRustc = rustcCandidates[0]?.version
  const topCrates = crateCandidates
    .slice(0, 3)
    .map((item) => item.name)
    .join(',')
  return `Passive ${format} found ${symbolMangling.total_count} Rust mangled symbol candidate(s), ${crateCandidates.length} crate hint(s), ${rustcCandidates.length} rustc version hint(s), and ${panicProfile.panic_runtime} panic profile with ${confidence} confidence${topRustc ? ` (rustc=${topRustc})` : ''}${topCrates ? ` (crates=${topCrates})` : ''}.`
}

export function buildRustBinaryInventoryFromBuffer(
  data: Buffer,
  options: BuildOptions = {}
): RustBinaryInventory {
  const maxReadBytes = options.maxReadBytes ?? data.length
  const strings = extractStrings(data)
  const container = detectContainer(data, options.filename)
  const evidence = collectRustEvidence(strings)
  const symbolMangling = buildSymbolMangling(evidence)
  const rustcCandidates = buildRustcCandidates(evidence)
  const cargoMarkers = buildCargoMarkers(evidence)
  const crateCandidates = buildCrateCandidates(evidence, strings)
  const targetTriples = buildTargetTriples(evidence)
  const runtimeMarkers = buildRuntimeMarkers(evidence)
  const panicProfile = buildPanicProfile(evidence)
  const ecosystemMarkers = buildEcosystemMarkers(evidence)
  const provenanceMarkers = buildProvenanceMarkers(evidence)
  const formatInfo = detectFormat(container, options.filename, evidence, symbolMangling)
  const riskFlags = buildRiskFlags(
    symbolMangling,
    panicProfile,
    cargoMarkers,
    crateCandidates,
    rustcCandidates
  )

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: formatInfo.format,
    detected_by: formatInfo.detectedBy,
    confidence: formatInfo.confidence,
    size: options.totalSize,
    preview_size: data.length,
    container,
    rustc_candidates: rustcCandidates,
    cargo_markers: cargoMarkers,
    crate_candidates: crateCandidates,
    target_triples: targetTriples,
    symbol_mangling: symbolMangling,
    runtime_markers: runtimeMarkers,
    panic_profile: panicProfile,
    ecosystem_markers: ecosystemMarkers,
    provenance_markers: provenanceMarkers,
    risk_flags: riskFlags,
    policy: {
      passive: true,
      read_only: true,
      no_execute: true,
      no_native_load: true,
      no_rustc_invocation: true,
      no_cargo_invocation: true,
      no_external_demangler: true,
      no_external_tool: true,
      no_symbol_server_download: true,
      no_source_fetch: true,
      no_network: true,
      no_mutation: true,
    },
    summary: buildSummary(
      formatInfo.format,
      formatInfo.confidence,
      symbolMangling,
      crateCandidates,
      rustcCandidates,
      panicProfile
    ),
    recommended_next_tools: RUST_BINARY_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use compiler.codegen.fingerprint to correlate Rust language-runtime hints with compiler, linker, LTO, and debug provenance.',
      'Use native.debug.types.inventory and native.object.inventory to corroborate DWARF/CodeView/object evidence when present.',
      'Use sbom.provenance.graph and sample.family.cluster to compare crate and rustc hints across related samples.',
      'Keep demangling, execution, sandboxing, and dynamic behavior validation as explicit follow-up workflows; this tool does not invoke external demanglers or runtimes.',
    ],
    evidence_summary: {
      total_evidence: evidence.length,
      rustc_candidate_count: rustcCandidates.length,
      cargo_marker_count: cargoMarkers.length,
      crate_candidate_count: crateCandidates.length,
      target_triple_count: targetTriples.length,
      runtime_marker_count: runtimeMarkers.length,
      ecosystem_marker_count: ecosystemMarkers.length,
      bounded_preview: true,
      candidate_only: true,
    },
    workflow_handoff: {
      static_corroboration: [
        'compiler.codegen.fingerprint',
        'native.object.inventory',
        'native.debug.types.inventory',
        'strings.extract',
      ],
      provenance_correlation: ['sbom.provenance.graph', 'sample.family.cluster'],
      evidence_correlation: ['analysis.evidence.graph', 'report.generate'],
      demangler_boundary: {
        external_demangler_required_for_full_names: true,
        demangling_performed_by_this_tool: false,
        disallowed_by_this_tool: ['rustfilt', 'rustc', 'llvm-cxxfilt', 'c++filt'],
      },
      runtime_boundary: {
        required: false,
        guidance:
          'Runtime is not needed for this passive Rust inventory. Use workflow.search to select explicit runtime plans only when behavior validation is requested.',
      },
    },
    quality_gates: {
      passive_static_inventory: true,
      bounded_read_bytes: data.length,
      max_read_bytes: maxReadBytes,
      sample_executed_by_tool: false,
      native_loader_invoked_by_tool: false,
      rustc_invoked_by_tool: false,
      cargo_invoked_by_tool: false,
      external_demangler_invoked_by_tool: false,
      external_tool_invoked_by_tool: false,
      symbol_server_contacted_by_tool: false,
      source_fetched_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
      candidate_only: true,
      truncated: options.totalSize ? options.totalSize > data.length : false,
    },
  }
}

export function createRustBinaryInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (input: z.infer<typeof RustBinaryInventoryInputSchema>): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const parsed = RustBinaryInventoryInputSchema.parse(input)
      if (!deps.resolvePrimarySamplePath) {
        return {
          ok: false,
          errors: ['resolvePrimarySamplePath dependency is unavailable for rust.binary.inventory'],
          metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
        }
      }

      const resolved = await deps.resolvePrimarySamplePath(deps.workspaceManager, parsed.sample_id)
      const stat = await fs.stat(resolved.samplePath)
      const maxReadBytes = Math.min(parsed.max_read_bytes, MAX_PREVIEW_BYTES)
      const readSize = Math.max(0, Math.min(stat.size, maxReadBytes))
      const file = await fs.open(resolved.samplePath, 'r')
      let data: Buffer
      try {
        data = Buffer.alloc(readSize)
        await file.read(data, 0, readSize, 0)
      } finally {
        await file.close()
      }

      const inventory = buildRustBinaryInventoryFromBuffer(data, {
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
          RUST_BINARY_INVENTORY_ARTIFACT_TYPE,
          'rust-binary-inventory',
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
