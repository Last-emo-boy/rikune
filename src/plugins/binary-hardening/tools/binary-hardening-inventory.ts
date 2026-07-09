/**
 * binary.hardening.inventory — passive cross-platform mitigation inventory.
 *
 * This tool summarizes static hardening evidence for ELF, PE, Mach-O, and
 * object-like native artifacts. It never executes samples, invokes loaders,
 * starts debuggers/emulators, rewrites binaries, calls external checksec tools,
 * uses networks, or mutates inputs.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'binary.hardening.inventory'
export const BINARY_HARDENING_ARTIFACT_TYPE = 'binary_hardening_inventory'

const DEFAULT_MAX_READ_BYTES = 16 * 1024 * 1024
const MAX_PREVIEW_BYTES = 64 * 1024 * 1024
const MAX_STRINGS = 9000
const MAX_EVIDENCE = 420

type Confidence = 'low' | 'medium' | 'high'
type Status = 'present' | 'missing' | 'candidate' | 'unknown'
type Encoding = 'ascii' | 'utf16le'
type ContainerKind = 'elf' | 'pe' | 'macho' | 'raw'

interface BinaryString {
  value: string
  offset: number
  encoding: Encoding
}

interface SectionInfo {
  name: string
  executable: boolean
  writable: boolean
  readable: boolean
  offset?: number
  size?: number
}

interface EvidenceItem {
  id: string
  category: string
  value: string
  source: string
  confidence: Confidence
  offset?: number
}

interface MitigationItem {
  id: string
  name: string
  category: string
  status: Status
  confidence: Confidence
  severity_if_missing: 'info' | 'low' | 'medium' | 'high'
  evidence: EvidenceItem[]
  notes: string[]
}

interface BuildOptions {
  filename?: string
  sampleId?: string
  maxReadBytes?: number
  totalSize?: number
}

interface ContainerInfo {
  kind: ContainerKind
  bits?: 32 | 64
  endianness?: 'le' | 'be'
  machine?: string
  arch?: string
  format_detail?: string
  sections: SectionInfo[]
  features: Record<string, unknown>
}

const HARDENING_EVIDENCE = [
  'format-headers',
  'program-headers',
  'sections',
  'mitigations',
  'hardware-features',
  'symbols',
  'strings',
  'workflow',
]

const HARDENING_SAFETY = [
  'passive',
  'read_only',
  'no_execute',
  'no_loader_invocation',
  'no_exploit_test',
  'no_debugger',
  'no_emulation',
  'no_rewrite',
  'no_signing',
  'no_external_tool',
  'no_network_by_default',
  'no_mutation',
]

const HARDENING_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'native.object.inventory',
  'native.debug.types.inventory',
  'compiler.codegen.fingerprint',
  'pe.security.profile',
  'pe.structure.analyze',
  'elf.structure.analyze',
  'macho.structure.analyze',
  'linux.binary.inventory',
  'windows.debug.metadata.inspect',
  'strings.extract',
  'static.capability.triage',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const HARDENING_RULES = [
  {
    id: 'stack-canary.symbol',
    category: 'stack-protector',
    pattern:
      /\b(__stack_chk_fail|__stack_chk_guard|__security_cookie|__security_check_cookie|__GSHandlerCheck)\b/i,
    confidence: 'high' as Confidence,
  },
  {
    id: 'fortify.symbol',
    category: 'fortify',
    pattern: /\b(__memcpy_chk|__strcpy_chk|__sprintf_chk|__fortify_fail|_FORTIFY_SOURCE)\b/i,
    confidence: 'high' as Confidence,
  },
  {
    id: 'cet.ibt',
    category: 'cet',
    pattern: /\b(GNU_PROPERTY_X86_FEATURE_1_IBT|IBT|endbr64|endbr32)\b/i,
    confidence: 'medium' as Confidence,
  },
  {
    id: 'cet.shstk',
    category: 'cet',
    pattern: /\b(GNU_PROPERTY_X86_FEATURE_1_SHSTK|SHSTK|shadow stack|CET)\b/i,
    confidence: 'medium' as Confidence,
  },
  {
    id: 'pe.cfg',
    category: 'control-flow-integrity',
    pattern: /\b(GUARD_CF|__guard_check_icall_fptr|__guard_dispatch_icall_fptr)\b/i,
    confidence: 'medium' as Confidence,
  },
  {
    id: 'pe.xfg',
    category: 'control-flow-integrity',
    pattern: /\b(XFG|__guard_xfg_check_icall_fptr|__guard_xfg_dispatch_icall_fptr)\b/i,
    confidence: 'medium' as Confidence,
  },
  {
    id: 'aarch64.pac',
    category: 'hardware-cfi',
    pattern: /\b(PACIASP|PACIBSP|AUTIASP|AUTIBSP|ptrauth|pointer authentication|PAuth)\b/i,
    confidence: 'medium' as Confidence,
  },
  {
    id: 'aarch64.bti',
    category: 'hardware-cfi',
    pattern: /\b(BTI|branch target identification|GNU_PROPERTY_AARCH64_FEATURE_1_BTI)\b/i,
    confidence: 'medium' as Confidence,
  },
  {
    id: 'aarch64.mte',
    category: 'memory-tagging',
    pattern: /\b(MTE|memtag|memory tagging|HWASAN|tagged address)\b/i,
    confidence: 'medium' as Confidence,
  },
  {
    id: 'cheri.capability',
    category: 'capability-hardware',
    pattern: /\b(CHERI|Morello|purecap|__cap_relocs|capability table|\.captable)\b/i,
    confidence: 'medium' as Confidence,
  },
]

const BinaryHardeningPolicySchema = z.object({
  passive: z.literal(true),
  read_only: z.literal(true),
  no_execute: z.literal(true),
  no_loader_invocation: z.literal(true),
  no_exploit_test: z.literal(true),
  no_debugger: z.literal(true),
  no_emulation: z.literal(true),
  no_rewrite: z.literal(true),
  no_signing: z.literal(true),
  no_external_tool: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const BinaryHardeningInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.string(), z.any()),
  mitigation_summary: z.record(z.string(), z.any()),
  mitigations: z.array(z.record(z.string(), z.any())),
  hardware_features: z.array(z.record(z.string(), z.any())),
  section_risks: z.array(z.record(z.string(), z.any())),
  risk_flags: z.array(z.record(z.string(), z.any())),
  posture: z.record(z.string(), z.any()),
  policy: BinaryHardeningPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
})

export const BinaryHardeningInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive binary hardening inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist binary hardening inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const BinaryHardeningInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: BinaryHardeningInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const binaryHardeningInventoryAspects = {
  formats: [
    'binary-hardening',
    'hardening',
    'exploit-mitigation',
    'mitigation-profile',
    'checksec',
    'elf-hardening',
    'pe-hardening',
    'macho-hardening',
    'elf',
    'pe',
    'macho',
    'object',
    'static-lib',
    'native',
  ],
  platforms: ['windows', 'linux', 'macos', 'ios', 'android', 'firmware', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'riscv', 'cheri'],
  execution: ['static', 'triage', 'correlation', 'workflow-plan'],
  safety: HARDENING_SAFETY,
  capabilities: [
    'binary-hardening-inventory',
    'checksec-style-profile',
    'exploit-mitigation-posture',
    'relro-pie-nx-canary-fortify',
    'pe-cfg-xfg-load-config-hints',
    'cet-ibt-shstk-hints',
    'pac-bti-mte-hints',
    'cheri-purecap-hints',
    'section-permission-risk',
    'workflow-routing',
  ],
  evidence: HARDENING_EVIDENCE,
  route_terms: [
    'binary hardening',
    'checksec',
    'exploit mitigation',
    'relro',
    'pie',
    'aslr',
    'nx',
    'dep',
    'stack canary',
    'fortify',
    'cfg xfg',
    'cet ibt shstk',
    'pac bti',
    'mte',
    'cheri purecap',
    'w^x',
  ],
  search: [
    'cross-platform binary hardening inventory',
    'checksec exploit mitigation posture',
    'CET PAC BTI MTE CHERI hardening hints',
    'RELRO PIE NX stack canary fortify section risk',
  ],
}

export const binaryHardeningInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory cross-platform binary hardening posture across ELF, PE, Mach-O, and native object artifacts, including RELRO, PIE/ASLR, NX/DEP, stack canaries, FORTIFY, CFG/XFG, CET IBT/SHSTK, PAC/BTI, MTE, CHERI, and W^X section risks without execution or external tools.',
  inputSchema: BinaryHardeningInventoryInputSchema,
  outputSchema: BinaryHardeningInventoryOutputSchema,
  aspects: binaryHardeningInventoryAspects,
  artifacts: [
    {
      type: BINARY_HARDENING_ARTIFACT_TYPE,
      description:
        'Passive cross-platform binary exploit-mitigation and hardening posture inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: HARDENING_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [BINARY_HARDENING_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'binary.hardening-static-inventory',
      title: 'Binary hardening static inventory',
      description:
        'Inventory static exploit-mitigation evidence and section permission risks before routing to platform structure parsers, compiler provenance, evidence graph, and reporting tools.',
      startsWith: [TOOL_NAME],
      nextTools: HARDENING_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [BINARY_HARDENING_ARTIFACT_TYPE],
      evidence: HARDENING_EVIDENCE,
      safety: HARDENING_SAFETY,
    },
  ],
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function hex(value: number | bigint): string {
  return `0x${value.toString(16)}`
}

function safeReadUInt16LE(data: Buffer, offset: number): number | undefined {
  return offset >= 0 && offset + 2 <= data.length ? data.readUInt16LE(offset) : undefined
}

function safeReadUInt32LE(data: Buffer, offset: number): number | undefined {
  return offset >= 0 && offset + 4 <= data.length ? data.readUInt32LE(offset) : undefined
}

function safeReadUInt32BE(data: Buffer, offset: number): number | undefined {
  return offset >= 0 && offset + 4 <= data.length ? data.readUInt32BE(offset) : undefined
}

function safeReadBigUInt64LE(data: Buffer, offset: number): bigint | undefined {
  return offset >= 0 && offset + 8 <= data.length ? data.readBigUInt64LE(offset) : undefined
}

function readCString(data: Buffer, offset: number, maxLength: number): string {
  let end = offset
  const limit = Math.min(data.length, offset + maxLength)
  while (end < limit && data[end] !== 0) end += 1
  return data
    .toString('ascii', offset, end)
    .replace(/[^\x20-\x7e]/g, '')
    .trim()
}

function extractAsciiStrings(data: Buffer): BinaryString[] {
  const results: BinaryString[] = []
  let start = -1
  for (let i = 0; i <= data.length; i += 1) {
    const byte = i < data.length ? data[i] : 0
    const printable = byte >= 0x20 && byte <= 0x7e
    if (printable && start === -1) start = i
    if ((!printable || i === data.length) && start !== -1) {
      const length = i - start
      if (length >= 4) {
        results.push({ value: data.toString('ascii', start, i), offset: start, encoding: 'ascii' })
        if (results.length >= MAX_STRINGS) return results
      }
      start = -1
    }
  }
  return results
}

function extractUtf16Strings(data: Buffer): BinaryString[] {
  const results: BinaryString[] = []
  let start = -1
  for (let i = 0; i + 1 <= data.length; i += 2) {
    const lo = data[i]
    const hi = data[i + 1]
    const printable = hi === 0 && lo >= 0x20 && lo <= 0x7e
    if (printable && start === -1) start = i
    if ((!printable || i + 1 >= data.length) && start !== -1) {
      const end = printable ? i + 2 : i
      const length = (end - start) / 2
      if (length >= 4) {
        results.push({
          value: data.toString('utf16le', start, end),
          offset: start,
          encoding: 'utf16le',
        })
        if (results.length >= Math.floor(MAX_STRINGS / 3)) return results
      }
      start = -1
    }
  }
  return results
}

function extractStrings(data: Buffer): BinaryString[] {
  return [...extractAsciiStrings(data), ...extractUtf16Strings(data)].slice(0, MAX_STRINGS)
}

function parsePe(data: Buffer): ContainerInfo | null {
  if (data.length < 0x40 || data.toString('ascii', 0, 2) !== 'MZ') return null
  const peOffset = safeReadUInt32LE(data, 0x3c)
  if (!peOffset || peOffset + 24 >= data.length) return null
  if (data.toString('ascii', peOffset, peOffset + 4) !== 'PE\0\0') return null

  const machine = safeReadUInt16LE(data, peOffset + 4) ?? 0
  const sectionCount = safeReadUInt16LE(data, peOffset + 6) ?? 0
  const optSize = safeReadUInt16LE(data, peOffset + 20) ?? 0
  const optional = peOffset + 24
  const magic = safeReadUInt16LE(data, optional)
  const bits = magic === 0x20b ? 64 : 32
  const dllCharacteristics = safeReadUInt16LE(data, optional + 0x46) ?? 0
  const sectionTable = optional + optSize
  const sections = parsePeSections(data, sectionTable, sectionCount)
  const dataDirBase = optional + (bits === 64 ? 0x70 : 0x60)
  const loadConfigRva = safeReadUInt32LE(data, dataDirBase + 10 * 8) ?? 0
  const loadConfigSize = safeReadUInt32LE(data, dataDirBase + 10 * 8 + 4) ?? 0

  return {
    kind: 'pe',
    bits,
    endianness: 'le',
    machine: hex(machine),
    arch: peMachine(machine),
    format_detail: bits === 64 ? 'pe32-plus' : 'pe32',
    sections,
    features: {
      dll_characteristics: dllCharacteristics,
      dll_characteristics_flags: peDllCharacteristicFlags(dllCharacteristics),
      load_config_present: loadConfigRva > 0 && loadConfigSize > 0,
      load_config_rva: loadConfigRva,
      load_config_size: loadConfigSize,
    },
  }
}

function peMachine(machine: number): string {
  if (machine === 0x014c) return 'x86'
  if (machine === 0x8664) return 'x64'
  if (machine === 0xaa64) return 'arm64'
  if (machine === 0x01c4) return 'arm'
  return 'unknown'
}

function peDllCharacteristicFlags(value: number): string[] {
  const flags: Array<[number, string]> = [
    [0x0020, 'high_entropy_va'],
    [0x0040, 'dynamic_base'],
    [0x0080, 'force_integrity'],
    [0x0100, 'nx_compat'],
    [0x0400, 'no_seh'],
    [0x1000, 'app_container'],
    [0x4000, 'guard_cf'],
  ]
  return flags.filter(([bit]) => (value & bit) !== 0).map(([, name]) => name)
}

function parsePeSections(data: Buffer, sectionTable: number, sectionCount: number): SectionInfo[] {
  const sections: SectionInfo[] = []
  for (let i = 0; i < Math.min(sectionCount, 96); i += 1) {
    const offset = sectionTable + i * 40
    if (offset + 40 > data.length) break
    const name = readCString(data, offset, 8)
    const rawSize = safeReadUInt32LE(data, offset + 16) ?? 0
    const rawPointer = safeReadUInt32LE(data, offset + 20) ?? 0
    const characteristics = safeReadUInt32LE(data, offset + 36) ?? 0
    sections.push({
      name,
      executable: (characteristics & 0x20000000) !== 0,
      readable: (characteristics & 0x40000000) !== 0,
      writable: (characteristics & 0x80000000) !== 0,
      offset: rawPointer,
      size: rawSize,
    })
  }
  return sections
}

function parseElf(data: Buffer): ContainerInfo | null {
  if (data.length < 4 || data.toString('ascii', 0, 4) !== '\x7fELF') return null
  const is64 = data[4] === 2
  const little = data[5] !== 2
  const headerSize = is64 ? 0x40 : 0x34
  if (!little || data.length < headerSize) {
    return {
      kind: 'elf',
      bits: is64 ? 64 : 32,
      endianness: little ? 'le' : 'be',
      sections: [],
      features: { parse_limited: true },
    }
  }

  const eType = safeReadUInt16LE(data, 0x10) ?? 0
  const machine = safeReadUInt16LE(data, 0x12) ?? 0
  const phoff = is64
    ? Number(safeReadBigUInt64LE(data, 0x20) ?? 0n)
    : (safeReadUInt32LE(data, 0x1c) ?? 0)
  const shoff = is64
    ? Number(safeReadBigUInt64LE(data, 0x28) ?? 0n)
    : (safeReadUInt32LE(data, 0x20) ?? 0)
  const phentsize = safeReadUInt16LE(data, is64 ? 0x36 : 0x2a) ?? 0
  const phnum = safeReadUInt16LE(data, is64 ? 0x38 : 0x2c) ?? 0
  const shentsize = safeReadUInt16LE(data, is64 ? 0x3a : 0x2e) ?? 0
  const shnum = safeReadUInt16LE(data, is64 ? 0x3c : 0x30) ?? 0
  const shstrndx = safeReadUInt16LE(data, is64 ? 0x3e : 0x32) ?? 0
  const program = parseElfProgramHeaders(data, { is64, phoff, phentsize, phnum })
  const sections = parseElfSections(data, { is64, shoff, shentsize, shnum, shstrndx })

  return {
    kind: 'elf',
    bits: is64 ? 64 : 32,
    endianness: 'le',
    machine: hex(machine),
    arch: elfMachine(machine),
    format_detail: eType === 3 ? 'elf-dyn' : eType === 2 ? 'elf-executable' : 'elf',
    sections,
    features: {
      elf_type: eType,
      pie_candidate: eType === 3,
      relro_present: program.relro,
      gnu_stack_present: program.gnuStackPresent,
      gnu_stack_executable: program.gnuStackExecutable,
      bind_now_candidate: program.bindNow,
      dynamic_present: program.dynamicPresent,
    },
  }
}

function elfMachine(machine: number): string {
  if (machine === 3) return 'x86'
  if (machine === 62) return 'x64'
  if (machine === 40) return 'arm'
  if (machine === 183) return 'arm64'
  if (machine === 243) return 'riscv'
  return 'unknown'
}

function parseElfProgramHeaders(
  data: Buffer,
  args: { is64: boolean; phoff: number; phentsize: number; phnum: number }
) {
  const result = {
    relro: false,
    gnuStackPresent: false,
    gnuStackExecutable: false,
    dynamicPresent: false,
    bindNow: false,
  }
  if (!args.phoff || !args.phentsize || args.phnum <= 0 || args.phnum > 4096) return result
  for (let i = 0; i < Math.min(args.phnum, 256); i += 1) {
    const entry = args.phoff + i * args.phentsize
    if (entry + args.phentsize > data.length) break
    const type = safeReadUInt32LE(data, entry) ?? 0
    const flags = args.is64
      ? (safeReadUInt32LE(data, entry + 4) ?? 0)
      : (safeReadUInt32LE(data, entry + 24) ?? 0)
    const offset = args.is64
      ? Number(safeReadBigUInt64LE(data, entry + 8) ?? 0n)
      : (safeReadUInt32LE(data, entry + 4) ?? 0)
    const filesz = args.is64
      ? Number(safeReadBigUInt64LE(data, entry + 0x20) ?? 0n)
      : (safeReadUInt32LE(data, entry + 0x10) ?? 0)

    if (type === 0x6474e552) result.relro = true
    if (type === 0x6474e551) {
      result.gnuStackPresent = true
      result.gnuStackExecutable = (flags & 1) !== 0
    }
    if (type === 2) {
      result.dynamicPresent = true
      result.bindNow ||= parseElfDynamicBindNow(data, offset, filesz, args.is64)
    }
  }
  return result
}

function parseElfDynamicBindNow(
  data: Buffer,
  offset: number,
  filesz: number,
  is64: boolean
): boolean {
  const entrySize = is64 ? 16 : 8
  if (offset <= 0 || filesz <= 0 || offset + filesz > data.length) return false
  const count = Math.min(Math.floor(filesz / entrySize), 2048)
  for (let i = 0; i < count; i += 1) {
    const entry = offset + i * entrySize
    const tag = is64
      ? Number(safeReadBigUInt64LE(data, entry) ?? 0n)
      : (safeReadUInt32LE(data, entry) ?? 0)
    const value = is64
      ? Number(safeReadBigUInt64LE(data, entry + 8) ?? 0n)
      : (safeReadUInt32LE(data, entry + 4) ?? 0)
    if (tag === 0) break
    if (tag === 24) return true
    if (tag === 30 && (value & 0x8) !== 0) return true
    if (tag === 0x6ffffffb && (value & 0x1) !== 0) return true
  }
  return false
}

function parseElfSections(
  data: Buffer,
  args: { is64: boolean; shoff: number; shentsize: number; shnum: number; shstrndx: number }
): SectionInfo[] {
  if (
    !args.shoff ||
    !args.shentsize ||
    args.shnum <= 0 ||
    args.shnum > 4096 ||
    args.shstrndx >= args.shnum
  ) {
    return []
  }
  const table = args.shoff + args.shstrndx * args.shentsize
  if (table + args.shentsize > data.length) return []
  const strOffset = args.is64
    ? Number(safeReadBigUInt64LE(data, table + 0x18) ?? 0n)
    : (safeReadUInt32LE(data, table + 0x10) ?? 0)
  const strSize = args.is64
    ? Number(safeReadBigUInt64LE(data, table + 0x20) ?? 0n)
    : (safeReadUInt32LE(data, table + 0x14) ?? 0)
  if (strOffset <= 0 || strSize <= 0 || strOffset + strSize > data.length) return []

  const sections: SectionInfo[] = []
  for (let i = 0; i < Math.min(args.shnum, 256); i += 1) {
    const entry = args.shoff + i * args.shentsize
    if (entry + args.shentsize > data.length) break
    const nameOffset = safeReadUInt32LE(data, entry) ?? 0
    const flags = args.is64
      ? Number(safeReadBigUInt64LE(data, entry + 8) ?? 0n)
      : (safeReadUInt32LE(data, entry + 8) ?? 0)
    const offset = args.is64
      ? Number(safeReadBigUInt64LE(data, entry + 0x18) ?? 0n)
      : (safeReadUInt32LE(data, entry + 0x10) ?? 0)
    const size = args.is64
      ? Number(safeReadBigUInt64LE(data, entry + 0x20) ?? 0n)
      : (safeReadUInt32LE(data, entry + 0x14) ?? 0)
    if (nameOffset < strSize) {
      sections.push({
        name: readCString(data, strOffset + nameOffset, 128),
        executable: (flags & 0x4) !== 0,
        writable: (flags & 0x1) !== 0,
        readable: true,
        offset,
        size,
      })
    }
  }
  return sections.filter((item) => item.name)
}

function parseMacho(data: Buffer): ContainerInfo | null {
  if (data.length < 28) return null
  const magicLe = safeReadUInt32LE(data, 0)
  const magicBe = safeReadUInt32BE(data, 0)
  const isLittle = magicLe === 0xfeedface || magicLe === 0xfeedfacf
  const isBig = magicBe === 0xfeedface || magicBe === 0xfeedfacf || magicBe === 0xcafebabe
  if (!isLittle && !isBig) return null
  const is64 = magicLe === 0xfeedfacf || magicBe === 0xfeedfacf
  if (!isLittle) {
    return {
      kind: 'macho',
      bits: is64 ? 64 : 32,
      endianness: 'be',
      sections: [],
      features: { parse_limited: true, magic: hex(BigInt(magicBe ?? 0)) },
    }
  }

  const cpuType = safeReadUInt32LE(data, 4) ?? 0
  const cpuSubtype = safeReadUInt32LE(data, 8) ?? 0
  const fileType = safeReadUInt32LE(data, 12) ?? 0
  const flags = safeReadUInt32LE(data, 24) ?? 0
  return {
    kind: 'macho',
    bits: is64 ? 64 : 32,
    endianness: 'le',
    machine: hex(cpuType),
    arch: machoCpu(cpuType, cpuSubtype),
    format_detail: machoFileType(fileType),
    sections: [],
    features: {
      macho_flags: flags,
      pie: (flags & 0x00200000) !== 0,
      no_heap_execution: (flags & 0x01000000) !== 0,
      arm64e_candidate: cpuType === 0x0100000c && (cpuSubtype & 0xff) === 2,
    },
  }
}

function machoCpu(cpuType: number, cpuSubtype: number): string {
  if (cpuType === 0x01000007) return 'x64'
  if (cpuType === 7) return 'x86'
  if (cpuType === 0x0100000c && (cpuSubtype & 0xff) === 2) return 'arm64e'
  if (cpuType === 0x0100000c) return 'arm64'
  if (cpuType === 12) return 'arm'
  return 'unknown'
}

function machoFileType(fileType: number): string {
  if (fileType === 2) return 'macho-executable'
  if (fileType === 6) return 'macho-dylib'
  if (fileType === 1) return 'macho-object'
  return 'macho'
}

function detectContainer(data: Buffer, filename?: string): ContainerInfo {
  return (
    parseElf(data) ??
    parsePe(data) ??
    parseMacho(data) ?? {
      kind: 'raw',
      sections: [],
      features: {
        filename_extension: filename?.toLowerCase().split('.').pop(),
      },
    }
  )
}

function evidence(
  id: string,
  category: string,
  value: string,
  source: string,
  confidence: Confidence,
  offset?: number
): EvidenceItem {
  return { id, category, value, source, confidence, offset }
}

function mitigation(
  id: string,
  name: string,
  category: string,
  status: Status,
  confidence: Confidence,
  severity: MitigationItem['severity_if_missing'],
  itemEvidence: EvidenceItem[],
  notes: string[] = []
): MitigationItem {
  return {
    id,
    name,
    category,
    status,
    confidence,
    severity_if_missing: severity,
    evidence: itemEvidence,
    notes,
  }
}

function hasStringEvidence(strings: BinaryString[], pattern: RegExp) {
  const matches: EvidenceItem[] = []
  for (const item of strings) {
    if (pattern.test(item.value)) {
      matches.push(
        evidence('string.marker', 'strings', item.value, item.encoding, 'medium', item.offset)
      )
      if (matches.length >= 24) break
    }
  }
  return matches
}

function collectRuleEvidence(
  data: Buffer,
  strings: BinaryString[],
  sections: SectionInfo[]
): EvidenceItem[] {
  const items: EvidenceItem[] = []
  const seen = new Set<string>()
  const addEvidence = (item: EvidenceItem): boolean => {
    const key = `${item.id}:${item.offset ?? 'n/a'}:${item.value.toLowerCase()}`
    if (seen.has(key)) return false
    seen.add(key)
    items.push(item)
    return items.length >= MAX_EVIDENCE
  }
  const haystack = [
    ...strings.map((item) => ({ value: item.value, source: item.encoding, offset: item.offset })),
    ...sections.map((section, index) => ({
      value: section.name,
      source: 'section',
      offset: index,
    })),
  ]
  for (const candidate of haystack) {
    for (const rule of HARDENING_RULES) {
      const match = rule.pattern.exec(candidate.value)
      if (match) {
        const offset =
          candidate.source === 'section' ? candidate.offset : candidate.offset + match.index
        if (
          addEvidence(
            evidence(rule.id, rule.category, match[0], candidate.source, rule.confidence, offset)
          )
        ) {
          return items
        }
      }
    }
  }

  const rawText = data.toString('latin1')
  for (const rule of HARDENING_RULES) {
    const match = rule.pattern.exec(rawText)
    if (match) {
      if (
        addEvidence(
          evidence(rule.id, rule.category, match[0], 'raw-bytes', rule.confidence, match.index)
        )
      ) {
        return items
      }
    }
  }
  return items
}

function buildMitigations(
  container: ContainerInfo,
  strings: BinaryString[],
  ruleEvidence: EvidenceItem[]
) {
  const mitigations: MitigationItem[] = []
  const features = container.features
  const sectionRisks = buildSectionRisks(container.sections)
  const noWxEvidence =
    sectionRisks.length === 0
      ? [
          evidence(
            'section.wx.none',
            'sections',
            'no writable+executable sections in bounded metadata',
            'parser',
            'medium'
          ),
        ]
      : []

  if (container.kind === 'elf') {
    mitigations.push(
      mitigation(
        'elf.relro',
        'RELRO segment',
        'loader-hardening',
        features.relro_present ? 'present' : 'missing',
        'high',
        'medium',
        features.relro_present
          ? [evidence('elf.pt-gnu-relro', 'program-headers', 'PT_GNU_RELRO', 'parser', 'high')]
          : []
      ),
      mitigation(
        'elf.bind-now',
        'Immediate binding / full RELRO candidate',
        'loader-hardening',
        features.bind_now_candidate ? 'present' : 'unknown',
        features.bind_now_candidate ? 'high' : 'low',
        'low',
        features.bind_now_candidate
          ? [
              evidence(
                'elf.dynamic-bind-now',
                'dynamic',
                'DT_BIND_NOW or DF_1_NOW',
                'parser',
                'high'
              ),
            ]
          : []
      ),
      mitigation(
        'elf.pie',
        'PIE / ASLR-ready ELF type',
        'aslr',
        features.pie_candidate ? 'present' : 'unknown',
        features.pie_candidate ? 'high' : 'medium',
        'medium',
        features.pie_candidate
          ? [
              evidence(
                'elf.et-dyn',
                'format-headers',
                'ET_DYN executable/library candidate',
                'parser',
                'high'
              ),
            ]
          : []
      ),
      mitigation(
        'elf.nx-stack',
        'Non-executable GNU stack',
        'nx',
        features.gnu_stack_present
          ? features.gnu_stack_executable
            ? 'missing'
            : 'present'
          : 'unknown',
        features.gnu_stack_present ? 'high' : 'low',
        'high',
        features.gnu_stack_present
          ? [
              evidence(
                'elf.pt-gnu-stack',
                'program-headers',
                features.gnu_stack_executable
                  ? 'PT_GNU_STACK executable'
                  : 'PT_GNU_STACK non-executable',
                'parser',
                'high'
              ),
            ]
          : []
      )
    )
  }

  if (container.kind === 'pe') {
    const flags = Array.isArray(features.dll_characteristics_flags)
      ? (features.dll_characteristics_flags as string[])
      : []
    mitigations.push(
      mitigation(
        'pe.dep-nx',
        'DEP / NX compatibility',
        'nx',
        flags.includes('nx_compat') ? 'present' : 'missing',
        'high',
        'high',
        flags.includes('nx_compat')
          ? [evidence('pe.dll-characteristics', 'format-headers', 'NX_COMPAT', 'parser', 'high')]
          : []
      ),
      mitigation(
        'pe.aslr',
        'ASLR dynamic base',
        'aslr',
        flags.includes('dynamic_base') ? 'present' : 'missing',
        'high',
        'high',
        flags.includes('dynamic_base')
          ? [evidence('pe.dll-characteristics', 'format-headers', 'DYNAMIC_BASE', 'parser', 'high')]
          : []
      ),
      mitigation(
        'pe.high-entropy-va',
        'High entropy VA',
        'aslr',
        flags.includes('high_entropy_va') ? 'present' : 'unknown',
        flags.includes('high_entropy_va') ? 'high' : 'low',
        'low',
        flags.includes('high_entropy_va')
          ? [
              evidence(
                'pe.dll-characteristics',
                'format-headers',
                'HIGH_ENTROPY_VA',
                'parser',
                'high'
              ),
            ]
          : []
      ),
      mitigation(
        'pe.cfg',
        'Control Flow Guard',
        'control-flow-integrity',
        flags.includes('guard_cf') ? 'present' : 'unknown',
        flags.includes('guard_cf') ? 'high' : 'medium',
        'medium',
        [
          ...(flags.includes('guard_cf')
            ? [evidence('pe.dll-characteristics', 'format-headers', 'GUARD_CF', 'parser', 'high')]
            : []),
          ...ruleEvidence.filter((item) => item.id === 'pe.cfg'),
        ]
      ),
      mitigation(
        'pe.safe-seh',
        'SEH hardening marker',
        'exception-hardening',
        flags.includes('no_seh') ? 'present' : 'unknown',
        flags.includes('no_seh') ? 'medium' : 'low',
        'low',
        flags.includes('no_seh')
          ? [evidence('pe.dll-characteristics', 'format-headers', 'NO_SEH', 'parser', 'medium')]
          : []
      )
    )
  }

  if (container.kind === 'macho') {
    mitigations.push(
      mitigation(
        'macho.pie',
        'Mach-O PIE',
        'aslr',
        features.pie ? 'present' : 'unknown',
        features.pie ? 'high' : 'medium',
        'medium',
        features.pie ? [evidence('macho.flags', 'format-headers', 'MH_PIE', 'parser', 'high')] : []
      ),
      mitigation(
        'macho.no-heap-exec',
        'No heap execution flag',
        'nx',
        features.no_heap_execution ? 'present' : 'unknown',
        features.no_heap_execution ? 'medium' : 'low',
        'medium',
        features.no_heap_execution
          ? [evidence('macho.flags', 'format-headers', 'MH_NO_HEAP_EXECUTION', 'parser', 'medium')]
          : []
      )
    )
  }

  const canaryEvidence = ruleEvidence.filter((item) => item.id === 'stack-canary.symbol')
  const fortifyEvidence = ruleEvidence.filter((item) => item.id === 'fortify.symbol')
  const xfgEvidence = ruleEvidence.filter((item) => item.id === 'pe.xfg')
  const ibtEvidence = ruleEvidence.filter((item) => item.id === 'cet.ibt')
  const shstkEvidence = ruleEvidence.filter((item) => item.id === 'cet.shstk')
  const pacEvidence = ruleEvidence.filter((item) => item.id === 'aarch64.pac')
  const btiEvidence = ruleEvidence.filter((item) => item.id === 'aarch64.bti')
  const mteEvidence = ruleEvidence.filter((item) => item.id === 'aarch64.mte')
  const cheriEvidence = ruleEvidence.filter((item) => item.id === 'cheri.capability')

  mitigations.push(
    mitigation(
      'stack.canary',
      'Stack canary / security cookie',
      'stack-protector',
      canaryEvidence.length > 0 ? 'present' : 'unknown',
      canaryEvidence.length > 0 ? 'high' : 'low',
      'medium',
      canaryEvidence
    ),
    mitigation(
      'fortify',
      'FORTIFY checked libc calls',
      'fortify',
      fortifyEvidence.length > 0 ? 'present' : 'unknown',
      fortifyEvidence.length > 0 ? 'high' : 'low',
      'low',
      fortifyEvidence
    ),
    mitigation(
      'section.no-wx',
      'No writable+executable sections',
      'section-permissions',
      sectionRisks.length === 0 ? 'present' : 'missing',
      sectionRisks.length === 0 ? 'medium' : 'high',
      'high',
      noWxEvidence,
      sectionRisks.length > 0 ? ['Writable+executable section metadata was found.'] : []
    ),
    mitigation(
      'cet.ibt',
      'Intel CET indirect branch tracking',
      'hardware-cfi',
      ibtEvidence.length > 0 ? 'candidate' : 'unknown',
      ibtEvidence.length > 0 ? 'medium' : 'low',
      'low',
      ibtEvidence,
      ['String/section evidence is candidate-only unless corroborated by GNU property notes.']
    ),
    mitigation(
      'cet.shstk',
      'Intel CET shadow stack',
      'hardware-cfi',
      shstkEvidence.length > 0 ? 'candidate' : 'unknown',
      shstkEvidence.length > 0 ? 'medium' : 'low',
      'low',
      shstkEvidence,
      ['String/section evidence is candidate-only unless corroborated by GNU property notes.']
    ),
    mitigation(
      'pe.xfg',
      'Extended Flow Guard',
      'control-flow-integrity',
      xfgEvidence.length > 0 ? 'candidate' : 'unknown',
      xfgEvidence.length > 0 ? 'medium' : 'low',
      'low',
      xfgEvidence
    ),
    mitigation(
      'aarch64.pac',
      'AArch64 pointer authentication',
      'hardware-cfi',
      pacEvidence.length > 0 ? 'candidate' : 'unknown',
      pacEvidence.length > 0 ? 'medium' : 'low',
      'low',
      pacEvidence
    ),
    mitigation(
      'aarch64.bti',
      'AArch64 branch target identification',
      'hardware-cfi',
      btiEvidence.length > 0 ? 'candidate' : 'unknown',
      btiEvidence.length > 0 ? 'medium' : 'low',
      'low',
      btiEvidence
    ),
    mitigation(
      'aarch64.mte',
      'AArch64 memory tagging hints',
      'memory-tagging',
      mteEvidence.length > 0 ? 'candidate' : 'unknown',
      mteEvidence.length > 0 ? 'medium' : 'low',
      'info',
      mteEvidence
    ),
    mitigation(
      'cheri.purecap',
      'CHERI / purecap capability hints',
      'capability-hardware',
      cheriEvidence.length > 0 ? 'candidate' : 'unknown',
      cheriEvidence.length > 0 ? 'medium' : 'low',
      'info',
      cheriEvidence
    )
  )

  if (container.kind === 'raw') {
    const nxEvidence = hasStringEvidence(strings, /\b(NX|DEP|non-executable stack)\b/i)
    if (nxEvidence.length > 0) {
      mitigations.push(
        mitigation('raw.nx-marker', 'NX / DEP marker', 'nx', 'candidate', 'low', 'info', nxEvidence)
      )
    }
  }

  return { mitigations, sectionRisks }
}

function buildSectionRisks(sections: SectionInfo[]) {
  return sections
    .filter((section) => section.executable && section.writable)
    .map((section) => ({
      id: 'section.write-execute',
      severity: 'high',
      section: section.name,
      reason: 'Section metadata is both writable and executable.',
      offset: section.offset,
      size: section.size,
    }))
}

function buildHardwareFeatures(mitigations: MitigationItem[]) {
  return mitigations
    .filter((item) =>
      ['hardware-cfi', 'memory-tagging', 'capability-hardware'].includes(item.category)
    )
    .filter((item) => item.status !== 'unknown')
    .map((item) => ({
      id: item.id,
      name: item.name,
      status: item.status,
      confidence: item.confidence,
      evidence_count: item.evidence.length,
      candidate_only: item.status === 'candidate',
    }))
}

function buildRiskFlags(mitigations: MitigationItem[], sectionRisks: Record<string, unknown>[]) {
  const flags: Record<string, unknown>[] = []
  for (const item of mitigations) {
    if (item.status !== 'missing') continue
    flags.push({
      id: `missing.${item.id}`,
      severity: item.severity_if_missing,
      mitigation: item.name,
      reason: `${item.name} is missing or disabled in static metadata.`,
    })
  }
  for (const risk of sectionRisks) flags.push(risk)
  if (mitigations.some((item) => item.status === 'candidate')) {
    flags.push({
      id: 'candidate.hardware-mitigations',
      severity: 'info',
      reason:
        'One or more hardware mitigation markers are candidate-only until corroborated by dedicated format parsers or platform policy.',
    })
  }
  return flags
}

function buildMitigationSummary(mitigations: MitigationItem[]) {
  const byStatus: Record<Status, number> = {
    present: 0,
    missing: 0,
    candidate: 0,
    unknown: 0,
  }
  const byCategory: Record<string, number> = {}
  for (const item of mitigations) {
    byStatus[item.status] += 1
    byCategory[item.category] = (byCategory[item.category] ?? 0) + 1
  }
  return {
    total: mitigations.length,
    by_status: byStatus,
    by_category: byCategory,
    present: mitigations.filter((item) => item.status === 'present').map((item) => item.id),
    missing: mitigations.filter((item) => item.status === 'missing').map((item) => item.id),
    candidate: mitigations.filter((item) => item.status === 'candidate').map((item) => item.id),
  }
}

function postureScore(mitigations: MitigationItem[], sectionRisks: Record<string, unknown>[]) {
  let score = 100
  for (const item of mitigations) {
    if (item.status !== 'missing') continue
    score -=
      item.severity_if_missing === 'high' ? 18 : item.severity_if_missing === 'medium' ? 10 : 4
  }
  score -= sectionRisks.length * 15
  const bounded = Math.max(0, Math.min(100, score))
  return {
    score: bounded,
    rating: bounded >= 80 ? 'hardened-candidate' : bounded >= 55 ? 'mixed' : 'weak',
  }
}

function detectFormat(
  container: ContainerInfo,
  filename?: string,
  mitigations: MitigationItem[] = []
) {
  const format =
    container.kind === 'pe'
      ? 'pe-hardening-profile'
      : container.kind === 'elf'
        ? 'elf-hardening-profile'
        : container.kind === 'macho'
          ? 'macho-hardening-profile'
          : 'binary-hardening-candidate'
  const detectedBy = unique([
    `container:${container.kind}`,
    container.format_detail ? `format:${container.format_detail}` : '',
    container.arch ? `arch:${container.arch}` : '',
    ...mitigations
      .filter((item) => item.status === 'present' || item.status === 'candidate')
      .slice(0, 10)
      .map((item) => `mitigation:${item.id}`),
    filename ? `filename:${path.basename(filename).toLowerCase()}` : '',
  ])
  const positive = mitigations.filter(
    (item) => item.status === 'present' || item.status === 'candidate'
  )
  const confidence: Confidence =
    container.kind !== 'raw' && positive.length >= 3
      ? 'high'
      : container.kind !== 'raw' || positive.length > 0
        ? 'medium'
        : 'low'
  return { format, detectedBy, confidence }
}

function buildSummary(
  format: string,
  summary: ReturnType<typeof buildMitigationSummary>,
  posture: ReturnType<typeof postureScore>
) {
  const status = summary.by_status
  return `Passive ${format} found ${status.present} present, ${status.candidate} candidate, ${status.missing} missing, and ${status.unknown} unknown mitigation marker(s); posture rating is ${posture.rating}.`
}

export function buildBinaryHardeningInventoryFromBuffer(data: Buffer, options: BuildOptions = {}) {
  const strings = extractStrings(data)
  const container = detectContainer(data, options.filename)
  const ruleEvidence = collectRuleEvidence(data, strings, container.sections)
  const { mitigations, sectionRisks } = buildMitigations(container, strings, ruleEvidence)
  const mitigationSummary = buildMitigationSummary(mitigations)
  const hardwareFeatures = buildHardwareFeatures(mitigations)
  const riskFlags = buildRiskFlags(mitigations, sectionRisks)
  const posture = postureScore(mitigations, sectionRisks)
  const formatInfo = detectFormat(container, options.filename, mitigations)

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: formatInfo.format,
    detected_by: formatInfo.detectedBy,
    confidence: formatInfo.confidence,
    size: options.totalSize,
    preview_size: data.length,
    container,
    mitigation_summary: mitigationSummary,
    mitigations,
    hardware_features: hardwareFeatures,
    section_risks: sectionRisks,
    risk_flags: riskFlags,
    posture,
    policy: {
      passive: true,
      read_only: true,
      no_execute: true,
      no_loader_invocation: true,
      no_exploit_test: true,
      no_debugger: true,
      no_emulation: true,
      no_rewrite: true,
      no_signing: true,
      no_external_tool: true,
      no_network: true,
      no_mutation: true,
    },
    summary: buildSummary(formatInfo.format, mitigationSummary, posture),
    recommended_next_tools: HARDENING_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use platform parsers such as pe.security.profile, elf.structure.analyze, or macho.structure.analyze to corroborate candidate-only mitigation evidence.',
      'Use compiler.codegen.fingerprint to connect hardening posture to compiler, linker, LTO, PGO, and language-runtime provenance.',
      'Use analysis.evidence.graph and report.generate to correlate missing mitigations, section risks, and hardening evidence across related samples.',
      'Keep runtime exploitability validation as an explicit opt-in workflow; this tool does not execute or load samples.',
    ],
    evidence_summary: {
      total_mitigations: mitigations.length,
      total_rule_evidence: ruleEvidence.length,
      hardware_feature_count: hardwareFeatures.length,
      section_risk_count: sectionRisks.length,
      risk_flag_count: riskFlags.length,
      bounded_preview: true,
      candidate_only_hardware_features: hardwareFeatures.some((item) => item.candidate_only),
    },
    workflow_handoff: {
      static_corroboration: [
        'pe.security.profile',
        'elf.structure.analyze',
        'macho.structure.analyze',
        'linux.binary.inventory',
        'native.object.inventory',
      ],
      provenance_correlation: ['compiler.codegen.fingerprint', 'sbom.provenance.graph'],
      evidence_correlation: ['analysis.evidence.graph', 'report.generate'],
      runtime_boundary: {
        required: false,
        exploit_test_allowed_by_this_tool: false,
        guidance:
          'Runtime probing, exploit tests, loader behavior checks, and debugger/emulator validation are outside this passive inventory and must remain explicit opt-in workflows.',
      },
    },
    quality_gates: {
      passive_static_inventory: true,
      bounded_read_bytes: data.length,
      max_read_bytes: options.maxReadBytes ?? DEFAULT_MAX_READ_BYTES,
      sample_executed_by_tool: false,
      loader_invoked_by_tool: false,
      exploit_test_performed_by_tool: false,
      debugger_or_emulator_started_by_tool: false,
      external_tool_invoked_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
      candidate_only: true,
      truncated: options.totalSize ? options.totalSize > data.length : false,
    },
  }
}

export function createBinaryHardeningInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (
    input: z.infer<typeof BinaryHardeningInventoryInputSchema>
  ): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const parsed = BinaryHardeningInventoryInputSchema.parse(input)
      if (!deps.resolvePrimarySamplePath) {
        return {
          ok: false,
          errors: [
            'resolvePrimarySamplePath dependency is unavailable for binary.hardening.inventory',
          ],
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

      const inventory = buildBinaryHardeningInventoryFromBuffer(data, {
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
          BINARY_HARDENING_ARTIFACT_TYPE,
          'binary-hardening-inventory',
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
