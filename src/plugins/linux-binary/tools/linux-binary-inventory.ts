/**
 * linux.binary.inventory — passive Linux ELF/core/module/initramfs inventory.
 *
 * This tool does not execute binaries, load shared objects, replay core dumps,
 * insert kernel modules, mount filesystems, or start emulators. It reads
 * bounded previews and returns structure and routing hints.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'linux.binary.inventory'
const DEFAULT_MAX_READ_BYTES = 6 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const LINUX_BINARY_ARTIFACT_TYPE = 'linux_binary_inventory'
const LINUX_BINARY_SAFETY = [
  'passive',
  'no_auto_mount',
  'no_live_sample_by_default',
  'no_execute',
  'no_load',
  'no_core_replay',
  'no_kernel_module_load',
  'no_runtime_start',
  'no_network_by_default',
]
const LINUX_BINARY_EVIDENCE = [
  'structure',
  'symbols',
  'filesystem',
  'memory',
  'nested-binaries',
  'workflow',
  'provenance',
]
const LINUX_BINARY_FOLLOW_UP_TOOLS = [
  'metadata.extract',
  'strings.extract',
  'elf.structure.analyze',
  'elf.imports.extract',
  'elf.exports.extract',
  'native.object.inventory',
  'linux.runtime.plan',
  'analysis.evidence.graph',
  'artifact.read',
]

const LinuxBinaryPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_load: z.literal(true),
  no_core_replay: z.literal(true),
  no_kernel_module_load: z.literal(true),
  no_mount: z.literal(true),
  no_runtime_start: z.literal(true),
})

const LinuxBinaryCandidateSchema = z.object({
  path: z.string(),
  routed_formats: z.array(z.string()),
  recommended_tools: z.array(z.string()),
})

const LinuxBinaryLoaderSecurityProfileSchema = z.object({
  entrypoint: z.string().optional(),
  interpreter: z.string().optional(),
  needed_libraries: z.array(z.string()),
  rpath_runpath_hints: z.array(z.string()),
  dynamic_segment_present: z.boolean(),
  pie_candidate: z.boolean().nullable(),
  nx_stack_candidate: z.boolean().nullable(),
  executable_stack_candidate: z.boolean().nullable(),
  relro_candidate: z.boolean(),
  bind_now_candidate: z.boolean(),
  canary_symbol_candidate: z.boolean(),
  hardening_notes: z.array(z.string()),
})

const LinuxBinaryInventoryDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  elf_header: z
    .object({
      class: z.string().optional(),
      endian: z.string().optional(),
      type: z.string().optional(),
      machine: z.string().optional(),
      osabi: z.string().optional(),
      entrypoint: z.string().optional(),
    })
    .optional(),
  loader_security_profile: LinuxBinaryLoaderSecurityProfileSchema,
  interpreter_hints: z.array(z.string()),
  shared_library_hints: z.array(z.string()),
  symbol_hints: z.array(z.string()),
  core_dump_hints: z.array(z.string()),
  kernel_module_hints: z.array(z.string()),
  initramfs_members: z.array(z.string()),
  nested_binary_candidates: z.array(LinuxBinaryCandidateSchema),
  policy: LinuxBinaryPolicySchema,
  unsupported_detail: z.string().optional(),
  evidence_summary: z.record(z.string(), z.any()).optional(),
  workflow_handoff: z.record(z.string(), z.any()).optional(),
  quality_gates: z.record(z.string(), z.any()).optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const LinuxBinaryInventoryInputSchema = z.object({
  sample_id: z
    .string()
    .describe('Target Linux ELF, shared object, core dump, kernel module, or initramfs sample.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive Linux binary inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const LinuxBinaryInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: LinuxBinaryInventoryDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const linuxBinaryInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Linux ELF executables, shared objects, core dumps, kernel modules, and initramfs/cpio images without executing, loading, mounting, or replaying content.',
  inputSchema: LinuxBinaryInventoryInputSchema,
  outputSchema: LinuxBinaryInventoryOutputSchema,
  aspects: {
    formats: [
      'linux-binary',
      'elf',
      'elf-executable',
      'so',
      'elf-so',
      'elf-core',
      'linux-kernel-module',
      'initramfs',
      'cpio',
      'dwarf',
    ],
    platforms: ['linux', 'embedded'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    safety: LINUX_BINARY_SAFETY,
    capabilities: [
      'inventory',
      'structure',
      'loader-profile',
      'security-profile',
      'hardening-candidates',
      'elf-interpreter-profile',
      'dependency-inventory',
      'symbols',
      'debug-metadata',
      'nested-binaries',
      'workflow-handoff',
      'routing',
    ],
    evidence: LINUX_BINARY_EVIDENCE,
  },
  artifacts: [
    {
      type: LINUX_BINARY_ARTIFACT_TYPE,
      description:
        'Passive Linux ELF/core/module/initramfs inventory, loader profile, hardening candidates, and routing hints',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [LINUX_BINARY_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [LINUX_BINARY_ARTIFACT_TYPE] },
    { category: 'filesystem', artifactTypes: [LINUX_BINARY_ARTIFACT_TYPE] },
    { category: 'memory', artifactTypes: [LINUX_BINARY_ARTIFACT_TYPE] },
    { category: 'nested-binaries', artifactTypes: [LINUX_BINARY_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [LINUX_BINARY_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [LINUX_BINARY_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'linux-binary.passive-loader-security-profile',
      title: 'Linux binary passive loader and security profile',
      description:
        'Extract ELF loader, dependency, hardening-candidate, symbol, core, module, and initramfs routing evidence without execution, loading, mounting, core replay, kernel module insertion, or runtime startup.',
      startsWith: [TOOL_NAME],
      nextTools: LINUX_BINARY_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [LINUX_BINARY_ARTIFACT_TYPE],
      evidence: LINUX_BINARY_EVIDENCE,
      safety: LINUX_BINARY_SAFETY,
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    noLoad: true,
    noMount: true,
    noCoreReplay: true,
    noKernelModuleLoad: true,
    notes: [
      'linux.binary.inventory is a passive local parser; it never executes ELF files or starts runtime tooling.',
      'Core dumps are inventoried as metadata only and are not replayed or attached to a debugger.',
      'Kernel modules are not inserted, loaded, or inspected through a live kernel.',
    ],
  } as ToolDefinition['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
    noLoad: true
    noMount: true
    noCoreReplay: true
    noKernelModuleLoad: true
  },
}

export type LinuxBinaryInventory = z.infer<typeof LinuxBinaryInventoryDataSchema>
type LinuxBinaryCandidate = z.infer<typeof LinuxBinaryCandidateSchema>
type LinuxBinaryLoaderSecurityProfile = z.infer<typeof LinuxBinaryLoaderSecurityProfileSchema>

const ELF_MACHINES: Record<number, string> = {
  3: 'x86',
  8: 'mips',
  20: 'ppc',
  40: 'arm',
  62: 'x64',
  183: 'arm64',
  243: 'riscv',
}

const ELF_TYPES: Record<number, string> = {
  1: 'relocatable',
  2: 'executable',
  3: 'shared-object',
  4: 'core',
}

const ELF_OSABI: Record<number, string> = {
  0: 'system-v',
  3: 'linux',
  6: 'solaris',
  9: 'freebsd',
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function previewText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
}

function isElf(data: Buffer): boolean {
  return (
    data.length >= 20 &&
    data[0] === 0x7f &&
    data[1] === 0x45 &&
    data[2] === 0x4c &&
    data[3] === 0x46
  )
}

function elfEndian(data: Buffer): 'be' | 'le' {
  return data[5] === 2 ? 'be' : 'le'
}

function readUInt16(data: Buffer, offset: number, endian: 'be' | 'le'): number {
  if (offset + 2 > data.length) return 0
  return endian === 'be' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
}

function readUInt32(data: Buffer, offset: number, endian: 'be' | 'le'): number {
  if (offset + 4 > data.length) return 0
  return endian === 'be' ? data.readUInt32BE(offset) : data.readUInt32LE(offset)
}

function readUInt64Number(data: Buffer, offset: number, endian: 'be' | 'le'): number | undefined {
  if (offset + 8 > data.length) return undefined
  const value = endian === 'be' ? data.readBigUInt64BE(offset) : data.readBigUInt64LE(offset)
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : undefined
}

function readUInt64Hex(data: Buffer, offset: number, endian: 'be' | 'le'): string | undefined {
  if (offset + 8 > data.length) return undefined
  const value = endian === 'be' ? data.readBigUInt64BE(offset) : data.readBigUInt64LE(offset)
  return `0x${value.toString(16)}`
}

function readCString(data: Buffer, offset: number, size: number): string | undefined {
  if (offset < 0 || size <= 0 || offset >= data.length) return undefined
  const end = Math.min(offset + size, data.length)
  const raw = data.subarray(offset, end)
  const nul = raw.indexOf(0)
  const text = raw
    .subarray(0, nul >= 0 ? nul : raw.length)
    .toString('utf8')
    .trim()
  return text.length > 0 ? text : undefined
}

function readElfHeader(data: Buffer): LinuxBinaryInventory['elf_header'] | undefined {
  if (!isElf(data)) {
    return undefined
  }
  const endian = elfEndian(data)
  const elfClass = data[4]
  const type = readUInt16(data, 16, endian)
  const machine = readUInt16(data, 18, endian)
  const entrypoint =
    elfClass === 2
      ? readUInt64Hex(data, 24, endian)
      : data.length >= 28
        ? `0x${readUInt32(data, 24, endian).toString(16)}`
        : undefined
  return {
    class: elfClass === 2 ? '64-bit' : elfClass === 1 ? '32-bit' : undefined,
    endian: endian === 'be' ? 'big' : 'little',
    type: ELF_TYPES[type] ?? `elf-type-${type}`,
    machine: ELF_MACHINES[machine] ?? `elf-machine-${machine}`,
    osabi: ELF_OSABI[data[7]] ?? `osabi-${data[7]}`,
    entrypoint,
  }
}

function readElfProgramHeaderProfile(data: Buffer): {
  interpreter?: string
  dynamicSegmentPresent: boolean
  relroCandidate: boolean
  executableStackCandidate: boolean | null
  nxStackCandidate: boolean | null
} {
  if (!isElf(data)) {
    return {
      dynamicSegmentPresent: false,
      relroCandidate: false,
      executableStackCandidate: null,
      nxStackCandidate: null,
    }
  }

  const endian = elfEndian(data)
  const is64 = data[4] === 2
  const phoff = is64 ? readUInt64Number(data, 32, endian) : readUInt32(data, 28, endian)
  const phentsize = readUInt16(data, is64 ? 54 : 42, endian)
  const phnum = readUInt16(data, is64 ? 56 : 44, endian)
  if (!phoff || phentsize <= 0 || phnum <= 0) {
    return {
      dynamicSegmentPresent: false,
      relroCandidate: false,
      executableStackCandidate: null,
      nxStackCandidate: null,
    }
  }

  let interpreter: string | undefined
  let dynamicSegmentPresent = false
  let relroCandidate = false
  let executableStackCandidate: boolean | null = null
  const PT_INTERP = 3
  const PT_DYNAMIC = 2
  const PT_GNU_STACK = 0x6474e551
  const PT_GNU_RELRO = 0x6474e552
  const PF_X = 1

  for (let index = 0; index < phnum; index++) {
    const offset = phoff + index * phentsize
    if (offset + phentsize > data.length) break
    const type = readUInt32(data, offset, endian)
    const flags = is64
      ? readUInt32(data, offset + 4, endian)
      : readUInt32(data, offset + 24, endian)
    const segmentOffset = is64
      ? readUInt64Number(data, offset + 8, endian)
      : readUInt32(data, offset + 4, endian)
    const segmentSize = is64
      ? readUInt64Number(data, offset + 32, endian)
      : readUInt32(data, offset + 16, endian)

    if (type === PT_INTERP && segmentOffset !== undefined && segmentSize !== undefined) {
      interpreter = readCString(data, segmentOffset, segmentSize) ?? interpreter
    }
    if (type === PT_DYNAMIC) dynamicSegmentPresent = true
    if (type === PT_GNU_RELRO) relroCandidate = true
    if (type === PT_GNU_STACK) executableStackCandidate = Boolean(flags & PF_X)
  }

  return {
    interpreter,
    dynamicSegmentPresent,
    relroCandidate,
    executableStackCandidate,
    nxStackCandidate: executableStackCandidate === null ? null : executableStackCandidate === false,
  }
}

function detectFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[]; elfHeader?: LinuxBinaryInventory['elf_header'] } {
  const ext = extensionOf(filename)
  const basename = path.posix.basename((filename ?? '').replace(/\\/g, '/')).toLowerCase()
  const text = previewText(data)

  if (
    data.length >= 6 &&
    ['070701', '070702', '070707'].includes(data.subarray(0, 6).toString('ascii'))
  ) {
    return { format: 'cpio', detectedBy: ['cpio magic'] }
  }

  const elfHeader = readElfHeader(data)
  if (elfHeader) {
    if (ext === 'ko' || basename.endsWith('.ko') || text.includes('vermagic=')) {
      return {
        format: 'linux-kernel-module',
        detectedBy: ['ELF magic', ext === 'ko' ? 'ko extension' : 'vermagic marker'],
        elfHeader,
      }
    }
    if (elfHeader.type === 'core' || ext === 'core') {
      return {
        format: 'elf-core',
        detectedBy: ['ELF magic', elfHeader.type === 'core' ? 'ET_CORE' : 'core extension'],
        elfHeader,
      }
    }
    if (elfHeader.type === 'shared-object' || ext === 'so') {
      return {
        format: 'elf-so',
        detectedBy: ['ELF magic', elfHeader.type === 'shared-object' ? 'ET_DYN' : 'so extension'],
        elfHeader,
      }
    }
    if (elfHeader.type === 'executable') {
      return { format: 'elf-executable', detectedBy: ['ELF magic', 'ET_EXEC'], elfHeader }
    }
    return { format: 'elf', detectedBy: ['ELF magic'], elfHeader }
  }

  if (ext === 'core') return { format: 'elf-core', detectedBy: ['filename extension'] }
  if (ext === 'so') return { format: 'elf-so', detectedBy: ['filename extension'] }
  if (ext === 'ko') return { format: 'linux-kernel-module', detectedBy: ['filename extension'] }
  if (ext === 'cpio' || basename.includes('initramfs') || basename.includes('initrd')) {
    return { format: ext === 'cpio' ? 'cpio' : 'initramfs', detectedBy: ['filename hint'] }
  }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function extractInterpreterHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /\/(?:lib|lib64|usr\/lib)\/(?:ld-linux|ld-musl|ld-uClibc)[A-Za-z0-9_.\/-]*/g
    ) ?? []
  return Array.from(new Set(matches)).slice(0, 40)
}

function extractSharedLibraryHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(/[A-Za-z0-9_./+-]{1,180}\.so(?:\.[0-9][A-Za-z0-9_.-]*)?/g) ?? []
  return Array.from(new Set(matches)).slice(0, 160)
}

function extractRpathRunpathHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /(?:(?:RPATH|RUNPATH|LD_LIBRARY_PATH)=)?\/(?:lib|lib64|usr\/lib|usr\/local\/lib|opt)[A-Za-z0-9_./:+-]*/g
    ) ?? []
  return Array.from(new Set(matches.map((item) => item.replace(/^(?:RPATH|RUNPATH)=/, '')))).slice(
    0,
    80
  )
}

function extractSymbolHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /(?:GLIBC_[0-9.]+|CXXABI_[0-9.]+|GCC_[0-9.]+|_?Z[A-Za-z0-9_]{3,140}|_?[A-Za-z][A-Za-z0-9_]{3,120}|vermagic=[A-Za-z0-9_.+\-]+)/g
    ) ?? []
  return Array.from(new Set(matches))
    .filter((value) => value.length >= 4 && !/^[0-9]+$/.test(value))
    .slice(0, 200)
}

function buildLoaderSecurityProfile(args: {
  data: Buffer
  elfHeader?: LinuxBinaryInventory['elf_header']
  interpreterHints: string[]
  sharedLibraryHints: string[]
  symbolHints: string[]
}): LinuxBinaryLoaderSecurityProfile {
  const programHeaderProfile = readElfProgramHeaderProfile(args.data)
  const text = previewText(args.data)
  const interpreter = programHeaderProfile.interpreter ?? args.interpreterHints[0]
  const neededLibraries = args.sharedLibraryHints.filter((item) => !item.includes('/'))
  const bindNowCandidate = /\b(?:BIND_NOW|DF_BIND_NOW)\b/.test(text)
  const canarySymbolCandidate =
    /__(?:stack_chk_fail|stack_chk_guard)\b/.test(text) ||
    args.symbolHints.some((item) => ['__stack_chk_fail', '__stack_chk_guard'].includes(item))
  const pieCandidate =
    args.elfHeader?.type === 'shared-object'
      ? true
      : args.elfHeader?.type === 'executable'
        ? false
        : null
  const hardeningNotes = unique([
    programHeaderProfile.relroCandidate ? 'PT_GNU_RELRO segment candidate present.' : '',
    programHeaderProfile.nxStackCandidate === true
      ? 'PT_GNU_STACK is present without executable flag; NX stack candidate.'
      : '',
    programHeaderProfile.executableStackCandidate === true
      ? 'PT_GNU_STACK appears executable; review executable-stack risk.'
      : '',
    bindNowCandidate ? 'BIND_NOW marker candidate present in preview strings.' : '',
    canarySymbolCandidate ? 'Stack canary symbol candidate present.' : '',
    pieCandidate === true
      ? 'ET_DYN binary may be PIE or shared object; confirm with ELF parser.'
      : '',
  ])

  return {
    entrypoint: args.elfHeader?.entrypoint,
    interpreter,
    needed_libraries: unique(neededLibraries).slice(0, 120),
    rpath_runpath_hints: extractRpathRunpathHints(args.data),
    dynamic_segment_present: programHeaderProfile.dynamicSegmentPresent,
    pie_candidate: pieCandidate,
    nx_stack_candidate: programHeaderProfile.nxStackCandidate,
    executable_stack_candidate: programHeaderProfile.executableStackCandidate,
    relro_candidate: programHeaderProfile.relroCandidate,
    bind_now_candidate: bindNowCandidate,
    canary_symbol_candidate: canarySymbolCandidate,
    hardening_notes: hardeningNotes,
  }
}

function extractCoreHints(data: Buffer): string[] {
  const text = previewText(data)
  const matches =
    text.match(
      /(?:CORE|NT_PRSTATUS|NT_AUXV|NT_FILE|SIG[A-Z]+|\/(?:proc|lib|usr|home|tmp)\/[A-Za-z0-9_./+-]{2,180})/g
    ) ?? []
  return Array.from(new Set(matches)).slice(0, 120)
}

function extractKernelModuleHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /(?:vermagic=[A-Za-z0-9_.+\-]+|depends=[A-Za-z0-9_,.-]*|srcversion=[A-Fa-f0-9]+|intree=[YN]|retpoline=[YN]|name=[A-Za-z0-9_.-]+)/g
    ) ?? []
  return Array.from(new Set(matches)).slice(0, 120)
}

function parseCpioNewcMembers(data: Buffer): string[] {
  const members: string[] = []
  let offset = 0
  while (offset + 110 <= data.length && members.length < 500) {
    const magic = data.subarray(offset, offset + 6).toString('ascii')
    if (!['070701', '070702'].includes(magic)) break
    const namesize = Number.parseInt(data.subarray(offset + 94, offset + 102).toString('ascii'), 16)
    const filesize = Number.parseInt(data.subarray(offset + 54, offset + 62).toString('ascii'), 16)
    if (!Number.isFinite(namesize) || namesize <= 0 || namesize > 4096) break
    const nameStart = offset + 110
    const nameEnd = nameStart + namesize
    if (nameEnd > data.length) break
    const name = data.subarray(nameStart, nameEnd).toString('utf8').replace(/\0.*$/s, '')
    if (name === 'TRAILER!!!') break
    if (name) members.push(name)
    const namePad = (4 - (nameEnd % 4)) % 4
    const fileStart = nameEnd + namePad
    const fileEnd = fileStart + (Number.isFinite(filesize) ? filesize : 0)
    const filePad = (4 - (fileEnd % 4)) % 4
    if (fileEnd > data.length) break
    offset = fileEnd + filePad
  }
  return Array.from(new Set(members))
}

function extractPathTokens(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /[A-Za-z0-9_./@{}$+ -]{2,240}\.(?:elf|so|ko|o|a|core|debug|dwo|dwp|wasm|jar|dex|apk|bin|conf|service|rules|sh|cpio|squashfs|ubi|ubifs)/gi
    ) ?? []
  return Array.from(new Set(matches.map((item) => item.trim()).filter(Boolean))).slice(0, 400)
}

function routeCandidate(candidatePath: string): LinuxBinaryCandidate | null {
  const lower = candidatePath.toLowerCase()
  const routedFormats: string[] = []
  const recommendedTools: string[] = []

  if (/\.(?:elf|bin)$/.test(lower)) {
    routedFormats.push('elf', 'linux-binary')
    recommendedTools.push('linux.binary.inventory', 'elf.structure.analyze')
  }
  if (lower.endsWith('.so') || /\.so\.[0-9]/.test(lower)) {
    routedFormats.push('elf-so', 'so')
    recommendedTools.push('linux.binary.inventory', 'elf.structure.analyze')
  }
  if (lower.endsWith('.ko')) {
    routedFormats.push('linux-kernel-module', 'elf')
    recommendedTools.push(
      'linux.binary.inventory',
      'native.object.inventory',
      'elf.structure.analyze'
    )
  }
  if (lower.endsWith('.core') || lower.includes('/core.')) {
    routedFormats.push('elf-core', 'core')
    recommendedTools.push('linux.binary.inventory', 'strings.extract')
  }
  if (/\.(?:o|a|debug|dwo|dwp)$/.test(lower)) {
    routedFormats.push('object')
    recommendedTools.push('native.object.inventory')
  }
  if (/\.(?:cpio|squashfs|ubi|ubifs)$/.test(lower)) {
    routedFormats.push('firmware', lower.endsWith('.cpio') ? 'cpio' : 'filesystem')
    recommendedTools.push(lower.endsWith('.cpio') ? 'linux.binary.inventory' : 'firmware.scan')
  }
  if (lower.endsWith('.apk') || lower.endsWith('.dex')) {
    routedFormats.push('android')
    recommendedTools.push(lower.endsWith('.apk') ? 'android.package.inventory' : 'dex.classes.list')
  }
  if (lower.endsWith('.jar')) {
    routedFormats.push('jar', 'jvm')
    recommendedTools.push('jvm.structure.analyze')
  }
  if (lower.endsWith('.wasm')) {
    routedFormats.push('wasm')
    recommendedTools.push('wasm.structure.analyze')
  }

  if (recommendedTools.length === 0) return null
  return {
    path: candidatePath,
    routed_formats: Array.from(new Set(routedFormats)),
    recommended_tools: Array.from(new Set(recommendedTools)),
  }
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function buildEvidenceSummary(args: {
  inventory: Omit<LinuxBinaryInventory, 'evidence_summary' | 'workflow_handoff' | 'quality_gates'>
}) {
  const { inventory } = args
  return {
    schema: 'rikune.linux_binary_inventory.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: inventory.sample_id ?? null,
    format: inventory.format,
    detected_by: inventory.detected_by,
    elf_header_present: Boolean(inventory.elf_header),
    loader_profile_present: Boolean(inventory.loader_security_profile.entrypoint),
    interpreter_count: inventory.interpreter_hints.length,
    needed_library_count: inventory.loader_security_profile.needed_libraries.length,
    symbol_hint_count: inventory.symbol_hints.length,
    core_dump_hint_count: inventory.core_dump_hints.length,
    kernel_module_hint_count: inventory.kernel_module_hints.length,
    initramfs_member_count: inventory.initramfs_members.length,
    nested_candidate_count: inventory.nested_binary_candidates.length,
    hardening_candidates: {
      relro: inventory.loader_security_profile.relro_candidate,
      nx_stack: inventory.loader_security_profile.nx_stack_candidate,
      executable_stack: inventory.loader_security_profile.executable_stack_candidate,
      bind_now: inventory.loader_security_profile.bind_now_candidate,
      canary_symbol: inventory.loader_security_profile.canary_symbol_candidate,
      pie: inventory.loader_security_profile.pie_candidate,
    },
    static_only: true,
  }
}

function buildWorkflowHandoff(args: {
  inventory: Omit<LinuxBinaryInventory, 'evidence_summary' | 'workflow_handoff' | 'quality_gates'>
}) {
  const { inventory } = args
  return {
    schema: 'rikune.linux_binary_inventory.workflow_handoff.v1',
    handoff_mode: 'linux_binary_loader_security_to_static_runtime_planning',
    source_tool: TOOL_NAME,
    sample_id: inventory.sample_id ?? null,
    recommended_next_tools: inventory.recommended_next_tools,
    artifact_contract: {
      consumes: ['sample'],
      produces: [LINUX_BINARY_ARTIFACT_TYPE],
      expected_consumers: inventory.recommended_next_tools,
    },
    routing: [
      {
        goal: 'elf-structure-and-imports',
        next_tools: ['elf.structure.analyze', 'elf.imports.extract', 'elf.exports.extract'],
        required_evidence: ['elf_header', 'loader_security_profile'],
      },
      {
        goal: 'runtime-readiness-planning',
        next_tools: ['linux.runtime.plan', 'tool.readiness', 'analysis.evidence.graph'],
        required_evidence: ['interpreter_hints', 'needed_libraries', 'hardening_candidates'],
      },
      {
        goal: 'nested-artifact-routing',
        next_tools: unique(
          inventory.nested_binary_candidates.flatMap((candidate) => candidate.recommended_tools)
        ),
        required_evidence: ['nested_binary_candidates'],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      library_loaded_by_tool: false,
      core_replayed_by_tool: false,
      kernel_module_loaded_by_tool: false,
      filesystem_mounted_by_tool: false,
      runtime_started_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildQualityGates(args: {
  inventory: Omit<LinuxBinaryInventory, 'evidence_summary' | 'workflow_handoff' | 'quality_gates'>
}) {
  const { inventory } = args
  return {
    schema: 'rikune.linux_binary_inventory.quality_gates.v1',
    passive_static_inventory: true,
    bounded_preview_only: true,
    elf_header_present: Boolean(inventory.elf_header),
    loader_profile_present:
      Boolean(inventory.loader_security_profile.entrypoint) ||
      Boolean(inventory.loader_security_profile.interpreter),
    hardening_candidates_present: inventory.loader_security_profile.hardening_notes.length > 0,
    nested_routing_present: inventory.nested_binary_candidates.length > 0,
    sample_executed_by_tool: false,
    library_loaded_by_tool: false,
    core_replayed_by_tool: false,
    kernel_module_loaded_by_tool: false,
    filesystem_mounted_by_tool: false,
    runtime_started_by_tool: false,
  }
}

export function buildLinuxBinaryInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): LinuxBinaryInventory {
  const detected = detectFormat(data, options.filename)
  const initramfsMembers = parseCpioNewcMembers(data)
  const pathTokens = unique([...initramfsMembers, ...extractPathTokens(data)]).slice(0, 600)
  const nested = pathTokens
    .map(routeCandidate)
    .filter((candidate): candidate is LinuxBinaryCandidate => Boolean(candidate))
    .slice(0, 200)
  const interpreterHints = extractInterpreterHints(data)
  const sharedLibraryHints = extractSharedLibraryHints(data)
  const symbolHints = extractSymbolHints(data)
  const loaderSecurityProfile = buildLoaderSecurityProfile({
    data,
    elfHeader: detected.elfHeader,
    interpreterHints,
    sharedLibraryHints,
    symbolHints,
  })
  const coreDumpHints = detected.format === 'elf-core' ? extractCoreHints(data) : []
  const kernelModuleHints =
    detected.format === 'linux-kernel-module' ? extractKernelModuleHints(data) : []
  const unsupported =
    detected.format === 'cpio' || detected.format === 'initramfs'
      ? 'Initramfs member extraction is represented as a static plan only; this tool does not mount or boot the image.'
      : detected.format === 'elf-core'
        ? 'Core dump inspection is static only; this tool does not replay the process or attach a debugger.'
        : undefined

  const inventoryBase = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: detected.detectedBy,
    size: options.size ?? data.length,
    elf_header: detected.elfHeader,
    loader_security_profile: loaderSecurityProfile,
    interpreter_hints: interpreterHints,
    shared_library_hints: sharedLibraryHints,
    symbol_hints: symbolHints,
    core_dump_hints: coreDumpHints,
    kernel_module_hints: kernelModuleHints,
    initramfs_members: initramfsMembers.slice(0, 300),
    nested_binary_candidates: nested,
    policy: {
      passive: true as const,
      no_execute: true as const,
      no_load: true as const,
      no_core_replay: true as const,
      no_kernel_module_load: true as const,
      no_mount: true as const,
      no_runtime_start: true as const,
    },
    unsupported_detail: unsupported,
    summary: `Passive Linux binary inventory detected ${detected.format} with ${sharedLibraryHints.length} shared library hint(s), ${symbolHints.length} symbol hint(s), ${initramfsMembers.length} initramfs member(s), and ${nested.length} nested candidate(s).`,
    recommended_next_tools: unique([
      'metadata.extract',
      'strings.extract',
      detected.format.startsWith('elf') ||
      detected.format === 'linux-kernel-module' ||
      detected.format === 'elf-so'
        ? 'elf.structure.analyze'
        : '',
      detected.format === 'linux-kernel-module' ? 'native.object.inventory' : '',
      detected.format === 'cpio' || detected.format === 'initramfs'
        ? 'container.structure.analyze'
        : '',
      detected.elfHeader ? 'linux.runtime.plan' : '',
      detected.elfHeader ? 'analysis.evidence.graph' : '',
      ...nested.flatMap((candidate) => candidate.recommended_tools),
    ]),
    next_actions: [
      'Review ELF header, interpreter, shared-library, symbol, core, and module hints as static metadata.',
      'Treat hardening values as candidates until corroborated by a full ELF parser such as elf.structure.analyze.',
      'Ingest nested initramfs members or linked objects separately before format-specific analysis.',
      'Do not execute binaries, dlopen libraries, replay core dumps, insert kernel modules, mount filesystems, or start emulators during passive triage.',
    ],
  }
  return {
    ...inventoryBase,
    evidence_summary: buildEvidenceSummary({ inventory: inventoryBase }),
    workflow_handoff: buildWorkflowHandoff({ inventory: inventoryBase }),
    quality_gates: buildQualityGates({ inventory: inventoryBase }),
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

export function createLinuxBinaryInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (args: z.infer<typeof LinuxBinaryInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = LinuxBinaryInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildLinuxBinaryInventoryFromBuffer(data, {
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
            'linux_binary_inventory',
            'linux-binary-inventory',
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
