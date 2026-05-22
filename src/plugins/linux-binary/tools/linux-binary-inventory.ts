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
    })
    .optional(),
  interpreter_hints: z.array(z.string()),
  shared_library_hints: z.array(z.string()),
  symbol_hints: z.array(z.string()),
  core_dump_hints: z.array(z.string()),
  kernel_module_hints: z.array(z.string()),
  initramfs_members: z.array(z.string()),
  nested_binary_candidates: z.array(LinuxBinaryCandidateSchema),
  policy: LinuxBinaryPolicySchema,
  unsupported_detail: z.string().optional(),
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
    safety: ['passive', 'no_auto_mount', 'no_live_sample_by_default'],
    capabilities: [
      'inventory',
      'structure',
      'symbols',
      'debug-metadata',
      'nested-binaries',
      'routing',
    ],
    evidence: ['structure', 'symbols', 'filesystem', 'memory', 'nested-binaries', 'provenance'],
  },
  artifacts: [
    {
      type: 'linux_binary_inventory',
      description: 'Passive Linux ELF/core/module/initramfs inventory and routing hints',
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: ['linux_binary_inventory'] },
    { category: 'symbols', artifactTypes: ['linux_binary_inventory'] },
    { category: 'memory', artifactTypes: ['linux_binary_inventory'] },
    { category: 'nested-binaries', artifactTypes: ['linux_binary_inventory'] },
  ],
}

export type LinuxBinaryInventory = z.infer<typeof LinuxBinaryInventoryDataSchema>
type LinuxBinaryCandidate = z.infer<typeof LinuxBinaryCandidateSchema>

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

function readElfHeader(data: Buffer): LinuxBinaryInventory['elf_header'] | undefined {
  if (
    data.length < 20 ||
    data[0] !== 0x7f ||
    data[1] !== 0x45 ||
    data[2] !== 0x4c ||
    data[3] !== 0x46
  ) {
    return undefined
  }
  const endian = data[5] === 2 ? 'be' : 'le'
  const readUInt16 = (offset: number) =>
    endian === 'be' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
  const type = data.length >= 18 ? readUInt16(16) : 0
  const machine = data.length >= 20 ? readUInt16(18) : 0
  return {
    class: data[4] === 2 ? '64-bit' : data[4] === 1 ? '32-bit' : undefined,
    endian: endian === 'be' ? 'big' : 'little',
    type: ELF_TYPES[type] ?? `elf-type-${type}`,
    machine: ELF_MACHINES[machine] ?? `elf-machine-${machine}`,
    osabi: ELF_OSABI[data[7]] ?? `osabi-${data[7]}`,
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

function extractSymbolHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /(?:GLIBC_[0-9.]+|CXXABI_[0-9.]+|GCC_[0-9.]+|_?Z[A-Za-z0-9_]{3,140}|_?[A-Za-z][A-Za-z0-9_]{3,120}|vermagic=[A-Za-z0-9_.+\-]+)/g
    ) ?? []
  return Array.from(new Set(matches))
    .filter((value) => value.length >= 4 && !/^[0-9]+$/.test(value))
    .slice(0, 200)
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
  const coreDumpHints = detected.format === 'elf-core' ? extractCoreHints(data) : []
  const kernelModuleHints =
    detected.format === 'linux-kernel-module' ? extractKernelModuleHints(data) : []
  const unsupported =
    detected.format === 'cpio' || detected.format === 'initramfs'
      ? 'Initramfs member extraction is represented as a static plan only; this tool does not mount or boot the image.'
      : detected.format === 'elf-core'
        ? 'Core dump inspection is static only; this tool does not replay the process or attach a debugger.'
        : undefined

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: detected.detectedBy,
    size: options.size ?? data.length,
    elf_header: detected.elfHeader,
    interpreter_hints: interpreterHints,
    shared_library_hints: sharedLibraryHints,
    symbol_hints: symbolHints,
    core_dump_hints: coreDumpHints,
    kernel_module_hints: kernelModuleHints,
    initramfs_members: initramfsMembers.slice(0, 300),
    nested_binary_candidates: nested,
    policy: {
      passive: true,
      no_execute: true,
      no_load: true,
      no_core_replay: true,
      no_kernel_module_load: true,
      no_mount: true,
      no_runtime_start: true,
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
      ...nested.flatMap((candidate) => candidate.recommended_tools),
    ]),
    next_actions: [
      'Review ELF header, interpreter, shared-library, symbol, core, and module hints as static metadata.',
      'Ingest nested initramfs members or linked objects separately before format-specific analysis.',
      'Do not execute binaries, dlopen libraries, replay core dumps, insert kernel modules, mount filesystems, or start emulators during passive triage.',
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
