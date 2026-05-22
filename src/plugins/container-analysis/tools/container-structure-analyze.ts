/**
 * container.structure.analyze — passive archive/container inventory.
 *
 * This tool never executes payloads, installer hooks, or container entrypoints.
 * It also does not mount disk images. It reads bounded previews and returns
 * extraction/routing plans only.
 */

import crypto from 'crypto'
import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'container.structure.analyze'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_ENTRIES = 1000
const ZIP_BOMB_RATIO_THRESHOLD = 100
const ZIP_BOMB_UNCOMPRESSED_THRESHOLD = 512 * 1024 * 1024

const ContainerPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_extract_to_execution_path: z.literal(true),
  no_install: z.literal(true),
  no_mount: z.literal(true),
  no_entrypoint_run: z.literal(true),
})

const ContainerEntrySchema = z.object({
  path: z.string(),
  size: z.number().optional(),
  compressed_size: z.number().optional(),
  type_hint: z.string(),
  risk_flags: z.array(z.string()),
})

const NestedBinarySchema = z.object({
  path: z.string(),
  routed_formats: z.array(z.string()),
  recommended_tools: z.array(z.string()),
})

const ContainerStructureDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  container_format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  sha256_preview: z.string(),
  entries: z.array(ContainerEntrySchema),
  entries_truncated: z.boolean(),
  nested_binary_candidates: z.array(NestedBinarySchema),
  manifest_candidates: z.array(z.string()),
  entrypoint_candidates: z.array(z.string()),
  risk_flags: z.array(z.string()),
  extraction_plan: z.object({
    status: z.literal('plan_only'),
    safe_default: z.literal(true),
    max_entries: z.number(),
    notes: z.array(z.string()),
  }),
  policy: ContainerPolicySchema,
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const ContainerStructureAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive container inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist container inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const ContainerStructureAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: ContainerStructureDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const containerStructureAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory archive/container files, detect nested binaries, flag extraction risks, and return an extraction plan without running payloads.',
  inputSchema: ContainerStructureAnalyzeInputSchema,
  outputSchema: ContainerStructureAnalyzeOutputSchema,
  aspects: {
    formats: [
      'archive',
      'container',
      'zip',
      '7z',
      'rar',
      'tar',
      'gz',
      'xz',
      'zstd',
      'iso',
      'ar',
      'static-lib',
      'ar-static-lib',
      'docker-image',
      'oci-image',
      'installer',
    ],
    platforms: ['windows', 'linux', 'macos', 'ios', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_installer_execution', 'no_auto_mount', 'no_live_sample_by_default'],
    capabilities: ['inventory', 'nested-binaries', 'hashes', 'extraction-plan', 'routing'],
    evidence: ['nested-binaries', 'filesystem', 'package-metadata', 'provenance'],
  },
  artifacts: [
    {
      type: 'container_structure',
      description:
        'Passive container member inventory, extraction safety plan, and nested routing hints',
    },
  ],
  evidence: [
    {
      category: 'nested-binaries',
      artifactTypes: ['container_structure'],
    },
    {
      category: 'filesystem',
      artifactTypes: ['container_structure'],
    },
  ],
}

export type ContainerStructureInventory = z.infer<typeof ContainerStructureDataSchema>
type ContainerEntry = ContainerStructureInventory['entries'][number]
type NestedBinaryCandidate = ContainerStructureInventory['nested_binary_candidates'][number]

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  if (base.endsWith('.tar.gz') || base.endsWith('.tgz')) return 'tar.gz'
  if (base.endsWith('.tar.xz')) return 'tar.xz'
  if (base.endsWith('.tar.zst') || base.endsWith('.tar.zstd')) return 'tar.zstd'
  return base.slice(base.lastIndexOf('.') + 1)
}

function previewText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
}

function detectContainerFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  const text = previewText(data)
  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) {
    if (text.includes('oci-layout'))
      return { format: 'oci-image', detectedBy: ['zip magic', 'oci-layout marker'] }
    if (text.includes('manifest.json') && text.includes('layer')) {
      return { format: 'docker-image', detectedBy: ['zip magic', 'Docker manifest marker'] }
    }
    return { format: ext || 'zip', detectedBy: ['zip magic'] }
  }
  if (data.length >= 262 && data.subarray(257, 262).toString('ascii') === 'ustar') {
    if (text.includes('oci-layout'))
      return { format: 'oci-image', detectedBy: ['tar ustar magic', 'oci-layout marker'] }
    if (text.includes('manifest.json') && text.includes('layer')) {
      return { format: 'docker-image', detectedBy: ['tar ustar magic', 'Docker manifest marker'] }
    }
    return { format: 'tar', detectedBy: ['tar ustar magic'] }
  }
  if (
    data.length >= 6 &&
    data[0] === 0x37 &&
    data[1] === 0x7a &&
    data[2] === 0xbc &&
    data[3] === 0xaf &&
    data[4] === 0x27 &&
    data[5] === 0x1c
  ) {
    return { format: '7z', detectedBy: ['7z magic'] }
  }
  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'Rar!') {
    return { format: 'rar', detectedBy: ['RAR magic'] }
  }
  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) {
    return { format: ext === 'tar.gz' ? 'tar.gz' : 'gz', detectedBy: ['gzip magic'] }
  }
  if (
    data.length >= 6 &&
    data[0] === 0xfd &&
    data[1] === 0x37 &&
    data[2] === 0x7a &&
    data[3] === 0x58 &&
    data[4] === 0x5a &&
    data[5] === 0x00
  ) {
    return { format: ext === 'tar.xz' ? 'tar.xz' : 'xz', detectedBy: ['xz magic'] }
  }
  if (
    data.length >= 4 &&
    data[0] === 0x28 &&
    data[1] === 0xb5 &&
    data[2] === 0x2f &&
    data[3] === 0xfd
  ) {
    return { format: ext === 'tar.zstd' ? 'tar.zstd' : 'zstd', detectedBy: ['zstd magic'] }
  }
  if (data.length >= 0x8006 && data.subarray(0x8001, 0x8006).toString('ascii') === 'CD001') {
    return { format: 'iso', detectedBy: ['ISO9660 CD001 marker'] }
  }
  if (data.length >= 8 && data.subarray(0, 8).toString('ascii') === '!<arch>\n') {
    return {
      format: ext === 'a' ? 'ar-static-lib' : ext === 'lib' ? 'static-lib' : 'ar',
      detectedBy: ['ar magic'],
    }
  }
  if (
    [
      'zip',
      '7z',
      'rar',
      'tar',
      'gz',
      'xz',
      'zst',
      'zstd',
      'iso',
      'oci',
      'docker',
      'ar',
      'a',
      'lib',
    ].includes(ext)
  ) {
    return {
      format:
        ext === 'oci'
          ? 'oci-image'
          : ext === 'docker'
            ? 'docker-image'
            : ext === 'a'
              ? 'ar-static-lib'
              : ext === 'lib'
                ? 'static-lib'
                : ext,
      detectedBy: ['filename extension'],
    }
  }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function classifyEntryPath(entryPath: string): string {
  const lower = entryPath.toLowerCase()
  if (lower.endsWith('/')) return 'directory'
  if (/\.(?:exe|dll|sys|scr|efi)$/.test(lower)) return 'pe'
  if (/\.(?:ko)$/.test(lower)) return 'linux-kernel-module'
  if (/(?:^|\/)core(?:\.[A-Za-z0-9_.-]+)?$/.test(lower) || lower.endsWith('.core'))
    return 'elf-core'
  if (/\.(?:elf|so|bin)$/.test(lower)) return 'elf'
  if (/\.(?:o|obj)$/.test(lower)) return 'native-object'
  if (/\.(?:a|lib)$/.test(lower)) return 'static-lib'
  if (
    /\.(?:dylib|macho)$/.test(lower) ||
    lower.includes('.framework/') ||
    lower.endsWith('.framework') ||
    lower.endsWith('.xcframework')
  )
    return 'macho'
  if (lower.endsWith('.dsym')) return 'debug-metadata'
  if (/\.(?:apk|aab|apks|xapk)$/.test(lower)) return 'android-package'
  if (/\.(?:dex|vdex|oat|odex|art)$/.test(lower)) return 'android-bytecode'
  if (/\.(?:jar|war|aar|jmod|class)$/.test(lower)) return 'jvm'
  if (/\.(?:nupkg|winmd)$/.test(lower)) return 'dotnet'
  if (lower.endsWith('global-metadata.dat') || lower.includes('il2cpp')) return 'unity'
  if (lower.endsWith('.wasm')) return 'wasm'
  if (/\.(?:pyc|luac|jsc|blob)$/.test(lower)) return 'script-bytecode'
  if (/\.(?:deb|rpm|appimage|snap|flatpak)$/.test(lower)) return 'linux-package'
  if (/\.(?:msi|msix|appx|cab)$/.test(lower)) return 'windows-installer'
  if (/\.(?:ipa|dmg|pkg|mobileprovision)$/.test(lower)) return 'apple-container'
  if (
    /\.(?:uimage|fit|itb|dtb|cpio|squashfs|cramfs|jffs2|ubi|ubifs|romfs)$/.test(lower) ||
    /(?:^|\/)(?:uimage|zimage|vmlinuz|initramfs|initrd)$/.test(lower)
  )
    return 'firmware'
  if (/\.(?:zip|7z|rar|tar|gz|xz|zst|zstd|iso)$/.test(lower)) return 'archive'
  return 'file'
}

function riskFlagsForPath(
  entryPath: string,
  uncompressedSize?: number,
  compressedSize?: number
): string[] {
  const normalized = entryPath.replace(/\\/g, '/')
  const flags: string[] = []
  if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) flags.push('absolute-path')
  if (normalized.split('/').includes('..')) flags.push('path-traversal')
  if (normalized.includes('\0')) flags.push('nul-byte')
  if (
    typeof uncompressedSize === 'number' &&
    typeof compressedSize === 'number' &&
    compressedSize > 0 &&
    uncompressedSize / compressedSize >= ZIP_BOMB_RATIO_THRESHOLD
  ) {
    flags.push('high-compression-ratio')
  }
  if (typeof uncompressedSize === 'number' && uncompressedSize >= ZIP_BOMB_UNCOMPRESSED_THRESHOLD) {
    flags.push('large-uncompressed-entry')
  }
  return flags
}

function parseZipLocalEntries(data: Buffer): { entries: ContainerEntry[]; truncated: boolean } {
  const entries: ContainerEntry[] = []
  let offset = 0

  while (offset + 30 <= data.length && entries.length < MAX_ENTRIES) {
    if (data.readUInt32LE(offset) !== 0x04034b50) {
      offset += 1
      continue
    }

    const compressedSize = data.readUInt32LE(offset + 18)
    const uncompressedSize = data.readUInt32LE(offset + 22)
    const nameLength = data.readUInt16LE(offset + 26)
    const extraLength = data.readUInt16LE(offset + 28)
    const nameStart = offset + 30
    const nameEnd = nameStart + nameLength
    if (nameEnd > data.length) break

    const entryPath = data.subarray(nameStart, nameEnd).toString('utf8')
    if (entryPath) {
      entries.push({
        path: entryPath,
        size: uncompressedSize,
        compressed_size: compressedSize,
        type_hint: classifyEntryPath(entryPath),
        risk_flags: riskFlagsForPath(entryPath, uncompressedSize, compressedSize),
      })
    }

    const nextOffset = nameEnd + extraLength + compressedSize
    offset = nextOffset > offset && nextOffset <= data.length ? nextOffset : nameEnd + extraLength
  }

  return { entries, truncated: entries.length >= MAX_ENTRIES }
}

function parseTarEntries(data: Buffer): { entries: ContainerEntry[]; truncated: boolean } {
  const entries: ContainerEntry[] = []
  let offset = 0
  while (offset + 512 <= data.length && entries.length < MAX_ENTRIES) {
    const block = data.subarray(offset, offset + 512)
    if (block.every((byte) => byte === 0)) break
    const name = block.subarray(0, 100).toString('utf8').replace(/\0.*$/s, '')
    const prefix = block.subarray(345, 500).toString('utf8').replace(/\0.*$/s, '')
    const entryPath = prefix ? `${prefix}/${name}` : name
    const sizeText = block.subarray(124, 136).toString('ascii').replace(/\0.*$/s, '').trim()
    const size = Number.parseInt(sizeText || '0', 8)
    if (!entryPath) break
    entries.push({
      path: entryPath,
      size: Number.isFinite(size) ? size : undefined,
      type_hint: classifyEntryPath(entryPath),
      risk_flags: riskFlagsForPath(entryPath, Number.isFinite(size) ? size : undefined),
    })
    const dataBlocks = Number.isFinite(size) ? Math.ceil(size / 512) : 0
    offset += 512 + dataBlocks * 512
  }
  return { entries, truncated: entries.length >= MAX_ENTRIES }
}

function extractTextPathEntries(data: Buffer): ContainerEntry[] {
  const matches =
    previewText(data).match(
      /[A-Za-z0-9_./@{}$+ -]{2,240}\.(?:exe|dll|sys|scr|efi|elf|so|ko|o|obj|a|lib|dylib|macho|framework|xcframework|dsym|apk|aab|apks|xapk|dex|vdex|oat|odex|art|jar|war|aar|jmod|class|nupkg|winmd|wasm|pyc|luac|jsc|blob|deb|rpm|appimage|snap|flatpak|msi|msix|appx|cab|ipa|dmg|pkg|mobileprovision|uimage|fit|itb|dtb|cpio|squashfs|cramfs|jffs2|ubi|ubifs|romfs|bin|zip|tar|gz|xz|zst|zstd|7z|rar|iso)/gi
    ) ?? []
  return Array.from(new Set(matches.map((item) => item.trim()).filter(Boolean)))
    .slice(0, 300)
    .map((entryPath) => ({
      path: entryPath,
      type_hint: classifyEntryPath(entryPath),
      risk_flags: riskFlagsForPath(entryPath),
    }))
}

function entriesFor(
  data: Buffer,
  format: string
): { entries: ContainerEntry[]; truncated: boolean } {
  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) return parseZipLocalEntries(data)
  if (format === 'tar' || format === 'docker-image' || format === 'oci-image') {
    return parseTarEntries(data)
  }
  return { entries: extractTextPathEntries(data), truncated: false }
}

function routeEntry(entry: ContainerEntry): NestedBinaryCandidate | null {
  const format = entry.type_hint
  const recommendedTools: string[] = []
  const routedFormats: string[] = []
  switch (format) {
    case 'pe':
      routedFormats.push('pe')
      recommendedTools.push('pe.structure.analyze')
      break
    case 'elf':
      routedFormats.push('elf')
      recommendedTools.push('linux.binary.inventory', 'elf.structure.analyze')
      break
    case 'elf-core':
      routedFormats.push('elf-core', 'linux-binary')
      recommendedTools.push('linux.binary.inventory', 'strings.extract')
      break
    case 'linux-kernel-module':
      routedFormats.push('linux-kernel-module', 'elf')
      recommendedTools.push(
        'linux.binary.inventory',
        'native.object.inventory',
        'elf.structure.analyze'
      )
      break
    case 'native-object':
      routedFormats.push('object')
      recommendedTools.push('native.object.inventory')
      break
    case 'static-lib':
      routedFormats.push('static-lib')
      recommendedTools.push('native.object.inventory')
      break
    case 'macho':
      routedFormats.push('macho')
      recommendedTools.push('apple.signing.inspect', 'macho.structure.analyze')
      break
    case 'debug-metadata':
      routedFormats.push('dsym', 'debug-metadata')
      recommendedTools.push('native.object.inventory')
      break
    case 'android-package':
      routedFormats.push('apk')
      recommendedTools.push('android.package.inventory', 'apk.structure.analyze')
      break
    case 'android-bytecode':
      routedFormats.push('dex')
      recommendedTools.push('android.package.inventory', 'dex.classes.list')
      break
    case 'jvm':
      routedFormats.push('jar', 'jvm')
      recommendedTools.push('jvm.structure.analyze')
      break
    case 'dotnet':
      routedFormats.push('dotnet')
      recommendedTools.push('dotnet.assembly.inspect')
      break
    case 'unity':
      routedFormats.push('unity', 'il2cpp')
      recommendedTools.push('unity.metadata.inspect')
      break
    case 'wasm':
      routedFormats.push('wasm')
      recommendedTools.push('wasm.structure.analyze')
      break
    case 'script-bytecode':
      routedFormats.push('pyc', 'lua-bytecode', 'v8-cache')
      recommendedTools.push('bytecode.metadata.inspect')
      break
    case 'linux-package':
      routedFormats.push('deb', 'rpm', 'appimage')
      recommendedTools.push('linux.package.inventory')
      break
    case 'windows-installer':
      routedFormats.push('installer')
      recommendedTools.push('installer.inventory')
      break
    case 'apple-container':
      routedFormats.push('ipa', 'dmg', 'pkg')
      recommendedTools.push('apple.container.inventory', 'apple.signing.inspect')
      break
    case 'firmware':
      routedFormats.push('firmware')
      recommendedTools.push('firmware.scan', 'firmware.entropy')
      break
    case 'archive':
      routedFormats.push('archive')
      recommendedTools.push('container.structure.analyze')
      break
    default:
      break
  }
  if (recommendedTools.length === 0) return null
  return {
    path: entry.path,
    routed_formats: Array.from(new Set(routedFormats)),
    recommended_tools: Array.from(new Set(recommendedTools)),
  }
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

export function buildContainerStructureFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): ContainerStructureInventory {
  const { format, detectedBy } = detectContainerFormat(data, options.filename)
  const parsed = entriesFor(data, format)
  const allEntries = parsed.entries
  const riskFlags = unique(allEntries.flatMap((entry) => entry.risk_flags))
  const nested = allEntries
    .map(routeEntry)
    .filter((candidate): candidate is NestedBinaryCandidate => Boolean(candidate))
    .slice(0, 300)
  const lowerMembers = allEntries.map((entry) => entry.path.toLowerCase())
  const manifestCandidates = allEntries
    .filter((entry) =>
      /(?:manifest\.json|oci-layout|config\.json|appxmanifest\.xml|androidmanifest\.xml|info\.plist|\.nuspec)$/i.test(
        entry.path
      )
    )
    .map((entry) => entry.path)
    .slice(0, 100)
  const entrypointCandidates = allEntries
    .filter((entry) =>
      /(?:entrypoint|cmd|postinst|preinst|install|setup|dockerfile)/i.test(entry.path)
    )
    .map((entry) => entry.path)
    .slice(0, 100)
  const unsupported = [
    '7z',
    'rar',
    'gz',
    'xz',
    'zstd',
    'tar.gz',
    'tar.xz',
    'tar.zstd',
    'iso',
  ].includes(format)
    ? 'Deep member listing for this container requires optional decompression or filesystem tooling; this tool keeps default behavior passive.'
    : undefined
  const formatRiskFlags = [
    format === 'docker-image' || format === 'oci-image' ? 'container-entrypoint-not-run' : '',
    lowerMembers.some((member) => member.includes('postinst') || member.includes('preinst'))
      ? 'installer-hooks-present'
      : '',
  ]

  const combinedRiskFlags = unique([...riskFlags, ...formatRiskFlags])

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    container_format: format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    sha256_preview: crypto.createHash('sha256').update(data).digest('hex'),
    entries: allEntries.slice(0, MAX_ENTRIES),
    entries_truncated: parsed.truncated,
    nested_binary_candidates: nested,
    manifest_candidates: manifestCandidates,
    entrypoint_candidates: entrypointCandidates,
    risk_flags: combinedRiskFlags,
    extraction_plan: {
      status: 'plan_only',
      safe_default: true,
      max_entries: MAX_ENTRIES,
      notes: [
        'Inventory first; extract only into a non-executable quarantine directory after reviewing risk flags.',
        'Reject absolute paths, parent-directory traversal, and high compression ratio entries before extraction.',
        'Do not mount disk images, install packages, or run container entrypoints/hooks during static triage.',
      ],
    },
    policy: {
      passive: true,
      no_execute: true,
      no_extract_to_execution_path: true,
      no_install: true,
      no_mount: true,
      no_entrypoint_run: true,
    },
    unsupported_detail: unsupported,
    summary: `Passive container inventory detected ${format} with ${allEntries.length} member/path hint(s), ${nested.length} nested binary candidate(s), and ${combinedRiskFlags.length} risk flag(s).`,
    recommended_next_tools: unique([
      'metadata.extract',
      'strings.extract',
      ...nested.flatMap((candidate) => candidate.recommended_tools),
    ]),
    next_actions: [
      'Review risk flags before extracting any member.',
      'Ingest nested binary candidates separately and route them to format-specific static plugins.',
      'Do not execute payloads, installer hooks, or container entrypoints during static triage.',
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

export function createContainerStructureAnalyzeHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (
    args: z.infer<typeof ContainerStructureAnalyzeInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = ContainerStructureAnalyzeInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildContainerStructureFromBuffer(data, {
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
            'container_structure',
            'container-structure',
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
