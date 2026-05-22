/**
 * android.package.inventory — passive Android package and bytecode inventory.
 *
 * This tool does not install packages, launch Android runtimes, connect to
 * devices, or start decompilers. It reads bounded previews and returns routing
 * hints for DEX, native ELF libraries, split packages, and signing metadata.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'android.package.inventory'
const DEFAULT_MAX_READ_BYTES = 6 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024

const AndroidPackagePolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_install: z.literal(true),
  no_runtime_start: z.literal(true),
  no_decompiler_launch: z.literal(true),
  no_device_connection: z.literal(true),
})

const RoutedCandidateSchema = z.object({
  path: z.string(),
  routed_formats: z.array(z.string()),
  recommended_tools: z.array(z.string()),
})

const AndroidPackageInventoryDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  package_format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  archive_members: z.array(z.string()),
  manifest_candidates: z.array(z.string()),
  dex_candidates: z.array(z.string()),
  native_library_candidates: z.array(RoutedCandidateSchema),
  resource_candidates: z.array(z.string()),
  signing_candidates: z.array(z.string()),
  split_package_candidates: z.array(z.string()),
  nested_package_candidates: z.array(RoutedCandidateSchema),
  policy: AndroidPackagePolicySchema,
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const AndroidPackageInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target Android package or bytecode sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive Android package inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const AndroidPackageInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: AndroidPackageInventoryDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const androidPackageInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Android APK/AAB/APKS/XAPK/AAR and standalone DEX/OAT/VDEX/ODEX/ART files. Does not install, execute, connect to devices, or launch decompilers.',
  inputSchema: AndroidPackageInventoryInputSchema,
  outputSchema: AndroidPackageInventoryOutputSchema,
  aspects: {
    formats: [
      'android-package',
      'apk',
      'aab',
      'apks',
      'xapk',
      'split-apk',
      'aar',
      'dex',
      'multi-dex',
      'oat',
      'vdex',
      'odex',
      'art',
      'apk-signature',
      'arsc',
    ],
    platforms: ['android', 'jvm', 'linux'],
    architectures: ['arm', 'arm64', 'x86', 'x64', 'riscv'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['inventory', 'manifest', 'resources', 'signatures', 'native-lib', 'routing'],
    evidence: ['structure', 'manifest', 'signatures', 'nested-binaries', 'provenance'],
  },
  artifacts: [
    {
      type: 'android_package_inventory',
      description: 'Passive Android package, bytecode, native library, and signing inventory',
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: ['android_package_inventory'] },
    { category: 'manifest', artifactTypes: ['android_package_inventory'] },
    { category: 'signatures', artifactTypes: ['android_package_inventory'] },
    { category: 'nested-binaries', artifactTypes: ['android_package_inventory'] },
  ],
}

export type AndroidPackageInventory = z.infer<typeof AndroidPackageInventoryDataSchema>
type RoutedCandidate = z.infer<typeof RoutedCandidateSchema>

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function previewText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
}

function detectAndroidFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  const text = previewText(data)

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'dex\n') {
    return { format: 'dex', detectedBy: ['DEX magic'] }
  }
  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'vdex') {
    return { format: 'vdex', detectedBy: ['VDEX magic'] }
  }
  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'oat\n') {
    return { format: 'oat', detectedBy: ['OAT magic'] }
  }
  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'dey\n') {
    return { format: 'odex', detectedBy: ['ODEX magic'] }
  }
  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'art\n') {
    return { format: 'art', detectedBy: ['ART magic'] }
  }

  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) {
    if (['apk', 'aab', 'apks', 'xapk', 'aar'].includes(ext)) {
      return { format: ext, detectedBy: ['zip magic', 'filename extension'] }
    }
    if (text.includes('base/manifest/AndroidManifest.xml')) {
      return { format: 'aab', detectedBy: ['zip magic', 'AAB manifest marker'] }
    }
    if (text.includes('splits/') && text.includes('.apk')) {
      return { format: 'apks', detectedBy: ['zip magic', 'split APK marker'] }
    }
    if (text.includes('AndroidManifest.xml') && text.includes('classes.jar')) {
      return { format: 'aar', detectedBy: ['zip magic', 'AAR classes.jar marker'] }
    }
    if (text.includes('AndroidManifest.xml') || text.includes('classes.dex')) {
      return { format: 'apk', detectedBy: ['zip magic', 'Android package marker'] }
    }
    return { format: 'zip', detectedBy: ['zip magic'] }
  }

  if (['apk', 'aab', 'apks', 'xapk', 'aar', 'dex', 'vdex', 'oat', 'odex', 'art'].includes(ext)) {
    return { format: ext, detectedBy: ['filename extension'] }
  }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function parseZipLocalMembers(data: Buffer): string[] {
  const members: string[] = []
  let offset = 0
  while (offset + 30 <= data.length && members.length < 600) {
    if (data.readUInt32LE(offset) !== 0x04034b50) {
      offset += 1
      continue
    }

    const compressedSize = data.readUInt32LE(offset + 18)
    const nameLength = data.readUInt16LE(offset + 26)
    const extraLength = data.readUInt16LE(offset + 28)
    const nameStart = offset + 30
    const nameEnd = nameStart + nameLength
    if (nameEnd > data.length) break

    const name = data.subarray(nameStart, nameEnd).toString('utf8')
    if (name) members.push(name)

    const nextOffset = nameEnd + extraLength + compressedSize
    offset = nextOffset > offset && nextOffset <= data.length ? nextOffset : nameEnd + extraLength
  }
  return Array.from(new Set(members))
}

function extractPathTokens(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /[A-Za-z0-9_./@{}$+ -]{2,240}\.(?:apk|aab|apks|xapk|aar|dex|vdex|oat|odex|art|so|jar|wasm|arsc|xml|RSA|DSA|EC|SF|MF|idsig)/g
    ) ?? []
  return Array.from(new Set(matches.map((item) => item.trim()).filter(Boolean))).slice(0, 400)
}

function routeAndroidCandidate(candidatePath: string): RoutedCandidate | null {
  const lower = candidatePath.toLowerCase()
  const routedFormats: string[] = []
  const recommendedTools: string[] = []

  if (lower.endsWith('.so')) {
    routedFormats.push('elf', 'so', 'native-lib')
    recommendedTools.push('elf.structure.analyze', 'linux.binary.inventory')
  }
  if (lower.endsWith('.dex')) {
    routedFormats.push('dex', 'android-bytecode')
    recommendedTools.push('dex.classes.list')
  }
  if (/\.(?:vdex|oat|odex|art)$/.test(lower)) {
    routedFormats.push('android-bytecode')
    recommendedTools.push('android.package.inventory', 'strings.extract')
  }
  if (lower.endsWith('.jar')) {
    routedFormats.push('jar', 'jvm')
    recommendedTools.push('jvm.structure.analyze')
  }
  if (lower.endsWith('.wasm')) {
    routedFormats.push('wasm')
    recommendedTools.push('wasm.structure.analyze')
  }
  if (/\.(?:apk|aab|apks|xapk|aar)$/.test(lower)) {
    routedFormats.push('android-package')
    recommendedTools.push('android.package.inventory')
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

export function buildAndroidPackageInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): AndroidPackageInventory {
  const detected = detectAndroidFormat(data, options.filename)
  const archiveMembers = parseZipLocalMembers(data)
  const tokens = extractPathTokens(data)
  const members = unique([...archiveMembers, ...tokens]).slice(0, 600)
  const lower = (value: string) => value.toLowerCase()

  const manifestCandidates = members.filter((member) =>
    lower(member).endsWith('androidmanifest.xml')
  )
  const dexCandidates = members.filter((member) => /\.(?:dex|vdex|oat|odex|art)$/i.test(member))
  const resourceCandidates = members.filter((member) => {
    const item = lower(member)
    return item.endsWith('resources.arsc') || item.startsWith('res/') || item.startsWith('assets/')
  })
  const signingCandidates = members.filter((member) => {
    const item = lower(member)
    return (
      (item.startsWith('meta-inf/') && /\.(?:rsa|dsa|ec|sf|mf)$/.test(item)) ||
      item.endsWith('.idsig')
    )
  })
  const splitPackageCandidates = members.filter((member) => {
    const item = lower(member)
    return item.endsWith('.apk') || item.includes('split') || item.includes('base.apk')
  })
  const routed = members
    .map(routeAndroidCandidate)
    .filter((candidate): candidate is RoutedCandidate => Boolean(candidate))
  const nativeLibraries = routed.filter((candidate) => candidate.routed_formats.includes('so'))
  const nestedPackages = routed.filter((candidate) =>
    candidate.routed_formats.includes('android-package')
  )
  const unsupported =
    detected.format === 'zip'
      ? 'ZIP container did not expose enough Android markers in the preview; inventory remains best-effort.'
      : undefined

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    package_format: detected.format,
    detected_by: detected.detectedBy,
    size: options.size ?? data.length,
    archive_members: members,
    manifest_candidates: manifestCandidates.slice(0, 50),
    dex_candidates: dexCandidates.slice(0, 100),
    native_library_candidates: nativeLibraries.slice(0, 100),
    resource_candidates: resourceCandidates.slice(0, 120),
    signing_candidates: signingCandidates.slice(0, 80),
    split_package_candidates: splitPackageCandidates.slice(0, 120),
    nested_package_candidates: nestedPackages.slice(0, 100),
    policy: {
      passive: true,
      no_execute: true,
      no_install: true,
      no_runtime_start: true,
      no_decompiler_launch: true,
      no_device_connection: true,
    },
    unsupported_detail: unsupported,
    summary: `Passive Android inventory detected ${detected.format} with ${members.length} member/path hint(s), ${dexCandidates.length} bytecode candidate(s), ${nativeLibraries.length} native library candidate(s), and ${signingCandidates.length} signing candidate(s).`,
    recommended_next_tools: unique([
      'apk.manifest.parse',
      'dex.classes.list',
      'apk.packer.detect',
      'strings.extract',
      ...routed.flatMap((candidate) => candidate.recommended_tools),
    ]),
    next_actions: [
      'Review manifest, resource, signing, and split-package candidates as static metadata.',
      'Ingest nested native libraries separately before running ELF analysis.',
      'Do not install APKs, start Android runtimes, connect devices, or launch decompilers during passive triage.',
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

export function createAndroidPackageInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (
    args: z.infer<typeof AndroidPackageInventoryInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = AndroidPackageInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildAndroidPackageInventoryFromBuffer(data, {
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
            'android_package_inventory',
            'android-package-inventory',
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
