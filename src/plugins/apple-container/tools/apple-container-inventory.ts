/**
 * apple.container.inventory — passive Apple container inventory.
 *
 * This tool never mounts DMG images, installs PKG payloads, launches apps, or
 * connects to devices. It reads bounded previews and returns routing hints.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'apple.container.inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024

const AppleContainerPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_install: z.literal(true),
  no_mount: z.literal(true),
  no_device_connection: z.literal(true),
})

const AppleContainerInventoryDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  container_format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  archive_members: z.array(z.string()),
  plist_candidates: z.array(z.string()),
  provisioning_candidates: z.array(z.string()),
  nested_macho_candidates: z.array(
    z.object({
      path: z.string(),
      routed_formats: z.array(z.string()),
      recommended_tools: z.array(z.string()),
    })
  ),
  policy: AppleContainerPolicySchema,
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const AppleContainerInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum number of bytes to read from the container for passive inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const AppleContainerInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: AppleContainerInventoryDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const appleContainerInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Apple containers (IPA, DMG, PKG, app bundles) and route nested Mach-O candidates. Does not mount images, install packages, launch apps, or connect to devices.',
  inputSchema: AppleContainerInventoryInputSchema,
  outputSchema: AppleContainerInventoryOutputSchema,
  aspects: {
    formats: [
      'ipa',
      'dmg',
      'pkg',
      'app-bundle',
      'framework',
      'xcframework',
      'dylib',
      'dsym',
      'mobileprovision',
    ],
    platforms: ['macos', 'ios'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_auto_mount', 'no_installer_execution', 'no_live_sample_by_default'],
    capabilities: ['inventory', 'package-metadata', 'provisioning', 'nested-binaries', 'routing'],
    evidence: ['manifest', 'package-metadata', 'nested-binaries', 'provenance'],
  },
  artifacts: [
    {
      type: 'apple_container_inventory',
      description: 'Passive IPA/DMG/PKG/app bundle inventory and nested Mach-O routing hints',
    },
  ],
  evidence: [
    {
      category: 'manifest',
      artifactTypes: ['apple_container_inventory'],
    },
    {
      category: 'package-metadata',
      artifactTypes: ['apple_container_inventory'],
    },
    {
      category: 'nested-binaries',
      artifactTypes: ['apple_container_inventory'],
    },
    {
      category: 'provenance',
      artifactTypes: ['apple_container_inventory'],
    },
  ],
  workflowRecipes: [
    {
      id: 'apple.container.static-inventory',
      title: 'Apple static container inventory',
      startsWith: ['apple.container.inventory'],
      nextTools: [
        'apple.signing.inspect',
        'macho.structure.analyze',
        'apple.security.profile',
        'macos.runtime.plan',
        'ios.runtime.plan',
      ],
      producesArtifacts: ['apple_container_inventory'],
      evidence: ['manifest', 'package-metadata', 'nested-binaries', 'provenance'],
      safety: ['passive', 'no_auto_mount', 'no_installer_execution', 'no_live_sample_by_default'],
    },
  ],
}

export type AppleContainerInventory = z.infer<typeof AppleContainerInventoryDataSchema>

type NestedMachoCandidate = AppleContainerInventory['nested_macho_candidates'][number]

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (base.endsWith('.app')) return 'app'
  if (base.endsWith('.framework')) return 'framework'
  if (base.endsWith('.xcframework')) return 'xcframework'
  if (base.endsWith('.dsym')) return 'dsym'
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function previewText(data: Buffer): string {
  return data.toString('latin1')
}

function detectContainerFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  const detectedBy: string[] = []

  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) {
    const preview = previewText(data.subarray(0, Math.min(data.length, 1024 * 1024)))
    if (ext === 'ipa' || (preview.includes('Payload/') && preview.includes('.app/'))) {
      detectedBy.push(ext === 'ipa' ? 'filename extension' : 'Payload app marker')
      return { format: 'ipa', detectedBy }
    }
    detectedBy.push('zip magic')
    return { format: ext || 'zip', detectedBy }
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'xar!') {
    detectedBy.push('xar magic')
    return { format: 'pkg', detectedBy }
  }

  if (
    data.length >= 512 &&
    data.subarray(data.length - 512, data.length - 508).toString('ascii') === 'koly'
  ) {
    detectedBy.push('DMG koly trailer')
    return { format: 'dmg', detectedBy }
  }

  if (
    ext === 'dmg' ||
    ext === 'pkg' ||
    ext === 'ipa' ||
    ext === 'app' ||
    ext === 'framework' ||
    ext === 'xcframework' ||
    ext === 'dsym' ||
    ext === 'mobileprovision'
  ) {
    detectedBy.push('filename extension')
    return { format: ext === 'app' ? 'app-bundle' : ext, detectedBy }
  }

  detectedBy.push('unknown')
  return { format: ext || 'unknown', detectedBy }
}

function parseZipLocalMembers(data: Buffer): string[] {
  const members: string[] = []
  let offset = 0

  while (offset + 30 <= data.length && members.length < 300) {
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
    if (name.length > 0) members.push(name)

    const nextOffset = nameEnd + extraLength + compressedSize
    if (nextOffset <= offset || nextOffset > data.length) {
      offset = nameEnd + extraLength
    } else {
      offset = nextOffset
    }
  }

  return Array.from(new Set(members))
}

function extractPathTokens(data: Buffer): string[] {
  const text = previewText(data.subarray(0, Math.min(data.length, 1024 * 1024)))
  const matches = text.match(
    /[A-Za-z0-9_./@+ -]{2,240}\.(?:app|framework|xcframework|dylib|plist|mobileprovision|appex|xpc|pkg|macho|dsym)/gi
  )
  return Array.from(new Set(matches ?? [])).slice(0, 300)
}

function routeNestedMacho(candidatePath: string): NestedMachoCandidate | null {
  const lower = candidatePath.toLowerCase()
  if (
    lower.endsWith('.dylib') ||
    lower.includes('.framework/') ||
    lower.endsWith('.framework') ||
    lower.endsWith('.appex') ||
    lower.endsWith('.xpc') ||
    lower.endsWith('.dsym') ||
    lower.includes('.app/')
  ) {
    return {
      path: candidatePath,
      routed_formats: ['macho'],
      recommended_tools: ['macho.structure.analyze', 'metadata.extract'],
    }
  }
  return null
}

export function buildAppleContainerInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): AppleContainerInventory {
  const { format, detectedBy } = detectContainerFormat(data, options.filename)
  const zipMembers = parseZipLocalMembers(data)
  const tokens = extractPathTokens(data)
  const members = Array.from(new Set([...zipMembers, ...tokens])).slice(0, 300)
  const plistCandidates = members.filter((member) => member.toLowerCase().endsWith('.plist'))
  const provisioningCandidates = members.filter((member) =>
    member.toLowerCase().endsWith('.mobileprovision')
  )
  const nestedMacho = members
    .map(routeNestedMacho)
    .filter((candidate): candidate is NestedMachoCandidate => Boolean(candidate))
  const unsupported =
    format === 'dmg'
      ? 'DMG payload listing requires mounting or dedicated DMG tooling; this tool does neither by default.'
      : format === 'pkg'
        ? 'PKG payload expansion requires xar/cpio tooling; installer scripts are not executed.'
        : undefined

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    container_format: format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    archive_members: members,
    plist_candidates: plistCandidates.slice(0, 100),
    provisioning_candidates: provisioningCandidates.slice(0, 50),
    nested_macho_candidates: nestedMacho.slice(0, 100),
    policy: {
      passive: true,
      no_execute: true,
      no_install: true,
      no_mount: true,
      no_device_connection: true,
    },
    unsupported_detail: unsupported,
    summary: `Passive Apple container inventory detected ${format} with ${members.length} member/path hint(s), ${plistCandidates.length} plist candidate(s), ${provisioningCandidates.length} provisioning candidate(s), and ${nestedMacho.length} nested Mach-O candidate(s).`,
    recommended_next_tools: Array.from(
      new Set(
        [
          'metadata.extract',
          ...nestedMacho.flatMap((candidate) => candidate.recommended_tools),
          provisioningCandidates.length > 0 ? 'strings.extract' : '',
        ].filter(Boolean)
      )
    ),
    next_actions: [
      'Review Info.plist and provisioning candidates as static metadata.',
      'Ingest nested Mach-O candidates separately before running Mach-O structure analysis.',
      'Do not mount DMG images, install PKG payloads, launch apps, or connect to iOS devices during static triage.',
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

export function createAppleContainerInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (
    args: z.infer<typeof AppleContainerInventoryInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = AppleContainerInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildAppleContainerInventoryFromBuffer(data, {
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
            'apple_container_inventory',
            'apple-container-inventory',
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
