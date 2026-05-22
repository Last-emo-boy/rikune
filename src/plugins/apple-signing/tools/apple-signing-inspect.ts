/**
 * apple.signing.inspect — passive Apple signing and bundle metadata inventory.
 *
 * This tool does not execute code, call codesign, open keychains, verify
 * certificates online, mount images, install apps, or connect to devices. It
 * reads bounded previews and returns signing, entitlement, and routing hints.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'apple.signing.inspect'
const DEFAULT_MAX_READ_BYTES = 6 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024

const AppleSigningPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_codesign_verification: z.literal(true),
  no_keychain_access: z.literal(true),
  no_device_connection: z.literal(true),
  no_network_lookup: z.literal(true),
})

const AppleSigningCandidateSchema = z.object({
  path: z.string(),
  routed_formats: z.array(z.string()),
  recommended_tools: z.array(z.string()),
})

const AppleSigningInspectDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  archive_members: z.array(z.string()),
  bundle_metadata_candidates: z.array(z.string()),
  provisioning_candidates: z.array(z.string()),
  entitlement_hints: z.array(z.string()),
  signing_blob_hints: z.array(z.string()),
  certificate_hints: z.array(z.string()),
  nested_code_candidates: z.array(AppleSigningCandidateSchema),
  policy: AppleSigningPolicySchema,
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const AppleSigningInspectInputSchema = z.object({
  sample_id: z.string().describe('Target Apple binary, bundle, IPA, or provisioning sample.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive Apple signing inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const AppleSigningInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: AppleSigningInspectDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const appleSigningInspectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inspect Apple code-signing, provisioning, entitlement, and bundle metadata hints without calling codesign, accessing keychains, mounting images, installing apps, or connecting devices.',
  inputSchema: AppleSigningInspectInputSchema,
  outputSchema: AppleSigningInspectOutputSchema,
  aspects: {
    formats: [
      'apple-signing',
      'codesignature',
      'entitlements',
      'plist',
      'mobileprovision',
      'ipa',
      'app-bundle',
      'framework',
      'xcframework',
      'dylib',
      'macho',
      'dsym',
    ],
    platforms: ['macos', 'ios'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_network_by_default', 'no_live_sample_by_default'],
    capabilities: ['inventory', 'package-metadata', 'provisioning', 'certificates', 'routing'],
    evidence: ['manifest', 'certificates', 'package-metadata', 'nested-binaries', 'provenance'],
  },
  artifacts: [
    {
      type: 'apple_signing_inventory',
      description: 'Passive Apple signing, provisioning, entitlement, and bundle metadata hints',
    },
  ],
  evidence: [
    { category: 'manifest', artifactTypes: ['apple_signing_inventory'] },
    { category: 'certificates', artifactTypes: ['apple_signing_inventory'] },
    { category: 'package-metadata', artifactTypes: ['apple_signing_inventory'] },
  ],
}

export type AppleSigningInspect = z.infer<typeof AppleSigningInspectDataSchema>
type AppleSigningCandidate = z.infer<typeof AppleSigningCandidateSchema>

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
  return data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
}

function detectFormat(data: Buffer, filename?: string): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  const text = previewText(data)
  const basename = path.posix.basename((filename ?? '').replace(/\\/g, '/')).toLowerCase()

  if (ext === 'mobileprovision')
    return { format: 'mobileprovision', detectedBy: ['filename extension'] }
  if (ext === 'entitlements') return { format: 'entitlements', detectedBy: ['filename extension'] }
  if (ext === 'plist') return { format: 'plist', detectedBy: ['filename extension'] }
  if (ext === 'app') return { format: 'app-bundle', detectedBy: ['filename extension'] }
  if (ext === 'framework') return { format: 'framework', detectedBy: ['filename extension'] }
  if (ext === 'xcframework') return { format: 'xcframework', detectedBy: ['filename extension'] }
  if (ext === 'dsym' || basename.endsWith('.dsym'))
    return { format: 'dsym', detectedBy: ['filename extension'] }

  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) {
    if (ext === 'ipa' || (text.includes('Payload/') && text.includes('.app/'))) {
      return {
        format: 'ipa',
        detectedBy: ['zip magic', ext === 'ipa' ? 'filename extension' : 'Payload app marker'],
      }
    }
    return { format: ext || 'zip', detectedBy: ['zip magic'] }
  }

  if (data.length >= 4) {
    const magic = data.readUInt32BE(0)
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca].includes(magic)) {
      return { format: 'macho', detectedBy: ['Mach-O magic'] }
    }
  }

  if (text.includes('com.apple.developer') || text.includes('application-identifier')) {
    return { format: 'entitlements', detectedBy: ['entitlement key marker'] }
  }
  if (text.includes('embedded.mobileprovision') || text.includes('ProvisionedDevices')) {
    return { format: 'mobileprovision', detectedBy: ['provisioning marker'] }
  }
  if (['ipa', 'dmg', 'pkg', 'dylib'].includes(ext)) {
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
      /[A-Za-z0-9_./@{}$+ -]{2,240}\.(?:app|appex|xpc|framework|xcframework|dylib|macho|plist|mobileprovision|entitlements|dsym|ipa|pkg|dmg)/gi
    ) ?? []
  return Array.from(new Set(matches.map((item) => item.trim()).filter(Boolean))).slice(0, 400)
}

function extractEntitlementHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /(?:application-identifier|com\.apple\.developer\.[A-Za-z0-9_.-]+|keychain-access-groups|get-task-allow|aps-environment|com\.apple\.security\.[A-Za-z0-9_.-]+)/g
    ) ?? []
  return Array.from(new Set(matches)).slice(0, 100)
}

function extractCertificateHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /(?:Apple (?:Development|Distribution|Root CA|Worldwide Developer Relations)[A-Za-z0-9 .-]*|iPhone (?:Developer|Distribution)[A-Za-z0-9 .:()_-]*)/g
    ) ?? []
  return Array.from(new Set(matches.map((item) => item.trim()))).slice(0, 80)
}

function findMachOCodeSignatureHints(data: Buffer): string[] {
  if (data.length < 32) return []
  const magic = data.readUInt32BE(0)
  const isBigEndian = magic === 0xfeedface || magic === 0xfeedfacf
  const isLittleEndian = magic === 0xcefaedfe || magic === 0xcffaedfe
  if (!isBigEndian && !isLittleEndian) return []
  const read32 = (offset: number) =>
    isBigEndian ? data.readUInt32BE(offset) : data.readUInt32LE(offset)
  const ncmds = read32(16)
  let offset = magic === 0xfeedfacf || magic === 0xcffaedfe ? 32 : 28
  const hints: string[] = []
  for (let index = 0; index < ncmds && offset + 8 <= data.length && index < 128; index += 1) {
    const cmd = read32(offset)
    const cmdsize = read32(offset + 4)
    if (cmd === 0x1d) hints.push('LC_CODE_SIGNATURE')
    if (cmdsize < 8) break
    offset += cmdsize
  }
  return hints
}

function routeCodeCandidate(candidatePath: string): AppleSigningCandidate | null {
  const lower = candidatePath.toLowerCase()
  const routedFormats: string[] = []
  const recommendedTools: string[] = []

  if (
    /\.(?:dylib|macho)$/.test(lower) ||
    lower.includes('.framework/') ||
    lower.endsWith('.framework') ||
    lower.endsWith('.appex') ||
    lower.endsWith('.xpc') ||
    lower.includes('.app/')
  ) {
    routedFormats.push('macho')
    recommendedTools.push('macho.structure.analyze', 'apple.signing.inspect')
  }
  if (
    lower.endsWith('.mobileprovision') ||
    lower.endsWith('.entitlements') ||
    lower.endsWith('.plist')
  ) {
    routedFormats.push('apple-signing')
    recommendedTools.push('apple.signing.inspect', 'metadata.extract', 'strings.extract')
  }
  if (lower.endsWith('.ipa') || lower.endsWith('.pkg') || lower.endsWith('.dmg')) {
    routedFormats.push('apple-container')
    recommendedTools.push('apple.container.inventory')
  }
  if (lower.endsWith('.dsym')) {
    routedFormats.push('dsym', 'debug-metadata')
    recommendedTools.push('native.object.inventory')
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

export function buildAppleSigningInspectFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): AppleSigningInspect {
  const detected = detectFormat(data, options.filename)
  const members = unique([...parseZipLocalMembers(data), ...extractPathTokens(data)]).slice(0, 600)
  const bundleMetadata = members.filter((member) => {
    const lower = member.toLowerCase()
    return (
      lower.endsWith('info.plist') || lower.endsWith('.plist') || lower.endsWith('.entitlements')
    )
  })
  const provisioning = members.filter((member) => member.toLowerCase().endsWith('.mobileprovision'))
  const signingBlobHints = unique([
    ...findMachOCodeSignatureHints(data),
    ...members.filter((member) => {
      const lower = member.toLowerCase()
      return (
        lower.includes('_codesignature/') ||
        lower.endsWith('code_signature') ||
        lower.endsWith('.idsig')
      )
    }),
  ]).slice(0, 120)
  const entitlements = extractEntitlementHints(data)
  const certificateHints = extractCertificateHints(data)
  const nested = members
    .map(routeCodeCandidate)
    .filter((candidate): candidate is AppleSigningCandidate => Boolean(candidate))
    .slice(0, 160)
  const unsupported =
    detected.format === 'dmg' || detected.format === 'pkg'
      ? 'Deep payload listing may require mounting or package expansion; this tool keeps inspection passive.'
      : undefined

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: detected.detectedBy,
    size: options.size ?? data.length,
    archive_members: members,
    bundle_metadata_candidates: bundleMetadata.slice(0, 120),
    provisioning_candidates: provisioning.slice(0, 80),
    entitlement_hints: entitlements,
    signing_blob_hints: signingBlobHints,
    certificate_hints: certificateHints,
    nested_code_candidates: nested,
    policy: {
      passive: true,
      no_execute: true,
      no_codesign_verification: true,
      no_keychain_access: true,
      no_device_connection: true,
      no_network_lookup: true,
    },
    unsupported_detail: unsupported,
    summary: `Passive Apple signing inventory detected ${detected.format} with ${bundleMetadata.length} metadata candidate(s), ${provisioning.length} provisioning candidate(s), ${entitlements.length} entitlement hint(s), and ${signingBlobHints.length} signing blob hint(s).`,
    recommended_next_tools: unique([
      'apple.container.inventory',
      'metadata.extract',
      'strings.extract',
      ...nested.flatMap((candidate) => candidate.recommended_tools),
      signingBlobHints.includes('LC_CODE_SIGNATURE') ? 'macho.structure.analyze' : '',
    ]),
    next_actions: [
      'Review Info.plist, entitlement, provisioning, and signing blob hints as static metadata.',
      'Ingest nested Mach-O candidates separately before structure analysis.',
      'Do not call codesign, access keychains, perform online certificate checks, mount images, install apps, or connect devices during passive triage.',
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

export function createAppleSigningInspectHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (args: z.infer<typeof AppleSigningInspectInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = AppleSigningInspectInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildAppleSigningInspectFromBuffer(data, {
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
            'apple_signing_inventory',
            'apple-signing-inventory',
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
