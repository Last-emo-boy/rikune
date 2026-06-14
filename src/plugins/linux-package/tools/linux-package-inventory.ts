/**
 * linux.package.inventory — passive Linux package inventory.
 *
 * This tool never installs packages or executes maintainer scripts. It reads
 * bounded file previews and returns routing hints for nested binaries.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'linux.package.inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024
const LINUX_PACKAGE_INVENTORY_ARTIFACT_TYPE = 'linux_package_inventory'
const LINUX_PACKAGE_FORMATS = ['deb', 'rpm', 'apk-alpine', 'snap', 'flatpak', 'appimage']
const LINUX_PACKAGE_EVIDENCE = [
  'workflow',
  'provenance',
  'package-metadata',
  'nested-binaries',
  'filesystem',
  'sbom',
]
const LINUX_PACKAGE_FOLLOW_UP_TOOLS = [
  'metadata.extract',
  'strings.extract',
  'sbom.provenance.graph',
  'linux.binary.inventory',
  'firmware.workflow.plan',
  'container.structure.analyze',
  'analysis.evidence.graph',
  'report.generate',
]
const LINUX_PACKAGE_SAFETY = [
  'passive',
  'no_install',
  'no_script_execution',
  'no_installer_execution',
  'no_auto_mount',
  'no_live_sample_by_default',
]

const LinuxPackagePolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_install: z.literal(true),
  no_mount: z.literal(true),
})

const LinuxPackageInventoryDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  package_format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  archive_members: z.array(z.string()),
  maintainer_script_candidates: z.array(z.string()),
  nested_binary_candidates: z.array(
    z.object({
      path: z.string(),
      routed_formats: z.array(z.string()),
      recommended_tools: z.array(z.string()),
    })
  ),
  policy: LinuxPackagePolicySchema,
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const LinuxPackageInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum number of bytes to read from the package for passive inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const LinuxPackageInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: LinuxPackageInventoryDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const linuxPackageInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Linux package containers (deb, rpm, Alpine apk, snap, flatpak, AppImage). Does not install packages or execute maintainer scripts.',
  inputSchema: LinuxPackageInventoryInputSchema,
  outputSchema: LinuxPackageInventoryOutputSchema,
  aspects: {
    formats: LINUX_PACKAGE_FORMATS,
    platforms: ['linux'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
    execution: ['static', 'triage'],
    safety: LINUX_PACKAGE_SAFETY,
    capabilities: [
      'inventory',
      'package-metadata',
      'scripts',
      'nested-binaries',
      'routing',
      'workflow-plan',
      'metadata-only-handoff',
      'supply-chain-handoff',
      'firmware-handoff',
    ],
    evidence: LINUX_PACKAGE_EVIDENCE,
  },
  artifacts: [
    {
      type: LINUX_PACKAGE_INVENTORY_ARTIFACT_TYPE,
      description: 'Passive Linux package metadata, script candidate, and nested binary inventory',
    },
  ],
  evidence: [
    {
      category: 'workflow',
      artifactTypes: [LINUX_PACKAGE_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [LINUX_PACKAGE_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'package-metadata',
      artifactTypes: [LINUX_PACKAGE_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'nested-binaries',
      artifactTypes: [LINUX_PACKAGE_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'filesystem',
      artifactTypes: [LINUX_PACKAGE_INVENTORY_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'linux-package.passive-inventory-handoff',
      title: 'Linux package passive inventory handoff',
      description:
        'Create a passive Linux package, maintainer script candidate, provenance, and nested binary inventory for supply-chain, firmware, container, evidence graph, and report workflows without installing packages, executing scripts, mounting filesystems, or running live samples.',
      startsWith: [TOOL_NAME],
      nextTools: LINUX_PACKAGE_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [LINUX_PACKAGE_INVENTORY_ARTIFACT_TYPE],
      evidence: LINUX_PACKAGE_EVIDENCE,
      safety: LINUX_PACKAGE_SAFETY,
    },
  ],
}

export type LinuxPackageInventory = z.infer<typeof LinuxPackageInventoryDataSchema>

type NestedBinaryCandidate = LinuxPackageInventory['nested_binary_candidates'][number]

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (base.endsWith('.appimage')) return 'appimage'
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function previewText(data: Buffer): string {
  return data.toString('latin1')
}

function detectPackageFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  const detectedBy: string[] = []

  if (data.length >= 8 && data.subarray(0, 8).toString('ascii') === '!<arch>\n') {
    const preview = previewText(data.subarray(8, Math.min(data.length, 4096)))
    if (preview.includes('debian-binary')) {
      detectedBy.push('ar magic', 'debian-binary member')
      return { format: 'deb', detectedBy }
    }
    detectedBy.push('ar magic')
    return { format: ext || 'ar', detectedBy }
  }

  if (
    data.length >= 4 &&
    data[0] === 0xed &&
    data[1] === 0xab &&
    data[2] === 0xee &&
    data[3] === 0xdb
  ) {
    detectedBy.push('rpm magic')
    return { format: 'rpm', detectedBy }
  }

  if (
    data.length >= 4 &&
    data[0] === 0x7f &&
    data[1] === 0x45 &&
    data[2] === 0x4c &&
    data[3] === 0x46 &&
    (ext === 'appimage' || data.subarray(8, 10).toString('ascii') === 'AI')
  ) {
    detectedBy.push(ext === 'appimage' ? 'filename extension' : 'AppImage ELF marker')
    return { format: 'appimage', detectedBy }
  }

  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b && ext === 'apk') {
    detectedBy.push('gzip magic', 'apk extension')
    return { format: 'apk-alpine', detectedBy }
  }

  if (ext === 'snap' || ext === 'flatpak' || ext === 'appimage' || ext === 'apk') {
    detectedBy.push('filename extension')
    return { format: ext === 'apk' ? 'apk-alpine' : ext, detectedBy }
  }

  detectedBy.push('unknown')
  return { format: ext || 'unknown', detectedBy }
}

function parseArMembers(data: Buffer): string[] {
  if (data.length < 8 || data.subarray(0, 8).toString('ascii') !== '!<arch>\n') {
    return []
  }

  const members: string[] = []
  let offset = 8
  while (offset + 60 <= data.length && members.length < 200) {
    const header = data.subarray(offset, offset + 60).toString('latin1')
    const name = header.slice(0, 16).trim().replace(/\/$/, '')
    const sizeText = header.slice(48, 58).trim()
    const size = Number.parseInt(sizeText, 10)
    if (!name || !Number.isFinite(size) || size < 0) break
    members.push(name)
    offset += 60 + size + (size % 2)
  }
  return members
}

function extractPathTokens(data: Buffer): string[] {
  const text = previewText(data.subarray(0, Math.min(data.length, 1024 * 1024)))
  const matches = text.match(
    /[A-Za-z0-9_./@+-]{2,240}\.(?:so|elf|bin|dylib|macho|apk|dex|jar|wasm|sh|service|desktop|plist)/gi
  )
  const maintainerScripts = text.match(
    /(?:^|[\s/])(preinst|postinst|prerm|postrm|triggers|conffiles)(?=$|[\s/])/g
  )
  const scriptTokens =
    maintainerScripts?.map((item) => item.replace(/[^\w-]/g, '').trim()).filter(Boolean) ?? []
  return Array.from(new Set([...(matches ?? []), ...scriptTokens])).slice(0, 200)
}

function routeNestedCandidate(candidatePath: string): NestedBinaryCandidate | null {
  const lower = candidatePath.toLowerCase()
  const routedFormats: string[] = []
  const recommendedTools: string[] = []

  if (lower.endsWith('.so') || lower.endsWith('.elf') || lower.endsWith('.bin')) {
    routedFormats.push('elf')
    recommendedTools.push('elf.structure.analyze')
  }
  if (lower.endsWith('.apk')) {
    routedFormats.push('apk')
    recommendedTools.push('apk.structure.analyze')
  }
  if (lower.endsWith('.dex')) {
    routedFormats.push('dex')
    recommendedTools.push('dex.classes.list')
  }
  if (lower.endsWith('.jar')) {
    routedFormats.push('jar')
    recommendedTools.push('metadata.extract')
  }
  if (lower.endsWith('.wasm')) {
    routedFormats.push('wasm')
    recommendedTools.push('metadata.extract')
  }

  if (routedFormats.length === 0) return null
  return {
    path: candidatePath,
    routed_formats: routedFormats,
    recommended_tools: Array.from(new Set(recommendedTools)),
  }
}

function maintainerScriptsFor(format: string, members: string[], tokens: string[]): string[] {
  const candidates = new Set<string>()
  for (const member of members) {
    if (/^(preinst|postinst|prerm|postrm|control|triggers|conffiles)$/.test(member)) {
      candidates.add(member)
    }
  }
  for (const token of tokens) {
    const lower = token.toLowerCase()
    if (
      lower.includes('postinst') ||
      lower.includes('preinst') ||
      lower.includes('postrm') ||
      lower.includes('prerm') ||
      lower.endsWith('.sh') ||
      lower.endsWith('.service') ||
      lower.endsWith('.desktop')
    ) {
      candidates.add(token)
    }
  }
  if (format === 'rpm')
    candidates.add(
      'rpm scriptlets may be present; external rpm tooling is required to list them safely'
    )
  return Array.from(candidates).slice(0, 100)
}

export function buildLinuxPackageInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): LinuxPackageInventory {
  const { format, detectedBy } = detectPackageFormat(data, options.filename)
  const archiveMembers = parseArMembers(data)
  const tokens = extractPathTokens(data)
  const nested = tokens
    .map(routeNestedCandidate)
    .filter((candidate): candidate is NestedBinaryCandidate => Boolean(candidate))
  const scriptCandidates = maintainerScriptsFor(format, archiveMembers, tokens)
  const unsupported =
    format === 'rpm' || format === 'snap' || format === 'flatpak' || format === 'apk-alpine'
      ? 'Deep payload listing requires optional external package tooling; this inventory remains passive and does not install or execute package hooks.'
      : undefined

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    package_format: format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    archive_members: archiveMembers,
    maintainer_script_candidates: scriptCandidates,
    nested_binary_candidates: nested,
    policy: {
      passive: true,
      no_execute: true,
      no_install: true,
      no_mount: true,
    },
    unsupported_detail: unsupported,
    summary: `Passive Linux package inventory detected ${format} with ${archiveMembers.length} archive member(s), ${scriptCandidates.length} script candidate(s), and ${nested.length} nested binary candidate(s).`,
    recommended_next_tools: Array.from(
      new Set([
        ...LINUX_PACKAGE_FOLLOW_UP_TOOLS,
        ...nested.flatMap((candidate) => candidate.recommended_tools),
        'sbom.generate',
      ])
    ),
    next_actions: [
      'Review package metadata and maintainer script candidates as text only.',
      'Ingest nested binary candidates separately before running ELF, Android, JVM, or WASM tools.',
      'Do not install the package or execute package hooks during static triage.',
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

export function createLinuxPackageInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (args: z.infer<typeof LinuxPackageInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = LinuxPackageInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildLinuxPackageInventoryFromBuffer(data, {
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
            'linux_package_inventory',
            'linux-package-inventory',
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
