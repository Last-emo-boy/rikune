/**
 * unity.metadata.inspect — passive Unity/IL2CPP metadata inventory.
 *
 * This tool does not load GameAssembly, start Unity, or execute managed/native
 * code. It produces a bridge plan and routing hints only.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'unity.metadata.inspect'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024

const UnityPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_runtime_start: z.literal(true),
  no_native_load: z.literal(true),
})

const UnityMetadataInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  header: z.record(z.any()),
  unity_version_hints: z.array(z.string()),
  managed_assembly_candidates: z.array(z.string()),
  il2cpp_candidates: z.array(z.string()),
  metadata_candidates: z.array(z.string()),
  bridge_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    notes: z.array(z.string()),
  }),
  policy: UnityPolicySchema,
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const UnityMetadataInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive Unity metadata inspection.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist Unity metadata inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const UnityMetadataInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: UnityMetadataInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const unityMetadataInspectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inspect Unity global-metadata.dat, IL2CPP, and managed assembly layout without starting Unity or loading native code.',
  inputSchema: UnityMetadataInspectInputSchema,
  outputSchema: UnityMetadataInspectOutputSchema,
  aspects: {
    formats: ['unity', 'unity-metadata', 'il2cpp', 'mono'],
    platforms: ['dotnet', 'windows', 'linux', 'macos', 'android', 'ios'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['metadata', 'managed-native-map', 'decompile-plan', 'routing'],
    evidence: ['manifest', 'symbols', 'nested-binaries', 'provenance'],
  },
  artifacts: [
    {
      type: 'unity_metadata_inventory',
      description: 'Passive Unity metadata, IL2CPP bridge, and managed assembly inventory',
    },
  ],
  evidence: [
    {
      category: 'manifest',
      artifactTypes: ['unity_metadata_inventory'],
    },
    {
      category: 'nested-binaries',
      artifactTypes: ['unity_metadata_inventory'],
    },
  ],
}

export type UnityMetadataInventory = z.infer<typeof UnityMetadataInventorySchema>

type ZipEntry = {
  name: string
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function basenameOf(filename?: string): string {
  return path.posix.basename((filename ?? '').replace(/\\/g, '/')).toLowerCase()
}

function previewText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
}

function detectUnityFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  const base = basenameOf(filename)
  if (
    base === 'global-metadata.dat' ||
    (data.length >= 4 &&
      data[0] === 0xfa &&
      data[1] === 0xb1 &&
      data[2] === 0x1b &&
      data[3] === 0xaf)
  ) {
    return {
      format: 'unity-metadata',
      detectedBy: base === 'global-metadata.dat' ? ['filename'] : ['global-metadata magic'],
    }
  }
  if (
    base === 'gameassembly.dll' ||
    base.includes('il2cpp') ||
    previewText(data).includes('il2cpp')
  ) {
    return { format: 'il2cpp', detectedBy: ['filename or IL2CPP marker'] }
  }
  if (ext === 'unity') return { format: 'unity', detectedBy: ['filename extension'] }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function parseGlobalMetadataHeader(data: Buffer): Record<string, unknown> {
  if (
    data.length >= 8 &&
    data[0] === 0xfa &&
    data[1] === 0xb1 &&
    data[2] === 0x1b &&
    data[3] === 0xaf
  ) {
    return {
      magic_hex: data.subarray(0, 4).toString('hex'),
      metadata_version: data.readUInt32LE(4),
    }
  }
  return data.length >= 16 ? { preview_hex: data.subarray(0, 16).toString('hex') } : {}
}

function parseZipLocalEntries(data: Buffer): ZipEntry[] {
  const entries: ZipEntry[] = []
  let offset = 0

  while (offset + 30 <= data.length && entries.length < 500) {
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
    if (name) entries.push({ name })

    const nextOffset = nameEnd + extraLength + compressedSize
    offset = nextOffset > offset && nextOffset <= data.length ? nextOffset : nameEnd + extraLength
  }

  return entries
}

function extractPathHints(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /(?:[A-Za-z0-9_./@+-]{0,200}\/)?(?:global-metadata\.dat|GameAssembly\.dll|libil2cpp\.so|UnityPlayer\.dll|Assembly-CSharp\.dll|[A-Za-z0-9_.-]+\.managed\.dll|[A-Za-z0-9_.-]+\.dll|[A-Za-z0-9_.-]+\.so)/gi
    ) ?? []
  return Array.from(new Set(matches.map((item) => item.trim()).filter(Boolean))).slice(0, 300)
}

function extractUnityVersions(data: Buffer): string[] {
  const matches =
    previewText(data).match(/(?:Unity|unity)[^0-9]{0,16}([0-9]{4}\.[0-9]\.[0-9a-zfp.]+)/g) ?? []
  return Array.from(
    new Set(
      matches
        .map((item) => item.match(/([0-9]{4}\.[0-9]\.[0-9a-zfp.]+)/)?.[1])
        .filter((item): item is string => Boolean(item))
    )
  ).slice(0, 50)
}

export function buildUnityMetadataInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): UnityMetadataInventory {
  const { format, detectedBy } = detectUnityFormat(data, options.filename)
  const members = parseZipLocalEntries(data).map((entry) => entry.name)
  const pathHints = Array.from(new Set([...members, ...extractPathHints(data)]))
  const managedAssemblies = pathHints
    .filter((item) => /\.(?:dll|winmd)$/i.test(item) && !/gameassembly|unityplayer/i.test(item))
    .slice(0, 100)
  const il2cppCandidates = pathHints
    .filter((item) => /gameassembly\.dll|libil2cpp\.so|il2cpp/i.test(item))
    .slice(0, 100)
  const metadataCandidates = pathHints
    .filter((item) => /global-metadata\.dat/i.test(item))
    .slice(0, 100)
  const versionHints = extractUnityVersions(data)

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    header: parseGlobalMetadataHeader(data),
    unity_version_hints: versionHints,
    managed_assembly_candidates: managedAssemblies,
    il2cpp_candidates: il2cppCandidates,
    metadata_candidates: metadataCandidates,
    bridge_plan: {
      status: 'plan_only',
      recommended_tools: [
        'dotnet.assembly.inspect',
        'pe.structure.analyze',
        'elf.structure.analyze',
        'strings.extract',
      ],
      notes: [
        'Pair global-metadata.dat with the matching IL2CPP native binary before bridge reconstruction.',
        'This tool does not load GameAssembly, libil2cpp, or Unity runtime components.',
      ],
    },
    policy: {
      passive: true,
      no_execute: true,
      no_runtime_start: true,
      no_native_load: true,
    },
    unsupported_detail:
      'Detailed IL2CPP type/method reconstruction requires explicit opt-in tooling and matched metadata/native binaries.',
    summary: `Passive Unity inventory detected ${format} with ${managedAssemblies.length} managed assembly candidate(s), ${il2cppCandidates.length} IL2CPP candidate(s), and ${metadataCandidates.length} metadata candidate(s).`,
    recommended_next_tools: Array.from(
      new Set([
        'metadata.extract',
        'strings.extract',
        ...managedAssemblies.map(() => 'dotnet.assembly.inspect'),
        ...il2cppCandidates.map((item) =>
          item.toLowerCase().endsWith('.so') ? 'elf.structure.analyze' : 'pe.structure.analyze'
        ),
      ])
    ),
    next_actions: [
      'Review global-metadata.dat and IL2CPP native binary pairing before bridge reconstruction.',
      'Analyze managed assembly candidates with .NET inventory tools.',
      'Do not load Unity native libraries or start the Unity runtime during static triage.',
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

export function createUnityMetadataInspectHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof UnityMetadataInspectInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = UnityMetadataInspectInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildUnityMetadataInventoryFromBuffer(data, {
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
            'unity_metadata_inventory',
            'unity-metadata-inventory',
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
