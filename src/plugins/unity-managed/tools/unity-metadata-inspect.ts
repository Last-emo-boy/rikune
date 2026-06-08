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
export const UNITY_METADATA_ARTIFACT_TYPE = 'unity_metadata_inventory'
export const UNITY_METADATA_FORMATS = [
  'unity',
  'unity-metadata',
  'global-metadata',
  'global-metadata.dat',
  'il2cpp',
  'gameassembly',
  'libil2cpp',
  'mono',
  'managed-assembly',
]
export const UNITY_METADATA_PLATFORMS = ['dotnet', 'windows', 'linux', 'macos', 'android', 'ios']
export const UNITY_METADATA_SAFETY = [
  'passive',
  'no_runtime_start',
  'no_native_load',
  'no_decompiler_launch',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
]
export const UNITY_METADATA_CAPABILITIES = [
  'metadata',
  'inventory',
  'managed-native-map',
  'il2cpp-bridge-plan',
  'managed-assembly-routing',
  'decompile-plan',
  'routing',
  'search-profile',
  'workflow-plan',
  'workflow-handoff',
  'metadata-only-handoff',
]
export const UNITY_METADATA_EVIDENCE = [
  'manifest',
  'symbols',
  'structure',
  'package-metadata',
  'nested-binaries',
  'workflow',
  'provenance',
  'search-profile',
]
export const UNITY_METADATA_FOLLOW_UP_TOOLS = [
  'metadata.extract',
  'strings.extract',
  'dotnet.assembly.inspect',
  'pe.structure.analyze',
  'elf.structure.analyze',
  'sbom.generate',
  'analysis.evidence.graph',
  'artifact.read',
  'report.generate',
]
export const UNITY_METADATA_WORKFLOW_RECIPES = [
  {
    id: 'unity-managed.passive-metadata-handoff',
    title: 'Unity managed and IL2CPP passive metadata handoff',
    description:
      'Profile Unity global-metadata.dat, Mono assemblies, IL2CPP native bridge candidates, and Unity version hints for static workflow routing without starting Unity, loading native libraries, launching decompilers, or mutating samples.',
    startsWith: [TOOL_NAME],
    nextTools: UNITY_METADATA_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [UNITY_METADATA_ARTIFACT_TYPE],
    evidence: UNITY_METADATA_EVIDENCE,
    safety: UNITY_METADATA_SAFETY,
    runtimeBackends: ['local'],
  },
]
export const UNITY_METADATA_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noRuntimeStart: true,
  noNativeLoad: true,
  noDecompilerLaunch: true,
  notes: [
    'The default workflow reads only bounded local sample bytes and ZIP local headers.',
    'Unity runtime startup, native library loading, decompiler launch, network access, and mutation are outside the default passive profile.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noRuntimeStart: true
  noNativeLoad: true
  noDecompilerLaunch: true
}

const UnityPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_runtime_start: z.literal(true),
  no_native_load: z.literal(true),
  no_decompiler_launch: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
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
  workflowRecipes: z.array(z.any()),
  formats: z.array(z.string()),
  platforms: z.array(z.string()),
  evidence: z.array(z.string()),
  policy: UnityPolicySchema,
  unsupported_detail: z.string().optional(),
  evidence_summary: z.record(z.any()).optional(),
  workflow_handoff: z.record(z.any()).optional(),
  quality_gates: z.record(z.any()).optional(),
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
    formats: UNITY_METADATA_FORMATS,
    platforms: UNITY_METADATA_PLATFORMS,
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: UNITY_METADATA_SAFETY,
    capabilities: UNITY_METADATA_CAPABILITIES,
    evidence: UNITY_METADATA_EVIDENCE,
  },
  artifacts: [
    {
      type: UNITY_METADATA_ARTIFACT_TYPE,
      description: 'Passive Unity metadata, IL2CPP bridge, and managed assembly inventory',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: [UNITY_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'manifest',
      artifactTypes: [UNITY_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'symbols',
      artifactTypes: [UNITY_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'package-metadata',
      artifactTypes: [UNITY_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'nested-binaries',
      artifactTypes: [UNITY_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [UNITY_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [UNITY_METADATA_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: UNITY_METADATA_WORKFLOW_RECIPES,
  runtimePolicy: UNITY_METADATA_RUNTIME_POLICY,
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

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function buildEvidenceSummary(inventory: {
  sample_id?: string
  filename?: string
  format: string
  detected_by: string[]
  unity_version_hints: string[]
  managed_assembly_candidates: string[]
  il2cpp_candidates: string[]
  metadata_candidates: string[]
}) {
  return {
    schema: 'rikune.unity_metadata_inventory.evidence_summary.v1',
    source_tool: TOOL_NAME,
    artifact_type: UNITY_METADATA_ARTIFACT_TYPE,
    sample_id: inventory.sample_id,
    filename: inventory.filename,
    format: inventory.format,
    detected_by: inventory.detected_by,
    evidence_categories: UNITY_METADATA_EVIDENCE,
    evidence_counts: {
      unity_version_hints: inventory.unity_version_hints.length,
      managed_assembly_candidates: inventory.managed_assembly_candidates.length,
      il2cpp_candidates: inventory.il2cpp_candidates.length,
      metadata_candidates: inventory.metadata_candidates.length,
    },
    static_only: true,
    native_library_loaded: false,
    unity_runtime_started: false,
  }
}

function buildWorkflowHandoff(inventory: {
  managed_assembly_candidates: string[]
  il2cpp_candidates: string[]
  metadata_candidates: string[]
  recommended_next_tools: string[]
}) {
  return {
    schema: 'rikune.unity_metadata_inventory.workflow_handoff.v1',
    handoff_mode: 'unity_metadata_to_managed_il2cpp_static_analysis',
    artifact_type: UNITY_METADATA_ARTIFACT_TYPE,
    recommended_next_tools: inventory.recommended_next_tools,
    artifact_contract: {
      consumes: ['sample'],
      produces: [UNITY_METADATA_ARTIFACT_TYPE],
      expected_consumers: [
        'workflow.search',
        'artifact.read',
        'analysis.evidence.graph',
        'report.generate',
      ],
    },
    routing: [
      {
        goal: 'il2cpp-metadata-native-bridge-static-analysis',
        priority:
          inventory.il2cpp_candidates.length > 0 && inventory.metadata_candidates.length > 0
            ? 'high'
            : 'conditional',
        next_tools: ['pe.structure.analyze', 'elf.structure.analyze', 'strings.extract'],
        required_evidence: ['global-metadata.dat candidate', 'GameAssembly/libil2cpp candidate'],
        consumes: [UNITY_METADATA_ARTIFACT_TYPE],
        produces: ['il2cpp_bridge_static_plan'],
      },
      {
        goal: 'managed-assembly-static-inventory',
        priority: inventory.managed_assembly_candidates.length > 0 ? 'high' : 'conditional',
        next_tools: ['dotnet.assembly.inspect', 'strings.extract'],
        required_evidence: ['managed assembly candidate'],
        consumes: [UNITY_METADATA_ARTIFACT_TYPE],
        produces: ['managed_assembly_inventory'],
      },
      {
        goal: 'supply-chain-and-evidence-reporting',
        priority: 'normal',
        next_tools: [
          'sbom.generate',
          'analysis.evidence.graph',
          'artifact.read',
          'report.generate',
        ],
        required_evidence: [UNITY_METADATA_ARTIFACT_TYPE],
        consumes: [UNITY_METADATA_ARTIFACT_TYPE],
        produces: ['evidence_graph', 'analysis_report'],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      unity_runtime_started_by_tool: false,
      native_library_loaded_by_tool: false,
      decompiler_launched_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildQualityGates(inventory: {
  format: string
  managed_assembly_candidates: string[]
  il2cpp_candidates: string[]
  metadata_candidates: string[]
}) {
  return {
    schema: 'rikune.unity_metadata_inventory.quality_gates.v1',
    passive_static_inventory: true,
    bounded_preview_only: true,
    format_detected: inventory.format !== 'unknown',
    managed_assembly_candidates_present: inventory.managed_assembly_candidates.length > 0,
    il2cpp_candidates_present: inventory.il2cpp_candidates.length > 0,
    metadata_candidates_present: inventory.metadata_candidates.length > 0,
    bridge_pairing_candidate_present:
      inventory.il2cpp_candidates.length > 0 && inventory.metadata_candidates.length > 0,
    sample_executed_by_tool: false,
    unity_runtime_started_by_tool: false,
    native_library_loaded_by_tool: false,
    decompiler_launched_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
  }
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
  const recommendedNextTools = unique([
    'metadata.extract',
    'strings.extract',
    ...managedAssemblies.map(() => 'dotnet.assembly.inspect'),
    ...il2cppCandidates.map((item) =>
      item.toLowerCase().endsWith('.so') ? 'elf.structure.analyze' : 'pe.structure.analyze'
    ),
    ...(metadataCandidates.length > 0 || il2cppCandidates.length > 0
      ? ['analysis.evidence.graph', 'artifact.read']
      : []),
    ...(managedAssemblies.length > 0 ? ['sbom.generate'] : []),
  ])

  const inventory: UnityMetadataInventory = {
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
        'analysis.evidence.graph',
      ],
      notes: [
        'Pair global-metadata.dat with the matching IL2CPP native binary before bridge reconstruction.',
        'This tool does not load GameAssembly, libil2cpp, or Unity runtime components.',
      ],
    },
    workflowRecipes: UNITY_METADATA_WORKFLOW_RECIPES,
    formats: UNITY_METADATA_FORMATS,
    platforms: UNITY_METADATA_PLATFORMS,
    evidence: UNITY_METADATA_EVIDENCE,
    policy: {
      passive: true,
      no_execute: true,
      no_runtime_start: true,
      no_native_load: true,
      no_decompiler_launch: true,
      no_network: true,
      no_mutation: true,
    },
    unsupported_detail:
      'Detailed IL2CPP type/method reconstruction requires explicit opt-in tooling and matched metadata/native binaries.',
    summary: `Passive Unity inventory detected ${format} with ${managedAssemblies.length} managed assembly candidate(s), ${il2cppCandidates.length} IL2CPP candidate(s), and ${metadataCandidates.length} metadata candidate(s).`,
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review global-metadata.dat and IL2CPP native binary pairing before bridge reconstruction.',
      'Analyze managed assembly candidates with .NET inventory tools.',
      'Do not load Unity native libraries or start the Unity runtime during static triage.',
    ],
  }
  const evidenceSummary = buildEvidenceSummary({
    sample_id: options.sampleId,
    filename: options.filename,
    format,
    detected_by: detectedBy,
    unity_version_hints: versionHints,
    managed_assembly_candidates: managedAssemblies,
    il2cpp_candidates: il2cppCandidates,
    metadata_candidates: metadataCandidates,
  })
  const workflowHandoff = buildWorkflowHandoff({
    managed_assembly_candidates: managedAssemblies,
    il2cpp_candidates: il2cppCandidates,
    metadata_candidates: metadataCandidates,
    recommended_next_tools: recommendedNextTools,
  })
  const qualityGates = buildQualityGates({
    format,
    managed_assembly_candidates: managedAssemblies,
    il2cpp_candidates: il2cppCandidates,
    metadata_candidates: metadataCandidates,
  })

  return {
    ...inventory,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
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
            UNITY_METADATA_ARTIFACT_TYPE,
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
