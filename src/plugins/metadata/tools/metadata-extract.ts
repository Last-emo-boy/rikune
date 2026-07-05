/**
 * metadata.extract — Extract file metadata using exiftool.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  normalizeError,
  executeCommand,
  safeJsonParse,
  persistBackendArtifact,
  buildMetrics,
  resolveSampleFile,
  resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'metadata.extract'
export const METADATA_EXTRACT_ARTIFACT_TYPE = 'metadata'
export const METADATA_EXTRACT_FORMATS = [
  'unknown',
  'generic',
  'generic-file',
  'raw-file',
  'binary',
  'pe',
  'coff',
  'pdb',
  'elf',
  'elf-object',
  'linux-kernel-module',
  'macho',
  'macho-object',
  'dsym',
  'apk',
  'ipa',
  'dmg',
  'pkg',
  'deb',
  'rpm',
  'appimage',
  'jar',
  'wasm',
  'firmware',
  'archive',
  'container',
  'office',
  'pdf',
]
export const METADATA_EXTRACT_PLATFORMS = [
  'windows',
  'linux',
  'macos',
  'ios',
  'android',
  'cross-platform',
]
export const METADATA_EXTRACT_SAFETY = [
  'passive',
  'no_network',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample',
  'no_live_sample_by_default',
  'no_sample_execution',
]
export const METADATA_EXTRACT_CAPABILITIES = [
  'metadata',
  'file-metadata',
  'file-profile',
  'search-profile',
  'passive-profile',
  'unknown-file-triage',
  'generic-file-triage',
  'package-metadata',
  'manifest',
  'routing',
  'workflow-handoff',
  'metadata-only-handoff',
  'evidence-correlation',
]
export const METADATA_EXTRACT_EVIDENCE = [
  'file-metadata',
  'package-metadata',
  'manifest',
  'provenance',
  'workflow',
  'search-profile',
]
export const METADATA_EXTRACT_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'container.structure.analyze',
  'strings.extract',
  'static.capability.triage',
  'analysis.evidence.graph',
  'report.generate',
]
export const METADATA_EXTRACT_WORKFLOW_RECIPES = [
  {
    id: 'metadata.passive-file-profile',
    title: 'Passive generic file metadata profile',
    description:
      'Use ExifTool metadata as the read-only entry profile for unknown or generic files before structure, strings, evidence graph, or reporting handoffs.',
    startsWith: [TOOL_NAME],
    nextTools: METADATA_EXTRACT_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [METADATA_EXTRACT_ARTIFACT_TYPE],
    evidence: METADATA_EXTRACT_EVIDENCE,
    safety: METADATA_EXTRACT_SAFETY,
  },
]
export const METADATA_EXTRACT_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'ExifTool is invoked only as a read-only local metadata extractor for the selected sample.',
    'The passive profile must not fetch network resources, mutate samples, or execute live samples.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}

export const metadataExtractInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(60).default(15).describe('Extraction timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist metadata as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const metadataExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      file_type: z.string().optional(),
      mime_type: z.string().optional(),
      file_size: z.string().optional(),
      metadata: z.record(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const metadataExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract universal file metadata using exiftool. Works on PE, ELF, Office docs, PDFs, images, archives, and more.',
  inputSchema: metadataExtractInputSchema,
  outputSchema: metadataExtractOutputSchema,
  aspects: {
    formats: METADATA_EXTRACT_FORMATS,
    platforms: METADATA_EXTRACT_PLATFORMS,
    execution: ['static', 'triage'],
    safety: METADATA_EXTRACT_SAFETY,
    capabilities: METADATA_EXTRACT_CAPABILITIES,
    evidence: METADATA_EXTRACT_EVIDENCE,
  },
  artifacts: [
    {
      type: METADATA_EXTRACT_ARTIFACT_TYPE,
      description: 'Universal read-only file metadata extracted by ExifTool',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    {
      category: 'file-metadata',
      artifactTypes: [METADATA_EXTRACT_ARTIFACT_TYPE],
    },
    {
      category: 'package-metadata',
      artifactTypes: [METADATA_EXTRACT_ARTIFACT_TYPE],
    },
    {
      category: 'manifest',
      artifactTypes: [METADATA_EXTRACT_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [METADATA_EXTRACT_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [METADATA_EXTRACT_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: METADATA_EXTRACT_WORKFLOW_RECIPES,
  runtimePolicy: METADATA_EXTRACT_RUNTIME_POLICY,
}

function metadataValue(meta: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = meta[key]
    if (typeof value === 'string' && value.trim().length > 0) return value.trim()
    if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  }
  return ''
}

function metadataGroupCounts(meta: Record<string, unknown>): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const key of Object.keys(meta)) {
    const group = key.includes(':') ? key.split(':')[0] : 'root'
    counts[group] = (counts[group] ?? 0) + 1
  }
  return counts
}

function routeToolsForMetadataProfile(fileType: string, mimeType: string): string[] {
  const normalized = `${fileType} ${mimeType}`.toLowerCase()
  const tools = new Set<string>(['strings.extract'])

  if (/\b(pe|exe|dll|coff)\b|portable executable/.test(normalized)) {
    tools.add('pe.structure.analyze')
    tools.add('pe.signature.verify')
  }
  if (/\b(elf|so)\b|x-executable|x-sharedlib/.test(normalized)) {
    tools.add('elf.structure.analyze')
  }
  if (/\b(macho|dmg|pkg|ipa)\b|x-mach-binary|x-apple/.test(normalized)) {
    tools.add('macho.structure.analyze')
    tools.add('apple.container.inventory')
  }
  if (
    /\b(zip|7z|tar|gzip|bzip2|rar|cab|msi|deb|rpm|apk|jar)\b|archive|compressed/.test(normalized)
  ) {
    tools.add('container.structure.analyze')
  }
  if (/\b(apk)\b|android/.test(normalized)) tools.add('android.package.inventory')
  if (/\b(office|doc|docx|xls|xlsx|ppt|pptx|ole)\b|msword|officedocument/.test(normalized)) {
    tools.add('office.behavior.profile')
  }
  if (/\b(wasm)\b|webassembly/.test(normalized)) tools.add('wasm.structure.analyze')

  tools.add('analysis.evidence.graph')
  tools.add('report.generate')
  return Array.from(tools)
}

export function buildMetadataExtractProfile(args: {
  sampleId?: string
  metadata: Record<string, unknown>
}) {
  const { metadata, sampleId } = args
  const fileType = metadataValue(metadata, ['File:FileType', 'FileType'])
  const mimeType = metadataValue(metadata, ['File:MIMEType', 'MIMEType'])
  const fileSize = metadataValue(metadata, ['File:FileSize', 'FileSize'])
  const keyCount = Object.keys(metadata).length
  const metadataGroups = metadataGroupCounts(metadata)
  const formatRouteTools = routeToolsForMetadataProfile(fileType, mimeType)
  const recommendedNextTools = Array.from(
    new Set([...METADATA_EXTRACT_FOLLOW_UP_TOOLS, ...formatRouteTools])
  )
  const hasTimestamp =
    Object.keys(metadata).some((key) => /date|time|timestamp/i.test(key)) ||
    Boolean(metadataValue(metadata, ['File:FileModifyDate', 'File:FileCreateDate']))
  const hasFileIdentity = Boolean(fileType || mimeType || fileSize)

  const evidence_summary = {
    schema: 'rikune.metadata_extract.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: sampleId ?? null,
    artifact_type: METADATA_EXTRACT_ARTIFACT_TYPE,
    file_type: fileType || null,
    mime_type: mimeType || null,
    file_size: fileSize || null,
    metadata_field_count: keyCount,
    metadata_groups: metadataGroups,
    timestamp_metadata_present: hasTimestamp,
    static_only: true,
  }

  const workflow_handoff = {
    schema: 'rikune.metadata_extract.workflow_handoff.v1',
    handoff_mode: 'metadata_file_profile_to_format_routing',
    source_tool: TOOL_NAME,
    sample_id: sampleId ?? null,
    artifact_type: METADATA_EXTRACT_ARTIFACT_TYPE,
    recommended_next_tools: recommendedNextTools,
    artifact_contract: {
      consumes: ['sample'],
      produces: [METADATA_EXTRACT_ARTIFACT_TYPE],
      expected_consumers: recommendedNextTools,
    },
    routing: [
      {
        goal: 'format-specific-inventory',
        priority: hasFileIdentity ? 'high' : 'normal',
        next_tools: formatRouteTools,
        required_evidence: ['file_type', 'mime_type', 'metadata_fields'],
      },
      {
        goal: 'strings-evidence-and-reporting',
        priority: 'normal',
        next_tools: ['strings.extract', 'analysis.evidence.graph', 'report.generate'],
        required_evidence: ['metadata_profile'],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: true,
      network_accessed_by_tool: false,
      mutation_performed: false,
      runtime_started_by_tool: false,
      decompiler_launched_by_tool: false,
    },
  }

  const quality_gates = {
    schema: 'rikune.metadata_extract.quality_gates.v1',
    passive_metadata_only: true,
    metadata_fields_present: keyCount > 0,
    file_identity_present: hasFileIdentity,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    runtime_started_by_tool: false,
    decompiler_launched_by_tool: false,
  }

  return {
    sample_id: sampleId,
    file_type: fileType,
    mime_type: mimeType,
    file_size: fileSize,
    metadata,
    evidence_summary,
    workflow_handoff,
    quality_gates,
    summary: `Extracted ${keyCount} metadata fields. Type: ${fileType}, MIME: ${mimeType}, Size: ${fileSize}.`,
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Use extracted metadata as a passive file profile before choosing format-specific analysis.',
      'Correlate metadata with strings, container structure, evidence graph, and reporting workflows.',
    ],
  }
}

export function createMetadataExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = metadataExtractInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({
        envPath: process.env.EXIFTOOL_PATH,
        pathCandidates: ['exiftool'],
        versionArgSets: [['-ver']],
      })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(
          backend ||
            ({
              name: 'exiftool',
              available: false,
              error: 'exiftool not installed. apt-get install libimage-exiftool-perl',
            } as any),
          startTime,
          TOOL_NAME
        )
      }

      const result = await executeCommand(
        backend.path,
        ['-json', '-G', samplePath],
        input.timeout_sec * 1000
      )

      if (result.exitCode !== 0 && !result.stdout.trim()) {
        return {
          ok: false,
          errors: [`exiftool exited ${result.exitCode}: ${result.stderr}`],
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }

      const parsed = safeJsonParse<any[]>(result.stdout)
      const meta = (parsed && parsed[0]) || {}

      const fileType = meta['File:FileType'] || meta['FileType'] || ''
      const mimeType = meta['File:MIMEType'] || meta['MIMEType'] || ''
      const fileSize = meta['File:FileSize'] || meta['FileSize'] || ''
      const profile = buildMetadataExtractProfile({
        sampleId: input.sample_id,
        metadata: meta,
      })

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'metadata',
          'extract',
          JSON.stringify(profile, null, 2),
          { extension: 'json', mime: 'application/json', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          ...profile,
          file_type: fileType,
          mime_type: mimeType,
          file_size: fileSize,
          artifact,
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    }
  }
}
