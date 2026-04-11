/**
 * metadata.extract — Extract file metadata using exiftool.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand, safeJsonParse,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'metadata.extract'

export const metadataExtractInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(60).default(15).describe('Extraction timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist metadata as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const metadataExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    file_type: z.string().optional(),
    mime_type: z.string().optional(),
    file_size: z.string().optional(),
    metadata: z.record(z.any()).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
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
}

export function createMetadataExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = metadataExtractInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.EXIFTOOL_PATH, pathCandidates: ['exiftool'], versionArgSets: [['-ver']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'exiftool', available: false, error: 'exiftool not installed. apt-get install libimage-exiftool-perl' } as any, startTime, TOOL_NAME)
      }

      const result = await executeCommand(backend.path, ['-json', '-G', samplePath], input.timeout_sec * 1000)

      if (result.exitCode !== 0 && !result.stdout.trim()) {
        return { ok: false, errors: [`exiftool exited ${result.exitCode}: ${result.stderr}`], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const parsed = safeJsonParse<any[]>(result.stdout)
      const meta = (parsed && parsed[0]) || {}

      const fileType = meta['File:FileType'] || meta['FileType'] || ''
      const mimeType = meta['File:MIMEType'] || meta['MIMEType'] || ''
      const fileSize = meta['File:FileSize'] || meta['FileSize'] || ''

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'metadata', 'extract', JSON.stringify(meta, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      const keyCount = Object.keys(meta).length

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          file_type: fileType,
          mime_type: mimeType,
          file_size: fileSize,
          metadata: meta,
          artifact,
          summary: `Extracted ${keyCount} metadata fields. Type: ${fileType}, MIME: ${mimeType}, Size: ${fileSize}.`,
          recommended_next_tools: ['artifact.read', 'pe.structure.analyze', 'pe.signature.verify'],
          next_actions: [
            'Review compilation timestamps and author metadata for attribution.',
            'Cross-reference with PE structure analysis.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
