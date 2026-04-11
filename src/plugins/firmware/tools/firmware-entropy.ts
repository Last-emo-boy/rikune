/**
 * firmware.entropy — Compute block-level entropy of a firmware image.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'firmware.entropy'

export const firmwareEntropyInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('Entropy computation timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist entropy data as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const firmwareEntropyOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    entropy_output: z.string().optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const firmwareEntropyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compute block-level entropy of a firmware image using binwalk. Helps identify encrypted/compressed regions.',
  inputSchema: firmwareEntropyInputSchema,
  outputSchema: firmwareEntropyOutputSchema,
}

export function createFirmwareEntropyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = firmwareEntropyInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.BINWALK_PATH, pathCandidates: ['binwalk'], versionArgSets: [['--help']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'binwalk', available: false, error: 'binwalk not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await executeCommand(backend.path, ['-E', samplePath], input.timeout_sec * 1000)
      const output = result.stdout.trim()

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact && output) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'firmware', 'entropy', output, { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          entropy_output: output.slice(0, 3000),
          artifact,
          summary: `Binwalk entropy analysis completed. Review output for high-entropy (encrypted/compressed) regions.`,
          recommended_next_tools: ['artifact.read', 'firmware.scan', 'firmware.extract', 'entropy.analyze'],
          next_actions: [
            'High-entropy regions (>7.5) likely indicate encryption or compression.',
            'Use firmware.extract to carve data from specific offsets.',
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
