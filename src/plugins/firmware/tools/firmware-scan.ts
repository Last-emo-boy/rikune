/**
 * firmware.scan — Scan a file for embedded firmware signatures.
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

const TOOL_NAME = 'firmware.scan'

export const firmwareScanInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('Scan timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist scan results as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const firmwareScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    signature_count: z.number().optional(),
    signatures: z.array(z.object({
      offset: z.string(),
      description: z.string(),
    })).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const firmwareScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Scan a file with binwalk for embedded firmware signatures (file systems, kernels, compressed archives, etc.).',
  inputSchema: firmwareScanInputSchema,
  outputSchema: firmwareScanOutputSchema,
}

export function createFirmwareScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = firmwareScanInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.BINWALK_PATH, pathCandidates: ['binwalk'], versionArgSets: [['--help']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'binwalk', available: false, error: 'binwalk not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await executeCommand(backend.path, [samplePath], input.timeout_sec * 1000)
      const lines = result.stdout.trim().split(/\r?\n/).filter(Boolean)

      // Parse binwalk output: DECIMAL  HEXADECIMAL  DESCRIPTION
      const signatures: Array<{ offset: string; description: string }> = []
      for (const line of lines) {
        const match = line.match(/^\s*(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$/)
        if (match) {
          signatures.push({ offset: match[2], description: match[3].trim() })
        }
      }

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'firmware', 'scan', result.stdout, { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          signature_count: signatures.length,
          signatures: signatures.slice(0, 50),
          artifact,
          summary: `Binwalk detected ${signatures.length} embedded signature(s).`,
          recommended_next_tools: ['firmware.extract', 'firmware.entropy', 'entropy.analyze'],
          next_actions: [
            'Use firmware.extract to carve out embedded files.',
            'Use firmware.entropy for block-level entropy analysis.',
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
