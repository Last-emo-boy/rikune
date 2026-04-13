/**
 * go.types.list — List Go types (interfaces, structs) recovered from a binary.
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

const TOOL_NAME = 'go.types.list'

export const goTypesListInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('GoReSym timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist type list as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const goTypesListOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    type_count: z.number().optional(),
    types_preview: z.array(z.any()).optional(),
    interfaces_preview: z.array(z.any()).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const goTypesListToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'List Go types (structs, interfaces) recovered from a Go binary using GoReSym.',
  inputSchema: goTypesListInputSchema,
  outputSchema: goTypesListOutputSchema,
}

export function createGoTypesListHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = goTypesListInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.GORESYM_PATH, pathCandidates: ['GoReSym', 'goresym'], versionArgSets: [['-version'], ['--help']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'GoReSym', available: false, error: 'GoReSym not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await executeCommand(backend.path, ['-t', '-d', '-p', samplePath], input.timeout_sec * 1000)
      const parsed = safeJsonParse<any>(result.stdout)
      if (!parsed) {
        return { ok: false, errors: ['Not a Go binary or GoReSym failed'], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const types = parsed.Types || []
      const interfaces = parsed.Interfaces || []

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'goresym', 'types', JSON.stringify({ types, interfaces }, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          type_count: types.length + interfaces.length,
          types_preview: types.slice(0, 30),
          interfaces_preview: interfaces.slice(0, 20),
          artifact,
          summary: `Go binary: ${types.length} types and ${interfaces.length} interfaces recovered.`,
          recommended_next_tools: ['artifact.read', 'go.symbols.recover', 'go.binary.analyze'],
          next_actions: ['Use artifact.read for full type/interface listing.'],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
