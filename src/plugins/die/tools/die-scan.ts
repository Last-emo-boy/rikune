/**
 * die.scan — Full DIE signature scan with detailed results.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics, safeJsonParse,
  resolveSampleFile, resolveAnalysisBackends,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'die.scan'

export const dieScanInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  deep_scan: z.boolean().default(true).describe('Enable deep scan mode for thorough analysis.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('DIE scan timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist scan results as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const dieScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    file_type: z.string().optional(),
    arch: z.string().optional(),
    mode: z.string().optional(),
    entropy: z.number().optional(),
    detects: z.array(z.object({
      type: z.string().optional(),
      name: z.string().optional(),
      version: z.string().optional(),
      options: z.string().optional(),
    })).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const dieScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run a full Detect It Easy signature scan. Returns detailed compiler, packer, linker, and crypto detections with version info.',
  inputSchema: dieScanInputSchema,
  outputSchema: dieScanOutputSchema,
}

export function createDieScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = dieScanInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = resolveAnalysisBackends()
      const backend = backends.die
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'die', available: false, error: 'diec (Detect It Easy console) not installed' } as any, startTime, TOOL_NAME)
      }

      const dieArgs = [samplePath, '-j']
      if (input.deep_scan) dieArgs.push('-d')
      const result = await executeCommand(backend.path, dieArgs, input.timeout_sec * 1000)

      if (result.exitCode !== 0 && !result.stdout.trim()) {
        return { ok: false, errors: [`DIE exited with code ${result.exitCode}: ${result.stderr}`], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const parsed = safeJsonParse<any>(result.stdout)
      if (!parsed) {
        return { ok: false, errors: ['Failed to parse DIE JSON output'], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const detects = (parsed.detects || []).map((d: any) => ({
        type: d.type || d.filetype || '',
        name: d.name || d.string || '',
        version: d.version || '',
        options: d.options || '',
      }))

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'die', 'scan', JSON.stringify(parsed, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          file_type: parsed.filetype || parsed.type || '',
          arch: parsed.arch || '',
          mode: parsed.mode || '',
          entropy: parsed.entropy,
          detects,
          artifact,
          summary: `DIE detected ${detects.length} signature(s): ${detects.map((d: any) => `${d.type}:${d.name}`).join(', ') || 'none'}.`,
          recommended_next_tools: ['packer.detect', 'compiler.packer.detect', 'unpack.auto'],
          next_actions: [
            'Cross-reference with packer.detect for consensus.',
            'If packed, use unpack.auto to attempt unpacking.',
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
