/**
 * go.symbols.recover — Recover Go function symbols from a Go binary.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand, safeJsonParse,
  persistBackendArtifact, buildMetrics, truncateText,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'go.symbols.recover'

export const goSymbolsRecoverInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(300).default(60).describe('GoReSym timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist recovered symbols as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const goSymbolsRecoverOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    go_version: z.string().optional(),
    build_id: z.string().optional(),
    function_count: z.number().optional(),
    functions_preview: z.array(z.any()).optional(),
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

export const goSymbolsRecoverToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Recover function symbols from a Go binary using GoReSym. Returns function names, addresses, and source file info.',
  inputSchema: goSymbolsRecoverInputSchema,
  outputSchema: goSymbolsRecoverOutputSchema,
}

export function createGoSymbolsRecoverHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = goSymbolsRecoverInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.GORESYM_PATH, pathCandidates: ['GoReSym', 'goresym'], versionArgSets: [['-version'], ['--help']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'GoReSym', available: false, error: 'GoReSym not installed' } as any, startTime, TOOL_NAME)
      }

      // -t = recover types, -d = recover filenames, -p = recover packages
      const result = await executeCommand(backend.path, ['-t', '-d', '-p', samplePath], input.timeout_sec * 1000)

      if (result.exitCode !== 0 && !result.stdout.trim()) {
        return { ok: false, errors: [`GoReSym exited ${result.exitCode}: ${result.stderr}`], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const parsed = safeJsonParse<any>(result.stdout)
      if (!parsed) {
        return { ok: false, errors: ['Not a Go binary or GoReSym failed to parse'], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const userFuncs = parsed.UserFunctions || []
      const stdFuncs = parsed.StdFunctions || []
      const totalFuncs = userFuncs.length + stdFuncs.length
      const goVersion = parsed.Version || 'unknown'
      const buildId = parsed.BuildId || ''

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'goresym', 'symbols', JSON.stringify(parsed, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          go_version: goVersion,
          build_id: buildId,
          function_count: totalFuncs,
          functions_preview: userFuncs.slice(0, 30).map((f: any) => ({
            name: f.FullName || f.PackageName,
            start: f.Start,
            end: f.End,
            src_file: f.FileName,
            src_line: f.StartLine,
          })),
          artifact,
          summary: `Go ${goVersion} binary: ${userFuncs.length} user + ${stdFuncs.length} std functions recovered.`,
          recommended_next_tools: ['artifact.read', 'go.types.list', 'go.binary.analyze', 'code.function.decompile'],
          next_actions: [
            'Use artifact.read for full function list.',
            'Use go.types.list for Go interface/struct type information.',
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
