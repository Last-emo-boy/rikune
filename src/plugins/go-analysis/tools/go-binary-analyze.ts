/**
 * go.binary.analyze — Combined Go binary analysis: version, symbols, types, packages.
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

const TOOL_NAME = 'go.binary.analyze'

export const goBinaryAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(300).default(60).describe('GoReSym timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist analysis as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const goBinaryAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    is_go_binary: z.boolean().optional(),
    go_version: z.string().optional(),
    build_id: z.string().optional(),
    os: z.string().optional(),
    arch: z.string().optional(),
    main_package: z.string().optional(),
    user_packages: z.array(z.string()).optional(),
    user_function_count: z.number().optional(),
    std_function_count: z.number().optional(),
    type_count: z.number().optional(),
    interface_count: z.number().optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const goBinaryAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Comprehensive Go binary analysis: Go version, build info, packages, function & type recovery summary.',
  inputSchema: goBinaryAnalyzeInputSchema,
  outputSchema: goBinaryAnalyzeOutputSchema,
}

export function createGoBinaryAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = goBinaryAnalyzeInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.GORESYM_PATH, pathCandidates: ['GoReSym', 'goresym'], versionArgSets: [['-version'], ['--help']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'GoReSym', available: false, error: 'GoReSym not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await executeCommand(backend.path, ['-t', '-d', '-p', samplePath], input.timeout_sec * 1000)
      const parsed = safeJsonParse<any>(result.stdout)
      if (!parsed) {
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            is_go_binary: false,
            summary: 'Not a Go binary or GoReSym could not parse the file.',
            recommended_next_tools: ['pe.structure.analyze', 'runtime.detect'],
            next_actions: ['Try runtime.detect or pe.structure.analyze for non-Go binaries.'],
          },
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }

      const userFuncs = parsed.UserFunctions || []
      const stdFuncs = parsed.StdFunctions || []
      const types = parsed.Types || []
      const interfaces = parsed.Interfaces || []
      const packages = [...new Set(userFuncs.map((f: any) => f.PackageName).filter(Boolean))].sort()

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'goresym', 'full_analysis', JSON.stringify(parsed, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          is_go_binary: true,
          go_version: parsed.Version || 'unknown',
          build_id: parsed.BuildId || '',
          os: parsed.OS || '',
          arch: parsed.Arch || '',
          main_package: parsed.MainPackage || '',
          user_packages: (packages as string[]).slice(0, 50),
          user_function_count: userFuncs.length,
          std_function_count: stdFuncs.length,
          type_count: types.length,
          interface_count: interfaces.length,
          artifact,
          summary: `Go ${parsed.Version || '?'} binary (${parsed.OS || '?'}/${parsed.Arch || '?'}): ${userFuncs.length} user functions across ${packages.length} packages, ${types.length} types, ${interfaces.length} interfaces.`,
          recommended_next_tools: ['artifact.read', 'go.symbols.recover', 'go.types.list', 'code.function.decompile'],
          next_actions: [
            'Use go.symbols.recover for detailed function listing.',
            'Use go.types.list for type/interface details.',
            'Use code.function.decompile with Ghidra for specific functions.',
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
