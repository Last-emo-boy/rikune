/**
 * dotnet.decompile.type — Decompile a specific type from a .NET assembly.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics, truncateText,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'dotnet.decompile.type'

export const dotnetDecompileTypeInputSchema = z.object({
  sample_id: z.string().describe('Target .NET assembly sample identifier.'),
  type_name: z.string().describe('Fully qualified type name to decompile (e.g. "MyNamespace.MyClass").'),
  language: z.enum(['CSharp', 'IL']).default('CSharp').describe('Output language.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('Decompilation timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist decompiled source as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const dotnetDecompileTypeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    type_name: z.string().optional(),
    source: z.string().optional(),
    source_lines: z.number().optional(),
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

export const dotnetDecompileTypeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decompile a specific type (class) from a .NET assembly using ILSpy CLI. Use dotnet.types.list to discover type names first.',
  inputSchema: dotnetDecompileTypeInputSchema,
  outputSchema: dotnetDecompileTypeOutputSchema,
}

export function createDotnetDecompileTypeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = dotnetDecompileTypeInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.ILSPYCMD_PATH, pathCandidates: ['ilspycmd'], versionArgSets: [['--version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'ilspycmd', available: false, error: 'ilspycmd not installed' } as any, startTime, TOOL_NAME)
      }

      const ilspyArgs = [samplePath, '-t', input.type_name]
      if (input.language === 'IL') ilspyArgs.push('-il')
      const result = await executeCommand(backend.path, ilspyArgs, input.timeout_sec * 1000)

      const source = result.stdout.trim()
      if (!source && result.exitCode !== 0) {
        return { ok: false, errors: [`ilspycmd exited ${result.exitCode}: ${result.stderr}`], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const lineCount = source.split('\n').length

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact && source.length > 0) {
        const ext = input.language === 'IL' ? 'il' : 'cs'
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'dotnet_decompile', `type_${input.type_name}`, source, { extension: ext, mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          type_name: input.type_name,
          source: truncateText(source, 5000),
          source_lines: lineCount,
          artifact,
          summary: `Decompiled type ${input.type_name}: ${lineCount} lines of ${input.language}.`,
          recommended_next_tools: ['artifact.read', 'dotnet.decompile', 'managed.il_xrefs'],
          next_actions: [
            'Use artifact.read for the full decompiled output.',
            'Use managed.il_xrefs for cross-reference analysis of this type.',
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
