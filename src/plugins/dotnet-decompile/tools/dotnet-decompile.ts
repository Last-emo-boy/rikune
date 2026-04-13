/**
 * dotnet.decompile — Decompile an entire .NET assembly to C# source.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  fs, path, os, ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired, truncateText,
} from '../../docker-shared.js'

const TOOL_NAME = 'dotnet.decompile'

export const dotnetDecompileInputSchema = z.object({
  sample_id: z.string().describe('Target .NET assembly sample identifier.'),
  language: z.enum(['CSharp', 'IL']).default('CSharp').describe('Output language: CSharp or IL.'),
  timeout_sec: z.number().int().min(10).max(600).default(120).describe('Decompilation timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist decompiled source as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const dotnetDecompileOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    language: z.string().optional(),
    source_preview: z.string().optional(),
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

export const dotnetDecompileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decompile an entire .NET assembly to C# (or IL) source code using ILSpy CLI. Returns a preview and persists full output as artifact.',
  inputSchema: dotnetDecompileInputSchema,
  outputSchema: dotnetDecompileOutputSchema,
}

export function createDotnetDecompileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = dotnetDecompileInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.ILSPYCMD_PATH, pathCandidates: ['ilspycmd'], versionArgSets: [['--version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'ilspycmd', available: false, error: 'ilspycmd not installed. Run: dotnet tool install ilspycmd -g' } as any, startTime, TOOL_NAME)
      }

      const tmpDir = path.join(os.tmpdir(), `rikune-ilspy-${Date.now()}`)
      await fs.mkdir(tmpDir, { recursive: true })

      try {
        const ilspyArgs = [samplePath, '-p', '-o', tmpDir]
        if (input.language === 'IL') ilspyArgs.push('-il')
        const result = await executeCommand(backend.path, ilspyArgs, input.timeout_sec * 1000)

        if (result.exitCode !== 0 && result.exitCode !== 1) {
          return { ok: false, errors: [`ilspycmd exited ${result.exitCode}: ${result.stderr}`], metrics: buildMetrics(startTime, TOOL_NAME) }
        }

        // Collect all output files
        const files = await collectFiles(tmpDir)
        const allSource = files.map(f => `// ===== ${f.relativePath} =====\n${f.content}`).join('\n\n')
        const lineCount = allSource.split('\n').length

        const artifacts: ArtifactRef[] = []
        let artifact: ArtifactRef | undefined
        if (input.persist_artifact && allSource.length > 0) {
          const ext = input.language === 'IL' ? 'il' : 'cs'
          artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'dotnet_decompile', 'full', allSource, { extension: ext, mime: 'text/plain', sessionTag: input.session_tag })
          artifacts.push(artifact)
        }

        const warnings: string[] = []
        if (result.stderr.trim()) warnings.push(truncateText(result.stderr, 500).text)

        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            language: input.language,
            source_preview: truncateText(allSource, 3000).text,
            source_lines: lineCount,
            artifact,
            summary: `Decompiled ${input.sample_id} to ${input.language}: ${lineCount} lines across ${files.length} file(s).`,
            recommended_next_tools: ['artifact.read', 'dotnet.decompile.type', 'dotnet.types.list', 'code.functions.search'],
            next_actions: [
              'Use artifact.read to view full decompiled source.',
              'Use dotnet.decompile.type for a specific class.',
            ],
          },
          warnings: warnings.length > 0 ? warnings : undefined,
          artifacts,
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      } finally {
        await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {})
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}

async function collectFiles(dir: string, base?: string): Promise<Array<{ relativePath: string; content: string }>> {
  const entries = await fs.readdir(dir, { withFileTypes: true })
  const results: Array<{ relativePath: string; content: string }> = []
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    const relPath = base ? `${base}/${entry.name}` : entry.name
    if (entry.isDirectory()) {
      results.push(...await collectFiles(fullPath, relPath))
    } else if (entry.isFile() && /\.(cs|il|vb)$/i.test(entry.name)) {
      const content = await fs.readFile(fullPath, 'utf8')
      results.push({ relativePath: relPath, content })
    }
  }
  return results
}
