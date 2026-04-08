/**
 * RetDec decompile tool — decompile a sample with RetDec.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../types.js'
import type { WorkspaceManager } from '../../workspace-manager.js'
import type { DatabaseManager } from '../../database.js'
import type { SharedBackendDependencies } from './docker-shared.js'
import {
  fs, os, path,
  ArtifactRefSchema, BackendSchema, SharedMetricsSchema,
  executeCommand, truncateText, normalizeError,
  persistBackendArtifact, buildMetrics, buildStaticSetupRequired,
  resolveSampleFile, resolveAnalysisBackends,
} from './docker-shared.js'

export const retdecDecompileInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  output_format: z
    .enum(['plain', 'json-human'])
    .default('plain')
    .describe('RetDec output format for the main decompilation file.'),
  timeout_sec: z.number().int().min(10).max(900).default(300).describe('RetDec timeout in seconds.'),
  persist_artifact: z.boolean().default(true).describe('Persist the generated decompilation output as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const retdecDecompileOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      output_format: z.string().optional(),
      preview: z
        .object({
          inline_text: z.string(),
          truncated: z.boolean(),
          char_count: z.number().int().nonnegative(),
        })
        .optional(),
      artifact: ArtifactRefSchema.optional(),
      supporting_artifacts: z.array(ArtifactRefSchema).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const retdecDecompileToolDefinition: ToolDefinition = {
  name: 'retdec.decompile',
  description:
    'Decompile a sample with RetDec and persist the generated high-level output as an artifact. Use this when you explicitly want a RetDec alternative to the default Ghidra-oriented flow.',
  inputSchema: retdecDecompileInputSchema,
  outputSchema: retdecDecompileOutputSchema,
}

export function createRetDecDecompileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = retdecDecompileInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.retdec
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, retdecDecompileToolDefinition.name)
      }

      const runner = dependencies?.executeCommand || executeCommand
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'retdec-decompile-'))
      const outputExtension = input.output_format === 'plain' ? 'c' : 'json'
      const outputPath = path.join(tempDir, `retdec_output.${outputExtension}`)
      const result = await runner(
        backend.path,
        ['--cleanup', '--output-format', input.output_format, '--output', outputPath, samplePath],
        input.timeout_sec * 1000
      )

      if (result.exitCode !== 0) {
        await fs.rm(tempDir, { recursive: true, force: true })
        return {
          ok: false,
          errors: [
            `RetDec exited with code ${result.exitCode}`,
            result.stderr || result.stdout || 'No backend output was returned.',
          ],
          metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
        }
      }

      const mainOutput = await fs.readFile(outputPath, 'utf8')
      const preview = truncateText(mainOutput, 3000)
      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'retdec',
          `decompile_${input.output_format}`,
          mainOutput,
          {
            extension: outputExtension,
            mime: input.output_format === 'plain' ? 'text/x-csrc' : 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      await fs.rm(tempDir, { recursive: true, force: true })

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id,
          output_format: input.output_format,
          preview: {
            inline_text: preview.text,
            truncated: preview.truncated,
            char_count: mainOutput.length,
          },
          artifact,
          supporting_artifacts: [],
          summary: `RetDec produced ${input.output_format} decompilation output for ${input.sample_id}.`,
          recommended_next_tools: ['artifact.read', 'code.function.decompile', 'workflow.reconstruct'],
          next_actions: [
            'Read the persisted RetDec artifact for the full output before comparing it with Ghidra-backed decompile results.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
      }
    }
  }
}
