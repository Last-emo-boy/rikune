/**
 * UPX inspect tool — inspect or decompress a sample with UPX.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from './docker-shared.js'
import {
  fs, os, path,
  ArtifactRefSchema, BackendSchema, SharedMetricsSchema,
  ensureSampleExists, executeCommand, truncateText, normalizeError,
  persistBackendArtifact, buildMetrics, buildStaticSetupRequired,
  findBackendPreviewEvidence, persistBackendPreviewEvidence, buildEvidenceReuseWarnings,
  resolveSampleFile, resolveAnalysisBackends,
} from './docker-shared.js'

export const upxInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  operation: z
    .enum(['list', 'test', 'decompress'])
    .default('test')
    .describe('UPX list/test/decompress operation.'),
  timeout_sec: z.number().int().min(1).max(180).default(30).describe('UPX timeout in seconds.'),
  persist_artifact: z.boolean().default(true).describe('Persist decompressed output or inspection text as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const upxInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      operation: z.string().optional(),
      exit_code: z.number().int().optional(),
      stdout_preview: z.string().optional(),
      stderr_preview: z.string().optional(),
      artifact: ArtifactRefSchema.optional(),
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

export const upxInspectToolDefinition: ToolDefinition = {
  name: 'upx.inspect',
  description:
    'Inspect or decompress a sample with UPX. Use this when you explicitly want UPX-aware packed-sample checks rather than generic packer heuristics.',
  inputSchema: upxInspectInputSchema,
  outputSchema: upxInspectOutputSchema,
}

export function createUPXInspectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = upxInspectInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      const evidenceArgs = {
        operation: input.operation,
      }
      const reused = findBackendPreviewEvidence(
        database,
        sample,
        'upx',
        input.operation,
        evidenceArgs
      )
      if (reused) {
        return {
          ok: true,
          data: reused.result as Record<string, unknown>,
          warnings: buildEvidenceReuseWarnings({
            source: 'analysis_evidence',
            record: reused,
          }),
          artifacts: reused.artifact_refs,
          metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.upx
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, upxInspectToolDefinition.name)
      }

      const runner = dependencies?.executeCommand || executeCommand
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'upx-inspect-'))
      let commandArgs: string[] = []
      let outputPath: string | null = null
      if (input.operation === 'list') {
        commandArgs = ['-l', samplePath]
      } else if (input.operation === 'test') {
        commandArgs = ['-t', samplePath]
      } else {
        outputPath = path.join(tempDir, path.basename(samplePath))
        commandArgs = ['-d', '-o', outputPath, samplePath]
      }

      const commandResult = await runner(
        backend.path,
        commandArgs,
        input.timeout_sec * 1000
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        if (input.operation === 'decompress' && outputPath) {
          const decompressed = await fs.readFile(outputPath)
          artifact = await persistBackendArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'upx',
            'decompress',
            decompressed,
            {
              extension: path.extname(samplePath).replace(/^\./, '') || 'bin',
              mime: 'application/octet-stream',
              sessionTag: input.session_tag,
            }
          )
        } else {
          artifact = await persistBackendArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'upx',
            input.operation,
            `${commandResult.stdout}\n${commandResult.stderr}`.trim(),
            {
              extension: 'txt',
              mime: 'text/plain',
              sessionTag: input.session_tag,
            }
          )
        }
        artifacts.push(artifact)
      }

      await fs.rm(tempDir, { recursive: true, force: true })

      const outputData = {
        status: 'ready',
        backend,
        sample_id: input.sample_id,
        operation: input.operation,
        exit_code: commandResult.exitCode,
        stdout_preview: truncateText(commandResult.stdout, 2000).text || undefined,
        stderr_preview: truncateText(commandResult.stderr, 2000).text || undefined,
        artifact,
        summary:
          input.operation === 'decompress'
            ? `UPX decompress completed with exit code ${commandResult.exitCode}.`
            : `UPX ${input.operation} completed with exit code ${commandResult.exitCode}.`,
        recommended_next_tools: ['artifact.read', 'packer.detect', 'workflow.analyze.start'],
        next_actions:
          input.operation === 'decompress'
            ? ['Use the persisted artifact as the unpacked binary for secondary analysis, then continue through workflow.analyze.start or workflow.analyze.promote.']
            : ['Inspect stdout/stderr previews or read the artifact for the full UPX output before promoting deeper staged analysis.'],
      } satisfies Record<string, unknown>

      persistBackendPreviewEvidence(
        database,
        sample,
        'upx',
        input.operation,
        evidenceArgs,
        outputData,
        artifacts,
        {
          backend_version: backend.version,
        }
      )

      return {
        ok: true,
        data: outputData,
        artifacts,
        warnings:
          commandResult.exitCode !== 0
            ? [`UPX returned non-zero exit code ${commandResult.exitCode}.`]
            : undefined,
        metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
      }
    }
  }
}
