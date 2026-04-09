/**
 * Wine run tool — preflight or run a sample under Wine or winedbg.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from './docker-shared.js'
import {
  ArtifactRefSchema, BackendSchema, SharedMetricsSchema,
  executeCommand, truncateText, normalizeError,
  persistBackendArtifact, buildMetrics, buildDynamicSetupRequired,
  resolveSampleFile, resolveAnalysisBackends,
} from './docker-shared.js'

export const wineRunInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  mode: z
    .enum(['preflight', 'run', 'debug'])
    .default('preflight')
    .describe('preflight only checks readiness, run uses wine, debug uses winedbg.'),
  approved: z
    .boolean()
    .default(false)
    .describe('Required when mode=run or mode=debug because those modes attempt to start the sample under Wine.'),
  timeout_sec: z.number().int().min(1).max(180).default(30).describe('Execution timeout in seconds.'),
  arguments: z.array(z.string()).default([]).describe('Optional command-line arguments forwarded to the sample.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist captured stdout/stderr as an artifact for run or debug mode.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const wineRunOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required', 'denied']),
      backend: z.object({
        wine: BackendSchema,
        winedbg: BackendSchema,
      }),
      sample_id: z.string().optional(),
      mode: z.string().optional(),
      approved: z.boolean().optional(),
      execution: z
        .object({
          exit_code: z.number().int(),
          timed_out: z.boolean(),
          stdout_preview: z.string().optional(),
          stderr_preview: z.string().optional(),
        })
        .optional(),
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

export const wineRunToolDefinition: ToolDefinition = {
  name: 'wine.run',
  description:
    'Preflight or run a sample under Wine or winedbg. Use this only when you explicitly request Linux-hosted Wine debugging or execution; run/debug modes require approved=true.',
  inputSchema: wineRunInputSchema,
  outputSchema: wineRunOutputSchema,
}

export function createWineRunHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = wineRunInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const wineBackend = backends.wine
      const winedbgBackend = backends.winedbg

      const selectedBackend = input.mode === 'debug' ? winedbgBackend : wineBackend
      if (!selectedBackend.available || !selectedBackend.path) {
        return buildDynamicSetupRequired(selectedBackend, startTime, wineRunToolDefinition.name)
      }

      if (input.mode === 'preflight') {
        return {
          ok: true,
          data: {
            status: 'ready',
            backend: {
              wine: wineBackend,
              winedbg: winedbgBackend,
            },
            sample_id: input.sample_id,
            mode: input.mode,
            approved: input.approved,
            summary: 'Wine readiness probe completed without launching the sample.',
            recommended_next_tools: ['sandbox.execute', 'dynamic.dependencies', 'tool.help'],
            next_actions: [
              'Set approved=true only when you intentionally want to launch the sample under Wine or winedbg.',
            ],
          },
          metrics: buildMetrics(startTime, wineRunToolDefinition.name),
        }
      }

      if (!input.approved) {
        return {
          ok: true,
          data: {
            status: 'denied',
            backend: {
              wine: wineBackend,
              winedbg: winedbgBackend,
            },
            sample_id: input.sample_id,
            mode: input.mode,
            approved: false,
            summary: 'Wine execution was not attempted because approved=false.',
            recommended_next_tools: ['sandbox.execute', 'dynamic.dependencies', 'system.health'],
            next_actions: [
              'Retry with approved=true only when you deliberately want MCP to start the sample under Wine or winedbg.',
            ],
          },
          warnings: ['Wine execution requires approved=true.'],
          metrics: buildMetrics(startTime, wineRunToolDefinition.name),
        }
      }

      const runner = dependencies?.executeCommand || executeCommand
      const result = await runner(selectedBackend.path, [samplePath, ...input.arguments], input.timeout_sec * 1000)

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          input.mode === 'debug' ? 'winedbg' : 'wine',
          'run',
          `${result.stdout}\n${result.stderr}`.trim(),
          {
            extension: 'txt',
            mime: 'text/plain',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          status: 'ready',
          backend: {
            wine: wineBackend,
            winedbg: winedbgBackend,
          },
          sample_id: input.sample_id,
          mode: input.mode,
          approved: true,
          execution: {
            exit_code: result.exitCode,
            timed_out: result.timedOut,
            stdout_preview: truncateText(result.stdout, 2000).text || undefined,
            stderr_preview: truncateText(result.stderr, 2000).text || undefined,
          },
          artifact,
          summary: `${input.mode === 'debug' ? 'winedbg' : 'wine'} launched the sample and exited with code ${result.exitCode}.`,
          recommended_next_tools: ['artifact.read', 'sandbox.execute', 'dynamic.trace.import'],
          next_actions: [
            'Use artifact.read for the full Wine stdout/stderr capture when the preview is truncated.',
          ],
        },
        artifacts,
        warnings: result.timedOut ? ['Wine execution timed out before completion.'] : undefined,
        metrics: buildMetrics(startTime, wineRunToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, wineRunToolDefinition.name),
      }
    }
  }
}
