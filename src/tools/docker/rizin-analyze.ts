/**
 * Rizin analyze tool — bounded Rizin inspection on a sample.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../types.js'
import type { WorkspaceManager } from '../../workspace-manager.js'
import type { DatabaseManager } from '../../database.js'
import type { SharedBackendDependencies } from './docker-shared.js'
import {
  randomUUID,
  ArtifactRefSchema, BackendSchema, SharedMetricsSchema,
  ensureSampleExists, executeCommand, truncateText, normalizeError, safeJsonParse,
  persistBackendArtifact, buildMetrics, buildStaticSetupRequired,
  findBackendPreviewEvidence, persistBackendPreviewEvidence, buildEvidenceReuseWarnings,
  resolveSampleFile, resolveAnalysisBackends,
  getRuntimeWorkerPool, buildRizinPreviewCompatibilityKey, resolvePackagePath,
} from './docker-shared.js'

export const rizinAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  operation: z
    .enum(['info', 'sections', 'imports', 'exports', 'entrypoints', 'functions', 'strings'])
    .default('info')
    .describe('Bounded Rizin inspection mode.'),
  max_items: z.number().int().min(1).max(200).default(25).describe('Maximum preview items to return.'),
  timeout_sec: z.number().int().min(1).max(180).default(45).describe('Rizin execution timeout in seconds.'),
  persist_artifact: z.boolean().default(true).describe('Persist the raw JSON result as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const rizinAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      operation: z.string().optional(),
      item_count: z.number().int().nonnegative().optional(),
      preview: z.any().optional(),
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

export const rizinAnalyzeToolDefinition: ToolDefinition = {
  name: 'rizin.analyze',
  description:
    'Run bounded Rizin inspection on a sample for info, sections, imports, exports, entrypoints, functions, or strings. Use this when you explicitly want Rizin-backed inspection instead of the default workflow backends.',
  inputSchema: rizinAnalyzeInputSchema,
  outputSchema: rizinAnalyzeOutputSchema,
}

function getRizinCommand(operation: z.infer<typeof rizinAnalyzeInputSchema>['operation']): string {
  switch (operation) {
    case 'sections':
      return 'iSj'
    case 'imports':
      return 'iij'
    case 'exports':
      return 'iEj'
    case 'entrypoints':
      return 'iej'
    case 'functions':
      return 'aaa;aflj'
    case 'strings':
      return 'izj'
    case 'info':
    default:
      return 'ij'
  }
}

export function createRizinAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = rizinAnalyzeInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      const evidenceArgs = {
        operation: input.operation,
        max_items: input.max_items,
      }
      const reused = findBackendPreviewEvidence(
        database,
        sample,
        'rizin',
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
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.rizin
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, rizinAnalyzeToolDefinition.name)
      }

      const command = getRizinCommand(input.operation)
      const pooledResult = !dependencies?.executeCommand
        ? await getRuntimeWorkerPool().executeHelperWorker(
            {
              job_id: randomUUID(),
              backend_path: backend.path,
              sample_path: samplePath,
              command,
              timeout_ms: input.timeout_sec * 1000,
            },
            {
              database,
              family: 'rizin.preview',
              compatibilityKey: buildRizinPreviewCompatibilityKey({
                backendPath: backend.path,
                backendVersion: backend.version,
                operation: input.operation,
                helperPath: resolvePackagePath('workers', 'rizin_preview_worker.py'),
              }),
              timeoutMs: input.timeout_sec * 1000,
              spawnConfig: {
                command:
                  process.platform === 'win32'
                    ? 'python'
                    : 'python3',
                args: [resolvePackagePath('workers', 'rizin_preview_worker.py')],
              },
            }
          )
        : null
      const commandResult = dependencies?.executeCommand
        ? await dependencies.executeCommand(
            backend.path,
            ['-A', '-q0', '-c', `${command};q`, samplePath],
            input.timeout_sec * 1000
          )
        : null

      const effectiveResult =
        pooledResult
          ? {
              stdout:
                typeof pooledResult.response.data === 'object' &&
                pooledResult.response.data &&
                typeof (pooledResult.response.data as Record<string, unknown>).stdout === 'string'
                  ? String((pooledResult.response.data as Record<string, unknown>).stdout)
                  : '',
              stderr:
                typeof pooledResult.response.data === 'object' &&
                pooledResult.response.data &&
                typeof (pooledResult.response.data as Record<string, unknown>).stderr === 'string'
                  ? String((pooledResult.response.data as Record<string, unknown>).stderr)
                  : '',
              exitCode:
                typeof pooledResult.response.data === 'object' &&
                pooledResult.response.data &&
                typeof (pooledResult.response.data as Record<string, unknown>).exit_code === 'number'
                  ? Number((pooledResult.response.data as Record<string, unknown>).exit_code)
                  : pooledResult.response.ok
                    ? 0
                    : 1,
              timedOut:
                typeof pooledResult.response.data === 'object' &&
                pooledResult.response.data &&
                typeof (pooledResult.response.data as Record<string, unknown>).timed_out === 'boolean'
                  ? Boolean((pooledResult.response.data as Record<string, unknown>).timed_out)
                  : false,
            }
          : {
              stdout: commandResult?.stdout || '',
              stderr: commandResult?.stderr || '',
              exitCode: commandResult?.exitCode ?? 1,
              timedOut: commandResult?.timedOut ?? false,
            }

      if (pooledResult && !pooledResult.response.ok) {
        return {
          ok: false,
          errors:
            pooledResult.response.errors && pooledResult.response.errors.length > 0
              ? pooledResult.response.errors
              : ['Rizin pooled helper failed without returning a concrete error.'],
          warnings: pooledResult.response.warnings,
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      if (effectiveResult.exitCode !== 0) {
        return {
          ok: false,
          errors: [
            `Rizin exited with code ${effectiveResult.exitCode}`,
            effectiveResult.stderr || effectiveResult.stdout || 'No backend output was returned.',
          ],
          metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
        }
      }

      const parsed = safeJsonParse<any>(effectiveResult.stdout.trim())
      let preview: unknown = parsed
      let itemCount = 0
      if (Array.isArray(parsed)) {
        itemCount = parsed.length
        preview = parsed.slice(0, input.max_items)
      } else if (parsed && typeof parsed === 'object') {
        const entries = Object.entries(parsed)
        itemCount = entries.length
        preview = Object.fromEntries(entries.slice(0, input.max_items))
      } else {
        const previewText = truncateText(effectiveResult.stdout.trim(), 3000)
        preview = {
          inline_text: previewText.text,
          truncated: previewText.truncated,
        }
      }

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'rizin',
          input.operation,
          JSON.stringify(parsed ?? { stdout: commandResult?.stdout }, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      const outputData = {
        status: 'ready',
        backend,
        sample_id: input.sample_id,
        operation: input.operation,
        item_count: itemCount,
        preview,
        worker_pool: pooledResult
          ? {
              family: pooledResult.lease.family,
              compatibility_key: pooledResult.lease.compatibility_key,
              deployment_key: pooledResult.lease.deployment_key,
              worker_id: pooledResult.lease.worker_id,
              pool_kind: pooledResult.lease.pool_kind,
              warm_reuse: pooledResult.lease.warm_reuse,
              cold_start: pooledResult.lease.cold_start,
            }
          : undefined,
        artifact,
        summary: `Rizin completed ${input.operation} inspection for ${input.sample_id}.`,
        recommended_next_tools: ['artifact.read', 'code.function.disassemble', 'code.xrefs.analyze'],
        next_actions: [
          'Use artifact.read for the full JSON payload when the inline preview is truncated.',
          'Prefer Ghidra-backed code tools when you need code-level decompile or reconstruction after this quick inspection.',
        ],
      } satisfies Record<string, unknown>

      persistBackendPreviewEvidence(
        database,
        sample,
        'rizin',
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
        metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, rizinAnalyzeToolDefinition.name),
      }
    }
  }
}
