/**
 * taint.track tool implementation
 * Track data flow from source APIs to sink APIs, enumerating taint paths.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { CacheManager } from '../../../cache-manager.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from '../../../tools/cache-observability.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from '../../../tools/static-worker-client.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import { CACHE_TTL_30_DAYS } from '../../../constants/cache-ttl.js'

const TOOL_NAME = 'taint.track'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = CACHE_TTL_30_DAYS

export const TaintTrackInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  source_categories: z
    .array(z.enum(['network', 'file', 'registry', 'user_input']))
    .optional()
    .describe('Filter source categories (default: all)'),
  sink_categories: z
    .array(z.enum(['exec', 'write', 'send', 'crypto']))
    .optional()
    .describe('Filter sink categories (default: all)'),
  force_refresh: z.boolean().default(false).describe('Bypass cache lookup'),
})

export type TaintTrackInput = z.infer<typeof TaintTrackInputSchema>

export const TaintTrackOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sources: z.array(z.object({ api: z.string(), category: z.string() })),
      sinks: z.array(z.object({ api: z.string(), category: z.string() })),
      taint_paths: z.array(
        z.object({
          source: z.string(),
          source_category: z.string(),
          sink: z.string(),
          sink_category: z.string(),
          risk: z.string(),
          description: z.string(),
        })
      ),
      risk_summary: z.object({
        critical: z.number(),
        high: z.number(),
        medium: z.number(),
        total_paths: z.number(),
      }),
      recommended_next_tools: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const taintTrackToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Perform static taint tracking: identify source APIs (network, file, registry, user_input), ' +
    'sink APIs (exec, write, send, crypto), and enumerate data-flow taint paths between them. ' +
    'Returns risk-scored paths to highlight critical data flows in the sample.',
  inputSchema: TaintTrackInputSchema,
  outputSchema: TaintTrackOutputSchema,
}

export function createTaintTrackHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = TaintTrackInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          source_categories: input.source_categories ?? 'all',
          sink_categories: input.sink_categories ?? 'all',
        },
      })

      if (!input.force_refresh) {
        const cached = await lookupCachedResult(cacheManager, cacheKey)
        if (cached) {
          return {
            ok: true,
            data: cached.data,
            warnings: ['Result from cache', formatCacheWarning(cached.metadata)],
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME, cached: true },
          }
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          source_categories: input.source_categories ?? null,
          sink_categories: input.sink_categories ?? null,
        },
        toolVersion: TOOL_VERSION,
      })

      const workerResponse = await callPooledStaticWorker(workerRequest, { database })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const data = workerResponse.data as Record<string, unknown>
      await cacheManager.setCachedResult(cacheKey, data, CACHE_TTL_MS, sample.sha256)

      const artifacts: ArtifactRef[] = []
      try {
        const artifact = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_id, 'taint_tracking', 'taint', { tool: TOOL_NAME, data }
        )
        artifacts.push(artifact)
      } catch { /* best effort */ }

      return {
        ok: true,
        data,
        warnings: workerResponse.warnings,
        artifacts,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
