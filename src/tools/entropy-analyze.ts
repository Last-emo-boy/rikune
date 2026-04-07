/**
 * entropy.analyze tool implementation
 * Section-level entropy analysis for packing/crypto detection.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from './static-worker-client.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'

const TOOL_NAME = 'entropy.analyze'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const EntropyAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  block_size: z
    .number()
    .int()
    .min(64)
    .max(4096)
    .default(256)
    .describe('Block size in bytes for entropy calculation'),
  high_entropy_threshold: z
    .number()
    .min(5.0)
    .max(8.0)
    .default(7.2)
    .describe('Threshold for marking high-entropy regions (0-8 scale)'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache lookup'),
})

export type EntropyAnalyzeInput = z.infer<typeof EntropyAnalyzeInputSchema>

export const EntropyAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      file_size: z.number(),
      overall_entropy: z.number(),
      block_size: z.number(),
      block_count: z.number(),
      histogram: z.array(z.number()),
      sections: z.array(
        z.object({
          name: z.string(),
          entropy: z.number(),
          raw_size: z.number(),
          virtual_size: z.number(),
          vsize_ratio: z.number(),
          characteristics: z.string(),
          suspicious: z.boolean(),
        })
      ),
      high_entropy_regions: z.array(
        z.object({
          offset: z.number(),
          end_offset: z.number(),
          length: z.number(),
          avg_entropy: z.number(),
        })
      ),
      classification: z.object({
        packing_likelihood: z.string(),
        crypto_data_likelihood: z.string(),
        is_pe: z.boolean(),
      }),
      recommended_next_tools: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const entropyAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compute byte-level and section-level Shannon entropy for a binary sample. ' +
    'Identifies packed regions, encrypted data, and high-entropy anomalies. ' +
    'Outputs per-section entropy, a block histogram, and packing/crypto likelihood classification.',
  inputSchema: EntropyAnalyzeInputSchema,
  outputSchema: EntropyAnalyzeOutputSchema,
}

export function createEntropyAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = EntropyAnalyzeInputSchema.parse(args)
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
        args: { block_size: input.block_size, high_entropy_threshold: input.high_entropy_threshold },
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
          block_size: input.block_size,
          high_entropy_threshold: input.high_entropy_threshold,
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
          workspaceManager, database, input.sample_id, 'entropy_analysis', 'entropy', { tool: TOOL_NAME, data }
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
