/**
 * obfuscation.detect tool implementation
 * Detect obfuscation techniques: CFF, opaque predicates, string encryption, etc.
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

const TOOL_NAME = 'obfuscation.detect'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const ObfuscationDetectInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache lookup'),
})

export type ObfuscationDetectInput = z.infer<typeof ObfuscationDetectInputSchema>

export const ObfuscationDetectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      obfuscation_score: z.number(),
      obfuscation_level: z.enum(['none', 'light', 'moderate', 'heavy']),
      techniques: z.array(
        z.object({
          name: z.string(),
          confidence: z.number(),
          description: z.string(),
          indicators: z.record(z.any()),
        })
      ),
      dotnet_specific: z.array(z.any()),
      recommended_next_tools: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const obfuscationDetectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Detect obfuscation techniques applied to a binary: control flow flattening, opaque predicates, ' +
    'string encryption, import obfuscation (API hashing), junk code insertion, anti-disassembly tricks, ' +
    'and .NET-specific obfuscation (name mangling, ConfuserEx/.NET Reactor markers). ' +
    'Returns a scored assessment with per-technique confidence and remediation guidance.',
  inputSchema: ObfuscationDetectInputSchema,
  outputSchema: ObfuscationDetectOutputSchema,
}

export function createObfuscationDetectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = ObfuscationDetectInputSchema.parse(args)
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
        args: {},
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
        args: {},
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
          workspaceManager, database, input.sample_id, 'obfuscation_detection', 'obfuscation', { tool: TOOL_NAME, data }
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
