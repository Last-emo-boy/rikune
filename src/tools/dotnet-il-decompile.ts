/**
 * dotnet.il.decompile — .NET IL-level decompilation to C#.
 *
 * Integrates ILSpy CLI or Python ilspy backend to decompile
 * .NET assemblies from IL to readable C# source code.
 * Falls back to dnfile-based IL disassembly if ILSpy is unavailable.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from './static-worker-client.js'

const TOOL_NAME = 'dotnet.il.decompile'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const DotNetIlDecompileInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  target_type: z.string().optional()
    .describe('Specific type/class to decompile (e.g., "MyNamespace.MyClass")'),
  target_method: z.string().optional()
    .describe('Specific method to decompile (e.g., "Main" or "DecryptString")'),
  output_format: z.enum(['csharp', 'il', 'both']).default('csharp')
    .describe('Output format: decompiled C#, raw IL, or both'),
  include_metadata: z.boolean().default(true)
    .describe('Include assembly metadata, references, and attributes'),
  max_methods: z.number().int().min(1).max(500).default(50)
    .describe('Maximum methods to decompile (for full assembly mode)'),
  force_refresh: z.boolean().default(false),
})
export type DotNetIlDecompileInput = z.infer<typeof DotNetIlDecompileInputSchema>

export const dotNetIlDecompileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decompile .NET assemblies from IL to C# source code using ILSpy or dnfile backend. ' +
    'Can target specific types/methods or decompile the full assembly. Outputs readable C# ' +
    'with optional raw IL annotations. Falls back to IL disassembly if ILSpy is unavailable.',
  inputSchema: DotNetIlDecompileInputSchema,
}

export function createDotNetIlDecompileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = DotNetIlDecompileInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      // Cache check
      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          target_type: input.target_type || null,
          target_method: input.target_method || null,
          output_format: input.output_format,
          max_methods: input.max_methods,
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

      // Call Python worker for decompilation
      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          target_type: input.target_type || null,
          target_method: input.target_method || null,
          output_format: input.output_format,
          include_metadata: input.include_metadata,
          max_methods: input.max_methods,
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

      // Cache result
      await cacheManager.setCachedResult(cacheKey, data, CACHE_TTL_MS, sample.sha256)

      // Persist artifact
      const artifacts: ArtifactRef[] = []
      try {
        const artifactType = input.output_format === 'il' ? 'il_disassembly' : 'csharp_decompilation'
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_id,
          artifactType, 'dotnet_decompile', { tool: TOOL_NAME, data },
        ))
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
