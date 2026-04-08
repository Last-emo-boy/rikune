/**
 * java.decompile — Java / APK bytecode decompilation using JADX.
 *
 * Decompiles Java .class files, .jar archives, and Android APK/DEX
 * files to readable Java source code using JADX backend.
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

const TOOL_NAME = 'java.decompile'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const JavaDecompileInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  target_class: z.string().optional()
    .describe('Specific class to decompile (e.g., "com.example.MainActivity")'),
  target_method: z.string().optional()
    .describe('Specific method within target_class to decompile'),
  decompiler: z.enum(['jadx', 'cfr', 'auto']).default('auto')
    .describe('Decompiler backend to use'),
  include_resources: z.boolean().default(false)
    .describe('Include APK resource analysis (AndroidManifest.xml, etc.)'),
  include_smali: z.boolean().default(false)
    .describe('Include Smali (Dalvik assembly) alongside Java source'),
  max_classes: z.number().int().min(1).max(500).default(50)
    .describe('Maximum classes to decompile in full-archive mode'),
  deobfuscate: z.boolean().default(true)
    .describe('Apply JADX deobfuscation passes'),
  force_refresh: z.boolean().default(false),
})
export type JavaDecompileInput = z.infer<typeof JavaDecompileInputSchema>

export const javaDecompileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decompile Java .class files, .jar archives, and Android APK/DEX to readable Java source. ' +
    'Uses JADX (default) or CFR backend. Supports targeted class/method decompilation, ' +
    'APK resource extraction (AndroidManifest.xml), Smali output, and deobfuscation.',
  inputSchema: JavaDecompileInputSchema,
}

export function createJavaDecompileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = JavaDecompileInputSchema.parse(args)
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
          target_class: input.target_class || null,
          target_method: input.target_method || null,
          decompiler: input.decompiler,
          include_resources: input.include_resources,
          include_smali: input.include_smali,
          max_classes: input.max_classes,
          deobfuscate: input.deobfuscate,
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

      // Call Python/JADX worker
      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          target_class: input.target_class || null,
          target_method: input.target_method || null,
          decompiler: input.decompiler,
          include_resources: input.include_resources,
          include_smali: input.include_smali,
          max_classes: input.max_classes,
          deobfuscate: input.deobfuscate,
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
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_id,
          'java_decompilation', 'java_decompile', { tool: TOOL_NAME, data },
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
