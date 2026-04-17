/**
 * deep.unpack.pipeline �?Multi-strategy deep unpacking pipeline.
 *
 * Runs packed binaries through multiple unpacking strategies (UPX �?Speakeasy �?Qiling �?memory carve),
 * supports unlimited multi-layer unpacking, and produces reconstructed PE binaries.
 * Docker-priority: best results in Docker container with all backends available.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePackagePath } from '../../../runtime-paths.js'
import {
import { getPythonCommand } from '../../../utils/shared-helpers.js'
  resolveSampleFile,
  runPythonJson,
  persistBackendArtifact,
  buildMetrics,
  buildDynamicSetupRequired,
  resolveAnalysisBackends,
  type SharedBackendDependencies,
} from '../../docker-shared.js'

const TOOL_NAME = 'deep.unpack.pipeline'

export const deepUnpackPipelineInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_layers: z.number().int().min(1).max(10).default(5)
    .describe('Maximum unpack iterations �?supports up to 10 layers for deeply nested packers'),
  strategies: z.array(z.enum(['upx', 'speakeasy', 'qiling', 'memory_carve']))
    .default(['upx', 'speakeasy', 'qiling', 'memory_carve'])
    .describe('Ordered list of unpacking strategies to try per layer'),
  timeout: z.number().int().min(10).max(600).default(120)
    .describe('Per-strategy timeout in seconds'),
  persist_artifact: z.boolean().default(true)
    .describe('Persist unpacked binary as artifact'),
  session_tag: z.string().optional()
    .describe('Optional session tag for artifact grouping'),
})

export const deepUnpackPipelineOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    total_layers: z.number(),
    successful_layers: z.number(),
    layers: z.array(z.any()),
    final_sample_id: z.string().nullable(),
    final_sha256: z.string().nullable(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.any().optional(),
})

export const deepUnpackPipelineToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Deep unpacking pipeline for heavily packed/obfuscated binaries. ' +
    'Tries multiple strategies in order (UPX �?Speakeasy emulation �?Qiling full emulation �?memory carve), ' +
    'supports up to 10 unpacking layers, auto-detects when unpacking is complete via entropy analysis. ' +
    'Best results in Docker environment with all backends available. ' +
    'Use when standard unpack.auto fails on custom/layered packers.',
  inputSchema: deepUnpackPipelineInputSchema,
  outputSchema: deepUnpackPipelineOutputSchema,
}

export function createDeepUnpackPipelineHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = deepUnpackPipelineInputSchema.parse(args)

    try {
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)

      // Check that at least one backend is available
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const hasDynamic = backends.qiling?.available || backends.wine?.available
      if (!hasDynamic && !backends.upx?.available) {
        return buildDynamicSetupRequired(
          backends.qiling || backends.wine || { available: false, source: null, path: null, version: null, checked_candidates: [], error: 'No unpacking backends available' },
          startTime, TOOL_NAME,
        )
      }

      // Resolve Python path for worker
      const pythonPath = backends.qiling?.path
        ? backends.qiling.path  // Qiling venv has pefile
        : getPythonCommand()

      const workerScript = `
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location("worker", "${resolvePackagePath('src', 'plugins', 'deep-unpack', 'workers', 'deep_unpack_worker.py').replace(/\\/g, '/')}")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()
`.trim()

      const runPython = dependencies?.runPythonJson || runPythonJson
      const result = await runPython(
        pythonPath,
        workerScript,
        {
          command: 'deep_unpack',
          sample_path: samplePath,
          max_layers: input.max_layers,
          strategies: input.strategies,
          timeout: input.timeout,
        },
        input.timeout * 1000 * (input.max_layers + 1),
      )

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      // Persist final unpacked binary as artifact
      if (workerData.ok && workerData.data?.final_path && input.persist_artifact) {
        try {
          const fs = await import('fs/promises')
          const content = await fs.readFile(workerData.data.final_path)
          const artifact = await persistBackendArtifact(
            workspaceManager, database, input.sample_id,
            'deep_unpack', 'unpacked',
            content,
            {
              extension: 'exe',
              mime: 'application/vnd.microsoft.portable-executable',
              sessionTag: input.session_tag,
              metadata: {
                layers_unpacked: workerData.data.successful_layers,
                final_sha256: workerData.data.final_sha256,
              },
            },
          )
          artifacts.push(artifact)
        } catch {
          // best effort
        }
      }

      return {
        ok: workerData.ok,
        data: {
          ...workerData.data,
          final_sample_id: null, // caller can use unpack.reingest to register
          recommended_next_tools: workerData.ok
            ? ['unpack.reingest', 'pe.fingerprint', 'workflow.analyze.start', 'deep.unpack.pe_reconstruct']
            : ['deep.unpack.pe_reconstruct', 'deobf.strings', 'behavior.capture'],
          next_actions: workerData.ok
            ? [
                'Use unpack.reingest to register the unpacked binary as a child sample.',
                'Run pe.fingerprint on the unpacked binary for clean static analysis.',
                'If imports are broken, use deep.unpack.pe_reconstruct to fix IAT.',
              ]
            : [
                'Try behavior.capture for behavioral analysis without unpacking.',
                'Try deobf.strings for runtime string decryption.',
                'Increase timeout or try different strategy order.',
              ],
        },
        errors: workerData.errors?.length ? workerData.errors : undefined,
        warnings: workerData.warnings?.length ? workerData.warnings : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    }
  }
}
