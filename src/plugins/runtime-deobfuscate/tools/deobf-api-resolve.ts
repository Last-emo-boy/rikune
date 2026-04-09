/**
 * deobf.api_resolve �?Capture dynamically resolved APIs via Frida hooks.
 *
 * Hooks GetProcAddress, LdrGetProcedureAddress, LoadLibrary* to capture
 * all dynamically resolved API names and addresses. Builds an IAT map
 * for post-unpack PE reconstruction.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePackagePath } from '../../../runtime-paths.js'
import {
  resolveSampleFile,
  runPythonJson,
  persistBackendArtifact,
  buildMetrics,
  buildDynamicSetupRequired,
  resolveAnalysisBackends,
  type SharedBackendDependencies,
} from '../../../tools/docker/docker-shared.js'

const TOOL_NAME = 'deobf.api_resolve'

export const deobfApiResolveInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout: z.number().int().min(5).max(120).default(60),
  persist_artifact: z.boolean().default(true),
  session_tag: z.string().optional(),
})

export const deobfApiResolveToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Capture dynamically resolved APIs: hooks GetProcAddress, LdrGetProcedureAddress, ' +
    'and LoadLibrary* via Frida. Builds a complete IAT map showing which DLLs are loaded ' +
    'and which APIs are resolved at runtime. Essential for understanding obfuscated import tables. ' +
    'Output can be fed into deep.unpack.pe_reconstruct for IAT fixing.',
  inputSchema: deobfApiResolveInputSchema,
}

export function createDeobfApiResolveHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = deobfApiResolveInputSchema.parse(args)

    try {
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()

      if (!backends.frida_cli?.available) {
        return buildDynamicSetupRequired(
          backends.frida_cli || { available: false, source: null, path: null, version: null, checked_candidates: [], error: 'Frida not available' },
          startTime, TOOL_NAME,
        )
      }

      const pythonPath = process.platform === 'win32' ? 'python' : 'python3'
      const workerScript = `
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location("worker", "${resolvePackagePath('src', 'plugins', 'runtime-deobfuscate', 'workers', 'deobfuscate_worker.py').replace(/\\/g, '/')}")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()
`.trim()

      const runPython = dependencies?.runPythonJson || runPythonJson
      const result = await runPython(pythonPath, workerScript, {
        command: 'api_resolve',
        sample_path: samplePath,
        timeout: input.timeout,
      }, (input.timeout + 10) * 1000)

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      if (workerData.ok && workerData.data && input.persist_artifact) {
        try {
          const artifact = await persistBackendArtifact(
            workspaceManager, database, input.sample_id,
            'deobfuscate', 'api_resolve',
            JSON.stringify(workerData.data, null, 2),
            { extension: 'json', mime: 'application/json', sessionTag: input.session_tag },
          )
          artifacts.push(artifact)
        } catch { /* best effort */ }
      }

      return {
        ok: workerData.ok,
        data: {
          ...workerData.data,
          recommended_next_tools: ['deep.unpack.pe_reconstruct', 'deobf.strings', 'deobf.cfg_trace'],
        },
        errors: workerData.errors?.length ? workerData.errors : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [(error as Error).message], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
