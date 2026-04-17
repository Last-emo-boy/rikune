/**
 * deobf.cfg_trace �?CFG recovery from execution trace.
 *
 * Uses Frida Stalker to trace all executed basic blocks,
 * reconstructing the actual control flow graph from dynamic execution.
 * Reveals the real CFG hidden behind control-flow flattening.
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

const TOOL_NAME = 'deobf.cfg_trace'

export const deobfCfgTraceInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout: z.number().int().min(5).max(120).default(60),
  max_blocks: z.number().int().min(100).max(100000).default(10000)
    .describe('Maximum basic blocks to return'),
  persist_artifact: z.boolean().default(true),
  session_tag: z.string().optional(),
})

export const deobfCfgTraceToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'CFG recovery from execution trace: uses Frida Stalker to instrument all branches, ' +
    'records every executed basic block, and reconstructs the actual control flow graph. ' +
    'Defeats control-flow flattening, opaque predicates, and bogus branches by showing ' +
    'only paths that were actually taken during execution.',
  inputSchema: deobfCfgTraceInputSchema,
}

export function createDeobfCfgTraceHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = deobfCfgTraceInputSchema.parse(args)

    try {
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()

      if (!backends.frida_cli?.available) {
        return buildDynamicSetupRequired(
          backends.frida_cli || { available: false, source: null, path: null, version: null, checked_candidates: [], error: 'Frida not available' },
          startTime, TOOL_NAME,
        )
      }

      const pythonPath = getPythonCommand()
      const workerScript = `
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location("worker", "${resolvePackagePath('src', 'plugins', 'runtime-deobfuscate', 'workers', 'deobfuscate_worker.py').replace(/\\/g, '/')}")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()
`.trim()

      const runPython = dependencies?.runPythonJson || runPythonJson
      const result = await runPython(pythonPath, workerScript, {
        command: 'cfg_trace',
        sample_path: samplePath,
        timeout: input.timeout,
        max_blocks: input.max_blocks,
      }, (input.timeout + 10) * 1000)

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      if (workerData.ok && workerData.data && input.persist_artifact) {
        try {
          const artifact = await persistBackendArtifact(
            workspaceManager, database, input.sample_id,
            'deobfuscate', 'cfg_trace',
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
          recommended_next_tools: ['graphviz.render', 'deobf.strings', 'deobf.api_resolve'],
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
