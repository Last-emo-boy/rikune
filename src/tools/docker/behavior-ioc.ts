/**
 * behavior.ioc — Extract IOCs from behavioral capture data.
 *
 * Extracts network indicators (IPs, domains, URLs), file indicators (dropped/deleted files),
 * registry modifications, and process creation from behavioral capture results.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../types.js'
import type { WorkspaceManager } from '../../workspace-manager.js'
import type { DatabaseManager } from '../../database.js'
import {
  runPythonJson,
  persistBackendArtifact,
  buildMetrics,
  ensureSampleExists,
  type SharedBackendDependencies,
} from './docker-shared.js'

const TOOL_NAME = 'behavior.ioc'

export const behaviorIocInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for artifact association'),
  behavior_data: z.record(z.any()).describe('Behavioral capture data from behavior.capture tool output'),
  persist_artifact: z.boolean().default(true),
  session_tag: z.string().optional(),
})

export const behaviorIocToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract IOCs (Indicators of Compromise) from behavioral capture data. ' +
    'Parses file operations, registry modifications, network traffic, and process ' +
    'creation events. Produces a structured IOC report with network indicators ' +
    '(IPs, domains, URLs), file indicators (dropped/deleted files), registry keys, ' +
    'and spawned processes. Feed behavior.capture output as behavior_data.',
  inputSchema: behaviorIocInputSchema,
}

export function createBehaviorIocHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = behaviorIocInputSchema.parse(args)

    try {
      ensureSampleExists(database, input.sample_id)
      const pythonPath = process.platform === 'win32' ? 'python' : 'python3'

      const workerScript = `
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location("worker", "${process.cwd().replace(/\\/g, '/')}/workers/behavior_worker.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()
`.trim()

      const runPython = dependencies?.runPythonJson || runPythonJson
      const result = await runPython(pythonPath, workerScript, {
        command: 'ioc_extract',
        behavior_data: input.behavior_data,
      }, 30_000)

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      if (workerData.ok && workerData.data && input.persist_artifact) {
        try {
          const artifact = await persistBackendArtifact(
            workspaceManager, database, input.sample_id,
            'behavior', 'iocs',
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
          recommended_next_tools: ['threat.map', 'ioc.export', 'sigma.generate'],
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
