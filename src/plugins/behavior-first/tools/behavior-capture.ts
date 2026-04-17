/**
 * behavior.capture �?Full behavioral capture for opaque binaries.
 *
 * Executes binary in Docker sandbox with comprehensive Frida instrumentation:
 * file I/O, registry, network, process creation, API calls.
 * Generates behavioral profile with risk classification.
 * Use when static analysis and unpacking both fail.
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

const TOOL_NAME = 'behavior.capture'

export const behaviorCaptureInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout: z.number().int().min(5).max(120).default(60)
    .describe('Execution timeout in seconds'),
  persist_artifact: z.boolean().default(true),
  session_tag: z.string().optional(),
})

export const behaviorCaptureToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Full behavioral capture: execute binary in Docker sandbox with comprehensive Frida instrumentation. ' +
    'Monitors file I/O, registry, network (DNS/HTTP/TCP), process creation, code injection, ' +
    'and API calls. Generates behavioral profile with risk classification and tags ' +
    '(persistence, process_injection, anti_debug, etc.). ' +
    'Use when static analysis is impossible due to heavy obfuscation/packing.',
  inputSchema: behaviorCaptureInputSchema,
}

export function createBehaviorCaptureHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = behaviorCaptureInputSchema.parse(args)

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
spec = importlib.util.spec_from_file_location("worker", "${resolvePackagePath('src', 'plugins', 'behavior-first', 'workers', 'behavior_worker.py').replace(/\\/g, '/')}")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()
`.trim()

      const runPython = dependencies?.runPythonJson || runPythonJson
      const result = await runPython(pythonPath, workerScript, {
        command: 'capture',
        sample_path: samplePath,
        timeout: input.timeout,
      }, (input.timeout + 15) * 1000)

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      if (workerData.ok && workerData.data && input.persist_artifact) {
        try {
          const artifact = await persistBackendArtifact(
            workspaceManager, database, input.sample_id,
            'behavior', 'capture',
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
          recommended_next_tools: ['behavior.ioc', 'behavior.network', 'malware.classify', 'threat.map'],
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
