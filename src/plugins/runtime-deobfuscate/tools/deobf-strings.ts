/**
 * deobf.strings �?Runtime string decryption via Frida hooks.
 *
 * Hooks CryptDecrypt, XOR loops, and custom decryption routines,
 * captures decrypted strings at runtime as the binary executes.
 * Docker-priority: requires Frida + Wine for Windows binaries on Linux.
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

const TOOL_NAME = 'deobf.strings'

export const deobfStringsInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout: z.number().int().min(5).max(120).default(60)
    .describe('Execution timeout in seconds'),
  frida_script: z.string().optional()
    .describe('Optional custom Frida script path for string decryption hooks'),
  persist_artifact: z.boolean().default(true),
  session_tag: z.string().optional(),
})

export const deobfStringsToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Runtime string decryption: hooks CryptDecrypt, XOR loops, VirtualAlloc, and custom ' +
    'decryption routines via Frida. Captures decrypted strings as the binary executes. ' +
    'Use when static FLOSS/string extraction returns only encrypted/obfuscated strings. ' +
    'Requires Frida + Wine (Docker recommended).',
  inputSchema: deobfStringsInputSchema,
}

export function createDeobfStringsHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = deobfStringsInputSchema.parse(args)

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
spec = importlib.util.spec_from_file_location("worker", "${resolvePackagePath('workers', 'deobfuscate_worker.py').replace(/\\/g, '/')}")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()
`.trim()

      const runPython = dependencies?.runPythonJson || runPythonJson
      const result = await runPython(
        pythonPath,
        workerScript,
        {
          command: 'strings_runtime',
          sample_path: samplePath,
          timeout: input.timeout,
          frida_script: input.frida_script,
        },
        (input.timeout + 10) * 1000,
      )

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      if (workerData.ok && workerData.data && input.persist_artifact) {
        try {
          const artifact = await persistBackendArtifact(
            workspaceManager, database, input.sample_id,
            'deobfuscate', 'runtime_strings',
            JSON.stringify(workerData.data, null, 2),
            {
              extension: 'json',
              mime: 'application/json',
              sessionTag: input.session_tag,
              metadata: { unique_strings: workerData.data.unique_strings },
            },
          )
          artifacts.push(artifact)
        } catch { /* best effort */ }
      }

      return {
        ok: workerData.ok,
        data: {
          ...workerData.data,
          recommended_next_tools: ['deobf.api_resolve', 'deobf.cfg_trace', 'deep.unpack.pipeline'],
        },
        errors: workerData.errors?.length ? workerData.errors : undefined,
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
