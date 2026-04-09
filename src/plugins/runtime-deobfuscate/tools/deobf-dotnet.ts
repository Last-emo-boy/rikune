/**
 * deobf.dotnet �?.NET deobfuscation via de4dot.
 *
 * Runs de4dot to deobfuscate .NET assemblies: string decryption,
 * control flow deobfuscation, delegate restoration.
 * Supports ConfuserEx, .NET Reactor, Dotfuscator, and others.
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
  type SharedBackendDependencies,
} from '../../../tools/docker/docker-shared.js'

const TOOL_NAME = 'deobf.dotnet'

export const deobfDotnetInputSchema = z.object({
  sample_id: z.string().describe('Sample ID of the .NET assembly'),
  timeout: z.number().int().min(10).max(300).default(120),
  persist_artifact: z.boolean().default(true),
  session_tag: z.string().optional(),
})

export const deobfDotnetToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Deobfuscate .NET assemblies using de4dot. Performs string decryption, ' +
    'control flow deobfuscation, delegate restoration, and anti-tamper removal. ' +
    'Supports ConfuserEx, .NET Reactor, Dotfuscator, Babel, Crypto Obfuscator, ' +
    'DeepSea, Agile, Goliath, MaxtoCode, Eazfuscator, and SmartAssembly. ' +
    'Produces a clean deobfuscated assembly for further static analysis.',
  inputSchema: deobfDotnetInputSchema,
}

export function createDeobfDotnetHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = deobfDotnetInputSchema.parse(args)

    try {
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)

      // de4dot is not in the standard backend resolution; check PATH directly
      const { execSync } = await import('child_process')
      let de4dotAvailable = false
      try {
        execSync('de4dot --help', { stdio: 'ignore', timeout: 5000 })
        de4dotAvailable = true
      } catch {
        // de4dot not in PATH �?acceptable, worker will report the error
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
        command: 'dotnet_deobfuscate',
        sample_path: samplePath,
        timeout: input.timeout,
      }, (input.timeout + 10) * 1000)

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      if (workerData.ok && workerData.data?.deobfuscated_path && input.persist_artifact) {
        try {
          const fs = await import('fs/promises')
          const content = await fs.readFile(workerData.data.deobfuscated_path)
          const artifact = await persistBackendArtifact(
            workspaceManager, database, input.sample_id,
            'deobfuscate', 'dotnet_deobfuscated',
            content,
            {
              extension: 'exe',
              mime: 'application/vnd.microsoft.portable-executable',
              sessionTag: input.session_tag,
              metadata: { detected_obfuscator: workerData.data.detected_obfuscator },
            },
          )
          artifacts.push(artifact)
        } catch { /* best effort */ }
      }

      return {
        ok: workerData.ok,
        data: {
          ...workerData.data,
          recommended_next_tools: workerData.ok
            ? ['unpack.reingest', 'managed.safe_run', 'il.xrefs', 'pe.fingerprint']
            : ['anti.tamper', 'string.decrypt', 'deobf.strings'],
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
