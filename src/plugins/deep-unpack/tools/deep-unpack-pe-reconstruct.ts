/**
 * deep.unpack.pe_reconstruct �?Rebuild PE from memory dump.
 *
 * Fixes section alignment, rebuilds headers, reconstructs IAT from API trace,
 * recalculates checksum. Use after emulation-based unpacking to produce a valid PE.
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

const TOOL_NAME = 'deep.unpack.pe_reconstruct'

export const peReconstructInputSchema = z.object({
  sample_id: z.string().describe('Sample ID of the memory dump or unpacked binary'),
  api_trace: z.array(z.object({
    address: z.string(),
    name: z.string(),
    module: z.string().default(''),
  })).optional().describe('API trace from emulation for IAT reconstruction'),
  image_base: z.string().optional().describe('Image base address (hex, e.g. "0x400000")'),
  oep_rva: z.string().optional().describe('Original Entry Point RVA (hex, e.g. "0x1000")'),
  timeout: z.number().int().min(5).max(120).default(30),
  persist_artifact: z.boolean().default(true),
  session_tag: z.string().optional(),
})

export const peReconstructOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    reconstructed_sha256: z.string().optional(),
    size: z.number().optional(),
    fixes_applied: z.array(z.string()).optional(),
    iat_entries: z.array(z.any()).optional(),
    sections: z.array(z.any()).optional(),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.any().optional(),
})

export const peReconstructToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Reconstruct a valid PE from a memory dump or raw unpacked binary. ' +
    'Fixes section alignment, rebuilds PE headers, reconstructs IAT from API call traces, ' +
    'sets entry point and image base, recalculates checksum. ' +
    'Use after deep.unpack.pipeline or emulation-based unpacking.',
  inputSchema: peReconstructInputSchema,
  outputSchema: peReconstructOutputSchema,
}

export function createPeReconstructHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = peReconstructInputSchema.parse(args)

    try {
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const pythonPath = process.platform === 'win32' ? 'python' : 'python3'

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
          command: 'pe_reconstruct',
          dump_path: samplePath,
          api_trace: input.api_trace || [],
          image_base: input.image_base,
          oep_rva: input.oep_rva,
        },
        input.timeout * 1000,
      )

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      if (workerData.ok && workerData.reconstructed_path && input.persist_artifact) {
        try {
          const fs = await import('fs/promises')
          const content = await fs.readFile(workerData.reconstructed_path)
          const artifact = await persistBackendArtifact(
            workspaceManager, database, input.sample_id,
            'deep_unpack', 'pe_reconstructed',
            content,
            {
              extension: 'exe',
              mime: 'application/vnd.microsoft.portable-executable',
              sessionTag: input.session_tag,
              metadata: { fixes: workerData.fixes_applied },
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
          reconstructed_sha256: workerData.sha256,
          size: workerData.size,
          fixes_applied: workerData.fixes_applied,
          iat_entries: workerData.iat_entries,
          sections: workerData.sections,
          recommended_next_tools: ['unpack.reingest', 'pe.fingerprint', 'pe.imports.extract'],
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
