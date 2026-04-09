/**
 * deep.unpack.dump_scan �?Scan memory dumps for embedded PE images.
 *
 * Scans arbitrary binary data for MZ/PE signatures, validates headers,
 * extracts and saves each PE image found, computes entropy.
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

const TOOL_NAME = 'deep.unpack.dump_scan'

export const dumpScanInputSchema = z.object({
  sample_id: z.string().describe('Sample ID of the memory dump to scan'),
  timeout: z.number().int().min(5).max(120).default(30),
  persist_artifact: z.boolean().default(true),
  session_tag: z.string().optional(),
})

export const dumpScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    pe_count: z.number(),
    images: z.array(z.any()),
    total_size: z.number(),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.any().optional(),
})

export const dumpScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Scan a memory dump file for embedded PE images. Validates MZ/PE signatures, ' +
    'extracts each PE image, computes per-section entropy, and identifies PE type (PE32/PE32+). ' +
    'Useful for finding unpacked payloads in memory dumps from emulation or process hollowing detection.',
  inputSchema: dumpScanInputSchema,
  outputSchema: dumpScanOutputSchema,
}

export function createDumpScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = dumpScanInputSchema.parse(args)

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
        { command: 'dump_scan', dump_path: samplePath },
        input.timeout * 1000,
      )

      const workerData = result.parsed
      const artifacts: ArtifactRef[] = []

      // Persist extracted PEs
      if (workerData.ok && workerData.data?.images && input.persist_artifact) {
        const fs = await import('fs/promises')
        for (const img of workerData.data.images) {
          if (img.path) {
            try {
              const content = await fs.readFile(img.path)
              const artifact = await persistBackendArtifact(
                workspaceManager, database, input.sample_id,
                'deep_unpack', `dump_scan_pe${img.index}`,
                content,
                {
                  extension: 'exe',
                  mime: 'application/vnd.microsoft.portable-executable',
                  sessionTag: input.session_tag,
                  metadata: { offset: img.offset, pe_type: img.pe_type },
                },
              )
              artifacts.push(artifact)
            } catch {
              // best effort
            }
          }
        }
      }

      return {
        ok: workerData.ok ?? true,
        data: {
          ...workerData.data,
          recommended_next_tools: (workerData.data?.pe_count ?? 0) > 0
            ? ['unpack.reingest', 'pe.fingerprint', 'deep.unpack.pe_reconstruct']
            : ['deep.unpack.pipeline', 'behavior.capture'],
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
