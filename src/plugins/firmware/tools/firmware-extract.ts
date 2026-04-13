/**
 * firmware.extract — Extract embedded files from firmware images.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  fs, path, os, ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'firmware.extract'

export const firmwareExtractInputSchema = z.object({
  sample_id: z.string().describe('Target firmware sample identifier.'),
  timeout_sec: z.number().int().min(10).max(300).default(60).describe('Extraction timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist extraction manifest as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const firmwareExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    extracted_count: z.number().optional(),
    extracted_files: z.array(z.object({
      path: z.string(),
      size: z.number(),
    })).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const firmwareExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract embedded files from a firmware image using binwalk. Returns a manifest of extracted files.',
  inputSchema: firmwareExtractInputSchema,
  outputSchema: firmwareExtractOutputSchema,
}

export function createFirmwareExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = firmwareExtractInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.BINWALK_PATH, pathCandidates: ['binwalk'], versionArgSets: [['--help']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'binwalk', available: false, error: 'binwalk not installed' } as any, startTime, TOOL_NAME)
      }

      const tmpDir = path.join(os.tmpdir(), `rikune-binwalk-${Date.now()}`)
      await fs.mkdir(tmpDir, { recursive: true })

      try {
        const result = await executeCommand(backend.path, ['-e', '-C', tmpDir, samplePath], input.timeout_sec * 1000)

        // List extracted files
        const extractedFiles: Array<{ path: string; size: number }> = []
        await listExtracted(tmpDir, tmpDir, extractedFiles)

        const artifacts: ArtifactRef[] = []
        let artifact: ArtifactRef | undefined
        if (input.persist_artifact) {
          const manifest = JSON.stringify({ extracted_files: extractedFiles, binwalk_output: result.stdout }, null, 2)
          artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'firmware', 'extract', manifest, { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
          artifacts.push(artifact)
        }

        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            extracted_count: extractedFiles.length,
            extracted_files: extractedFiles.slice(0, 50),
            artifact,
            summary: `Binwalk extracted ${extractedFiles.length} file(s) from firmware image.`,
            recommended_next_tools: ['artifact.read', 'firmware.scan', 'strings.extract', 'yara.scan'],
            next_actions: [
              'Review extracted files for embedded executables or configurations.',
              'Ingest interesting extracted files as new samples with sample.ingest.',
            ],
          },
          artifacts,
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      } finally {
        await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {})
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}

async function listExtracted(rootDir: string, dir: string, results: Array<{ path: string; size: number }>) {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        await listExtracted(rootDir, fullPath, results)
      } else if (entry.isFile()) {
        const stat = await fs.stat(fullPath)
        results.push({ path: path.relative(rootDir, fullPath), size: stat.size })
      }
    }
  } catch {
    // non-fatal
  }
}
