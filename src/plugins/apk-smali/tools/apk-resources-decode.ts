/**
 * apk.resources.decode — Decode and list APK resources via apktool.
 */

import { z } from 'zod'
import nodeFs from 'node:fs'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  os, path,
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'apk.resources.decode'

export const apkResourcesDecodeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the APK file.'),
  resource_filter: z.string().optional().describe('Regex filter for resource paths (e.g. "values/strings").'),
  max_files: z.number().int().min(1).max(200).default(50).describe('Max resource files to return.'),
  timeout_sec: z.number().int().min(10).max(120).default(60).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist resource listing as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const apkResourcesDecodeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    total_resources: z.number().optional(),
    returned_files: z.number().optional(),
    resource_files: z.array(z.object({
      path: z.string(),
      size_bytes: z.number(),
      preview: z.string().optional(),
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

export const apkResourcesDecodeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Decode and list resources from an APK (layouts, strings, drawables, etc.).',
  inputSchema: apkResourcesDecodeInputSchema,
  outputSchema: apkResourcesDecodeOutputSchema,
}

function collectResourceFiles(dir: string, base: string, filter?: RegExp): Array<{ rel: string; abs: string; size: number }> {
  const results: Array<{ rel: string; abs: string; size: number }> = []
  if (!nodeFs.existsSync(dir)) return results
  const entries = nodeFs.readdirSync(dir, { withFileTypes: true })
  for (const entry of entries) {
    const abs = path.join(dir, entry.name)
    const rel = path.join(base, entry.name)
    if (entry.isDirectory()) {
      results.push(...collectResourceFiles(abs, rel, filter))
    } else {
      if (filter && !filter.test(rel)) continue
      const stat = nodeFs.statSync(abs)
      results.push({ rel, abs, size: stat.size })
    }
  }
  return results
}

export function createApkResourcesDecodeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const tmpDir = path.join(os.tmpdir(), `apk-res-${Date.now()}`)
    try {
      const input = apkResourcesDecodeInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.APKTOOL_PATH, pathCandidates: ['apktool'], versionArgSets: [['--version'], ['-version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'apktool', available: false, error: 'apktool not installed' } as any, startTime, TOOL_NAME)
      }

      nodeFs.mkdirSync(tmpDir, { recursive: true })
      await executeCommand(
        backend.path,
        ['d', '-f', '-s', '-o', tmpDir, samplePath],
        input.timeout_sec * 1000,
      )

      const resDir = path.join(tmpDir, 'res')
      const filter = input.resource_filter ? new RegExp(input.resource_filter, 'i') : undefined
      const allFiles = collectResourceFiles(resDir, '', filter)
      allFiles.sort((a, b) => b.size - a.size)

      const textExtensions = new Set(['.xml', '.json', '.txt', '.html', '.properties'])
      const resourceFiles = allFiles.slice(0, input.max_files).map(f => {
        let preview = ''
        const ext = path.extname(f.abs).toLowerCase()
        if (textExtensions.has(ext) && f.size < 4096) {
          try { preview = nodeFs.readFileSync(f.abs, 'utf-8').slice(0, 512) } catch {}
        }
        return { path: f.rel.replace(/\\/g, '/'), size_bytes: f.size, preview: preview || undefined }
      })

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        const listing = allFiles.map(f => `${f.rel.replace(/\\/g, '/')} (${f.size}B)`).join('\n')
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'apk', 'resources-listing', listing, { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          total_resources: allFiles.length,
          returned_files: resourceFiles.length,
          resource_files: resourceFiles,
          artifact,
          summary: `Decoded ${allFiles.length} resource files${filter ? ' (filtered)' : ''}.`,
          recommended_next_tools: ['apk.manifest.parse', 'apk.disassemble', 'artifact.read'],
          next_actions: [
            'Look for suspicious URL strings in values/strings.xml.',
            'Check layouts for overlay attack indicators.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    } finally {
      try { nodeFs.rmSync(tmpDir, { recursive: true, force: true }) } catch {}
    }
  }
}
