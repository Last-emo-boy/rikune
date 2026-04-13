/**
 * apk.disassemble — Disassemble APK to Smali bytecode via apktool.
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

const TOOL_NAME = 'apk.disassemble'

export const apkDisassembleInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the APK file.'),
  class_filter: z.string().optional().describe('Regex filter to limit Smali output to matching class paths (e.g. "com/example").'),
  max_files: z.number().int().min(1).max(200).default(50).describe('Max Smali files to include in result.'),
  timeout_sec: z.number().int().min(10).max(120).default(60).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist disassembly listing as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const apkDisassembleOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    total_classes: z.number().optional(),
    returned_files: z.number().optional(),
    smali_files: z.array(z.object({
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

export const apkDisassembleToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Disassemble an APK file into Smali bytecode via apktool. Lists Smali class files and provides previews.',
  inputSchema: apkDisassembleInputSchema,
  outputSchema: apkDisassembleOutputSchema,
}

function collectSmaliFiles(dir: string, base: string, filter?: RegExp): Array<{ rel: string; abs: string; size: number }> {
  const results: Array<{ rel: string; abs: string; size: number }> = []
  if (!nodeFs.existsSync(dir)) return results
  const entries = nodeFs.readdirSync(dir, { withFileTypes: true })
  for (const entry of entries) {
    const abs = path.join(dir, entry.name)
    const rel = path.join(base, entry.name)
    if (entry.isDirectory()) {
      results.push(...collectSmaliFiles(abs, rel, filter))
    } else if (entry.name.endsWith('.smali')) {
      if (filter && !filter.test(rel)) continue
      const stat = nodeFs.statSync(abs)
      results.push({ rel, abs, size: stat.size })
    }
  }
  return results
}

export function createApkDisassembleHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const tmpDir = path.join(os.tmpdir(), `apk-disasm-${Date.now()}`)
    try {
      const input = apkDisassembleInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.APKTOOL_PATH, pathCandidates: ['apktool'], versionArgSets: [['--version'], ['-version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'apktool', available: false, error: 'apktool not installed' } as any, startTime, TOOL_NAME)
      }

      nodeFs.mkdirSync(tmpDir, { recursive: true })
      await executeCommand(
        backend.path,
        ['d', '-f', '-o', tmpDir, samplePath],
        input.timeout_sec * 1000,
      )

      const smaliDir = path.join(tmpDir, 'smali')
      const filter = input.class_filter ? new RegExp(input.class_filter, 'i') : undefined
      const allFiles = collectSmaliFiles(smaliDir, '', filter)
      allFiles.sort((a, b) => b.size - a.size)

      const smaliFiles = allFiles.slice(0, input.max_files).map(f => {
        let preview = ''
        try { preview = nodeFs.readFileSync(f.abs, 'utf-8').slice(0, 512) } catch {}
        return { path: f.rel.replace(/\\/g, '/'), size_bytes: f.size, preview }
      })

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        const listing = allFiles.map(f => `${f.rel.replace(/\\/g, '/')} (${f.size}B)`).join('\n')
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'apk', 'smali-listing', listing, { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          total_classes: allFiles.length,
          returned_files: smaliFiles.length,
          smali_files: smaliFiles,
          artifact,
          summary: `Disassembled APK: ${allFiles.length} Smali classes found${filter ? ` (filtered)` : ''}.`,
          recommended_next_tools: ['apk.manifest.parse', 'apk.resources.decode', 'string.extract'],
          next_actions: [
            'Inspect Smali for obfuscated methods or crypto usage.',
            'Parse AndroidManifest.xml for permissions and components.',
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
