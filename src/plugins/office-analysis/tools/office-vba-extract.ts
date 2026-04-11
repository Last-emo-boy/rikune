/**
 * office.vba.extract — Extract VBA macro source code from Office documents.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson,
  persistBackendArtifact, buildMetrics, truncateText,
  resolveSampleFile, resolvePythonModuleBackend,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'office.vba.extract'

export const officeVbaExtractInputSchema = z.object({
  sample_id: z.string().describe('Target Office document sample identifier.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('Extraction timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist VBA source as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const officeVbaExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    macro_count: z.number().optional(),
    macros: z.array(z.object({
      filename: z.string(),
      stream_path: z.string(),
      vba_code: z.string(),
    })).optional(),
    suspicious_keywords: z.array(z.string()).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const officeVbaExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract VBA macro source code from Office documents (.doc, .xls, .docm, .xlsm, etc.) using olevba.',
  inputSchema: officeVbaExtractInputSchema,
  outputSchema: officeVbaExtractOutputSchema,
}

const VBA_EXTRACT_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
file_path = payload["sample_path"]

from oletools.olevba import VBA_Parser

vba_parser = VBA_Parser(file_path)
macros = []
suspicious = set()

if vba_parser.detect_vba_macros():
    for filename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
        macros.append({
            "filename": str(vba_filename or filename or ""),
            "stream_path": str(stream_path or ""),
            "vba_code": str(vba_code or "")[:10000],
        })
    for kw_type, keyword, description in vba_parser.analyze_macros():
        if kw_type in ("Suspicious", "IOC", "AutoExec"):
            suspicious.add(f"{kw_type}: {keyword} — {description}")

vba_parser.close()

print(json.dumps({
    "macro_count": len(macros),
    "macros": macros[:20],
    "suspicious_keywords": sorted(suspicious)[:30],
}, ensure_ascii=False))
`.trim()

export function createOfficeVbaExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = officeVbaExtractInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.OLETOOLS_PYTHON, moduleNames: ['oletools'], distributionNames: ['oletools'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'oletools', available: false, error: 'oletools Python module not available' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(backend.path, VBA_EXTRACT_SCRIPT, { sample_path: samplePath }, input.timeout_sec * 1000)

      const macros = result.parsed?.macros || []
      const suspicious = result.parsed?.suspicious_keywords || []

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact && macros.length > 0) {
        const vbaText = macros.map((m: any) => `' ===== ${m.filename} (${m.stream_path}) =====\n${m.vba_code}`).join('\n\n')
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'office', 'vba_extract', vbaText, { extension: 'vba', mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          macro_count: macros.length,
          macros: macros.slice(0, 5).map((m: any) => ({ ...m, vba_code: truncateText(m.vba_code, 2000) })),
          suspicious_keywords: suspicious,
          artifact,
          summary: `Extracted ${macros.length} VBA macro(s), ${suspicious.length} suspicious keyword(s).`,
          recommended_next_tools: ['artifact.read', 'office.macro.detect', 'strings.extract', 'yara.scan'],
          next_actions: [
            'Use artifact.read for full untruncated macro source.',
            'Use office.macro.detect for maliciousness assessment.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
