/**
 * office.ole.analyze — Analyze OLE2 structure and embedded objects.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolvePythonModuleBackend,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'office.ole.analyze'

export const officeOleAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target Office/OLE document sample identifier.'),
  timeout_sec: z.number().int().min(5).max(60).default(20).describe('Analysis timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist OLE analysis as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const officeOleAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    is_ole2: z.boolean().optional(),
    streams: z.array(z.object({
      name: z.string(),
      size: z.number(),
    })).optional(),
    embedded_objects: z.array(z.object({
      type: z.string(),
      indicator: z.string().optional(),
    })).optional(),
    rtf_objects: z.array(z.any()).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const officeOleAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze OLE2 compound document structure: streams, embedded objects, ActiveX, and RTF objects.',
  inputSchema: officeOleAnalyzeInputSchema,
  outputSchema: officeOleAnalyzeOutputSchema,
}

const OLE_ANALYZE_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
file_path = payload["sample_path"]

result = {"is_ole2": False, "streams": [], "embedded_objects": [], "rtf_objects": []}

# Try OLE2 analysis
try:
    import olefile
    if olefile.isOleFile(file_path):
        result["is_ole2"] = True
        ole = olefile.OleFileIO(file_path)
        for stream in ole.listdir():
            path = "/".join(stream)
            try:
                size = ole.get_size(path)
            except:
                size = 0
            result["streams"].append({"name": path, "size": size})
        ole.close()
except ImportError:
    pass

# Try oleobj for embedded objects
try:
    from oletools import oleobj
    for index, data in enumerate(oleobj.find_ole(file_path)):
        if hasattr(data, 'format_id'):
            result["embedded_objects"].append({
                "type": "OLE_OBJECT",
                "indicator": str(getattr(data, 'filename', ''))[:200],
            })
except Exception:
    pass

# Try rtfobj
try:
    from oletools import rtfobj
    rtf_parser = rtfobj.RtfObjParser(open(file_path, "rb").read())
    rtf_parser.parse()
    for obj in rtf_parser.objects:
        result["rtf_objects"].append({
            "format_id": getattr(obj, "format_id", None),
            "class_name": str(getattr(obj, "class_name", ""))[:100],
            "is_package": getattr(obj, "is_package", False),
            "filename": str(getattr(obj, "filename", ""))[:200],
        })
except Exception:
    pass

print(json.dumps(result, ensure_ascii=False))
`.trim()

export function createOfficeOleAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = officeOleAnalyzeInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.OLETOOLS_PYTHON, moduleNames: ['oletools'], distributionNames: ['oletools'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'oletools', available: false, error: 'oletools Python module not available' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(backend.path, OLE_ANALYZE_SCRIPT, { sample_path: samplePath }, input.timeout_sec * 1000)

      const streams = result.parsed?.streams || []
      const embeds = result.parsed?.embedded_objects || []
      const rtfObjs = result.parsed?.rtf_objects || []

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'office', 'ole_analysis', JSON.stringify(result.parsed, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          is_ole2: result.parsed?.is_ole2 || false,
          streams: streams.slice(0, 30),
          embedded_objects: embeds.slice(0, 20),
          rtf_objects: rtfObjs.slice(0, 10),
          artifact,
          summary: `OLE analysis: ${streams.length} streams, ${embeds.length} embedded objects, ${rtfObjs.length} RTF objects. OLE2: ${result.parsed?.is_ole2 ? 'yes' : 'no'}.`,
          recommended_next_tools: ['artifact.read', 'office.vba.extract', 'strings.extract', 'yara.scan'],
          next_actions: [
            'Check embedded objects for executable payloads.',
            'Extract VBA macros with office.vba.extract.',
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
