/**
 * sample.similarity — Compute fuzzy hashes (ssdeep, TLSH) for a sample.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson,
  buildMetrics, resolveSampleFile, resolvePythonModuleBackend,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'sample.similarity'

export const sampleSimilarityInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  compare_to: z.string().optional().describe('Optional second sample_id to compare against.'),
})

export const sampleSimilarityOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    ssdeep_hash: z.string().optional(),
    tlsh_hash: z.string().optional(),
    comparison: z.object({
      compare_to: z.string(),
      ssdeep_score: z.number().optional(),
      tlsh_distance: z.number().optional(),
    }).optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const sampleSimilarityToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compute ssdeep and TLSH fuzzy hashes for a sample. Optionally compare against a second sample.',
  inputSchema: sampleSimilarityInputSchema,
  outputSchema: sampleSimilarityOutputSchema,
}

const SIMILARITY_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
path1 = payload["sample_path"]
path2 = payload.get("compare_path")

with open(path1, "rb") as f:
    data1 = f.read()

result = {}
warnings = []

# ssdeep via ppdeep
try:
    import ppdeep
    result["ssdeep_hash"] = ppdeep.hash(data1)
except ImportError:
    warnings.append("ppdeep not installed; ssdeep hash unavailable")

# TLSH
try:
    import tlsh
    h = tlsh.hash(data1)
    result["tlsh_hash"] = h if h else "TNULL"
except ImportError:
    warnings.append("py-tlsh not installed; TLSH hash unavailable")
except Exception as e:
    result["tlsh_hash"] = f"error: {e}"

comparison = None
if path2:
    with open(path2, "rb") as f:
        data2 = f.read()
    comparison = {"compare_to": payload.get("compare_id", path2)}
    try:
        import ppdeep
        h2 = ppdeep.hash(data2)
        comparison["ssdeep_score"] = ppdeep.compare(result.get("ssdeep_hash", ""), h2)
    except (ImportError, Exception):
        pass
    try:
        import tlsh
        h1 = tlsh.hash(data1)
        h2t = tlsh.hash(data2)
        if h1 and h2t:
            comparison["tlsh_distance"] = tlsh.diff(h1, h2t)
    except (ImportError, Exception):
        pass

result["comparison"] = comparison
result["warnings"] = warnings
print(json.dumps(result, ensure_ascii=False))
`.trim()

export function createSampleSimilarityHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = sampleSimilarityInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.SIMILARITY_PYTHON, moduleNames: ['ppdeep'], distributionNames: ['ppdeep'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'similarity', available: false, error: 'ppdeep Python module not available' } as any, startTime, TOOL_NAME)
      }

      const payload: Record<string, unknown> = { sample_path: samplePath }
      if (input.compare_to) {
        const comparePath = await resolveSampleFile(workspaceManager, database, input.compare_to)
        payload.compare_path = comparePath
        payload.compare_id = input.compare_to
      }

      const result = await runPythonJson(backend.path, SIMILARITY_SCRIPT, payload, 30_000)

      const warnings = result.parsed?.warnings || []
      const comparison = result.parsed?.comparison || undefined

      let summaryParts = [`ssdeep: ${result.parsed?.ssdeep_hash || 'N/A'}`, `TLSH: ${result.parsed?.tlsh_hash || 'N/A'}`]
      if (comparison?.ssdeep_score !== undefined) summaryParts.push(`ssdeep match: ${comparison.ssdeep_score}%`)
      if (comparison?.tlsh_distance !== undefined) summaryParts.push(`TLSH distance: ${comparison.tlsh_distance}`)

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          ssdeep_hash: result.parsed?.ssdeep_hash,
          tlsh_hash: result.parsed?.tlsh_hash,
          comparison,
          summary: summaryParts.join(', '),
          recommended_next_tools: ['sample.cluster.fuzzy', 'malware.classify', 'pe.fingerprint'],
          next_actions: [
            'Use sample.cluster.fuzzy for batch similarity across multiple samples.',
            'Compare TLSH distance < 100 to identify likely variants.',
          ],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
