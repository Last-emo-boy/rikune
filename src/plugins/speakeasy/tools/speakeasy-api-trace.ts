/**
 * speakeasy.api_trace — Extract a focused API call trace from Speakeasy emulation.
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

const TOOL_NAME = 'speakeasy.api_trace'

export const speakeasyApiTraceInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  filter_modules: z.array(z.string()).optional().describe('Only include API calls from these modules (e.g. ["kernel32","ntdll"]).'),
  filter_apis: z.array(z.string()).optional().describe('Only include API calls matching these names (substring match).'),
  timeout_sec: z.number().int().min(5).max(300).default(60).describe('Emulation timeout in seconds.'),
  persist_artifact: z.boolean().default(true).describe('Persist trace as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const speakeasyApiTraceOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    total_apis: z.number().optional(),
    filtered_count: z.number().optional(),
    api_trace: z.array(z.any()).optional(),
    unique_apis: z.array(z.string()).optional(),
    module_histogram: z.record(z.number()).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const speakeasyApiTraceToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run Speakeasy emulation and extract a focused API call trace with optional module/API name filtering.',
  inputSchema: speakeasyApiTraceInputSchema,
  outputSchema: speakeasyApiTraceOutputSchema,
}

const SPEAKEASY_TRACE_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
timeout_sec = int(payload.get("timeout_sec", 60))
filter_modules = [m.lower() for m in (payload.get("filter_modules") or [])]
filter_apis = [a.lower() for a in (payload.get("filter_apis") or [])]

import speakeasy
se = speakeasy.Speakeasy()
try:
    module = se.load_module(sample_path)
    se.run_module(module, timeout=timeout_sec)
except Exception:
    pass

report = se.get_report()
all_apis = []
for ep in report.get("entry_points", []):
    for api_call in ep.get("apis_called", []):
        mod = api_call.get("module", "")
        name = api_call.get("api_name", "")
        if filter_modules and mod.lower() not in filter_modules:
            continue
        if filter_apis and not any(f in name.lower() for f in filter_apis):
            continue
        all_apis.append({
            "api_name": name,
            "module": mod,
            "args": [str(a)[:200] for a in api_call.get("args", [])[:8]],
            "ret_val": str(api_call.get("ret_val", ""))[:100],
        })

unique_apis = sorted(set(a["api_name"] for a in all_apis))
mod_hist = {}
for a in all_apis:
    mod_hist[a["module"]] = mod_hist.get(a["module"], 0) + 1

print(json.dumps({
    "total_apis": len(all_apis),
    "api_trace": all_apis[:200],
    "unique_apis": unique_apis[:100],
    "module_histogram": dict(sorted(mod_hist.items(), key=lambda x: -x[1])[:30]),
}, ensure_ascii=False))
`.trim()

export function createSpeakeasyApiTraceHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = speakeasyApiTraceInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.SPEAKEASY_PYTHON, moduleNames: ['speakeasy'], distributionNames: ['speakeasy-emulator'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'speakeasy', available: false, error: 'speakeasy-emulator not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(
        backend.path,
        SPEAKEASY_TRACE_SCRIPT,
        { sample_path: samplePath, timeout_sec: input.timeout_sec, filter_modules: input.filter_modules, filter_apis: input.filter_apis },
        (input.timeout_sec + 30) * 1000,
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'speakeasy', 'api_trace', JSON.stringify(result.parsed, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      const totalApis = result.parsed?.total_apis || 0
      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          total_apis: totalApis,
          filtered_count: totalApis,
          api_trace: (result.parsed?.api_trace || []).slice(0, 50),
          unique_apis: result.parsed?.unique_apis || [],
          module_histogram: result.parsed?.module_histogram || {},
          artifact,
          summary: `Speakeasy API trace: ${totalApis} calls captured, ${(result.parsed?.unique_apis || []).length} unique APIs.`,
          recommended_next_tools: ['artifact.read', 'attack.map', 'malware.classify'],
          next_actions: [
            'Map API behavior to MITRE ATT&CK techniques with attack.map.',
            'Use artifact.read for the full untruncated trace.',
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
