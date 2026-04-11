/**
 * speakeasy.emulate — Emulate a PE file using Speakeasy.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  fs, ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolvePythonModuleBackend,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'speakeasy.emulate'

export const speakeasyEmulateInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(300).default(60).describe('Emulation timeout in seconds.'),
  max_api_count: z.number().int().min(100).max(50000).default(10000).describe('Max API calls to capture before stopping.'),
  persist_artifact: z.boolean().default(true).describe('Persist emulation report as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const speakeasyEmulateOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    entry_points: z.array(z.any()).optional(),
    api_call_count: z.number().optional(),
    api_calls_preview: z.array(z.any()).optional(),
    file_activity: z.array(z.string()).optional(),
    registry_activity: z.array(z.string()).optional(),
    network_activity: z.array(z.string()).optional(),
    dropped_files: z.array(z.string()).optional(),
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

export const speakeasyEmulateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Emulate a Windows PE file using Mandiant Speakeasy. Captures API calls, file/registry/network activity without native execution.',
  inputSchema: speakeasyEmulateInputSchema,
  outputSchema: speakeasyEmulateOutputSchema,
}

const SPEAKEASY_EMULATE_SCRIPT = `
import json, sys, os
payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
timeout_sec = int(payload.get("timeout_sec", 60))
max_api = int(payload.get("max_api_count", 10000))

import speakeasy
se = speakeasy.Speakeasy()
try:
    module = se.load_module(sample_path)
    se.run_module(module, timeout=timeout_sec)
except Exception as e:
    pass  # speakeasy raises on timeout or unsupported ops; we still get partial results

report = se.get_report()
entry_points = report.get("entry_points", [])
all_apis = []
file_activity = set()
registry_activity = set()
network_activity = set()
dropped_files = set()

for ep in entry_points:
    for api_call in ep.get("apis_called", [])[:max_api]:
        all_apis.append({
            "api_name": api_call.get("api_name", ""),
            "module": api_call.get("module", ""),
            "args": [str(a)[:200] for a in api_call.get("args", [])[:8]],
            "ret_val": str(api_call.get("ret_val", ""))[:100],
        })
        api_name = api_call.get("api_name", "").lower()
        args_str = " ".join(str(a) for a in api_call.get("args", []))
        if any(k in api_name for k in ("createfile", "writefile", "deletefile", "copyfile", "movefile")):
            file_activity.add(args_str[:300])
        if any(k in api_name for k in ("regopen", "regset", "regcreate", "regdelete", "regquery")):
            registry_activity.add(args_str[:300])
        if any(k in api_name for k in ("connect", "send", "recv", "socket", "inet", "gethost", "urldownload", "winhttp", "internetopen")):
            network_activity.add(args_str[:300])

print(json.dumps({
    "entry_points_count": len(entry_points),
    "entry_points_summary": [{"ep_type": ep.get("ep_type",""), "api_count": len(ep.get("apis_called",[]))} for ep in entry_points][:20],
    "api_call_count": len(all_apis),
    "api_calls_preview": all_apis[:50],
    "file_activity": sorted(file_activity)[:50],
    "registry_activity": sorted(registry_activity)[:50],
    "network_activity": sorted(network_activity)[:50],
    "dropped_files": sorted(dropped_files)[:50],
}, ensure_ascii=False))
`.trim()

export function createSpeakeasyEmulateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = speakeasyEmulateInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.SPEAKEASY_PYTHON, moduleNames: ['speakeasy'], distributionNames: ['speakeasy-emulator'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'speakeasy', available: false, error: 'speakeasy-emulator not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(
        backend.path,
        SPEAKEASY_EMULATE_SCRIPT,
        { sample_path: samplePath, timeout_sec: input.timeout_sec, max_api_count: input.max_api_count },
        (input.timeout_sec + 30) * 1000,
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'speakeasy', 'emulate', JSON.stringify(result.parsed, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      const apiCount = result.parsed?.api_call_count || 0
      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          entry_points: result.parsed?.entry_points_summary || [],
          api_call_count: apiCount,
          api_calls_preview: (result.parsed?.api_calls_preview || []).slice(0, 25),
          file_activity: result.parsed?.file_activity || [],
          registry_activity: result.parsed?.registry_activity || [],
          network_activity: result.parsed?.network_activity || [],
          dropped_files: result.parsed?.dropped_files || [],
          artifact,
          summary: `Speakeasy emulated ${input.sample_id}: ${apiCount} API calls captured across ${result.parsed?.entry_points_count || 0} entry points.`,
          recommended_next_tools: ['artifact.read', 'c2.extract', 'malware.config.extract', 'report.summarize'],
          next_actions: [
            'Review API trace for suspicious behavior patterns.',
            'Use c2.extract or malware.config.extract for deeper analysis.',
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
