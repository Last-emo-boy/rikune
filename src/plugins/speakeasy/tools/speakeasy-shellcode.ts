/**
 * speakeasy.shellcode — Emulate raw shellcode using Speakeasy.
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
  buildDynamicSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'speakeasy.shellcode'

export const speakeasyShellcodeInputSchema = z.object({
  sample_id: z.string().describe('Sample containing shellcode.'),
  arch: z.enum(['x86', 'x64']).default('x86').describe('Shellcode architecture.'),
  offset: z.number().int().min(0).default(0).describe('Byte offset where shellcode begins.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('Emulation timeout in seconds.'),
  persist_artifact: z.boolean().default(true).describe('Persist emulation report as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const speakeasyShellcodeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    arch: z.string().optional(),
    api_call_count: z.number().optional(),
    api_calls_preview: z.array(z.any()).optional(),
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

export const speakeasyShellcodeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Emulate raw shellcode bytes from a sample using Speakeasy. Specify architecture and optional offset.',
  inputSchema: speakeasyShellcodeInputSchema,
  outputSchema: speakeasyShellcodeOutputSchema,
  runtimeBackendHint: { type: 'inline', handler: 'executeSpeakeasyShellcode' },
}

const SPEAKEASY_SHELLCODE_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
arch = payload.get("arch", "x86")
offset = int(payload.get("offset", 0))
timeout_sec = int(payload.get("timeout_sec", 30))

with open(sample_path, "rb") as f:
    data = f.read()
sc_data = data[offset:]

import speakeasy
se = speakeasy.Speakeasy()
if arch == "x64":
    sc_addr = se.load_shellcode("amd64", sc_data)
else:
    sc_addr = se.load_shellcode("x86", sc_data)

try:
    se.run_shellcode(sc_addr, timeout=timeout_sec)
except Exception:
    pass

report = se.get_report()
all_apis = []
for ep in report.get("entry_points", []):
    for api_call in ep.get("apis_called", [])[:5000]:
        all_apis.append({
            "api_name": api_call.get("api_name", ""),
            "module": api_call.get("module", ""),
            "args": [str(a)[:200] for a in api_call.get("args", [])[:8]],
            "ret_val": str(api_call.get("ret_val", ""))[:100],
        })

print(json.dumps({
    "arch": arch,
    "shellcode_size": len(sc_data),
    "api_call_count": len(all_apis),
    "api_calls_preview": all_apis[:50],
}, ensure_ascii=False))
`.trim()

export function createSpeakeasyShellcodeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = speakeasyShellcodeInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.SPEAKEASY_PYTHON, moduleNames: ['speakeasy'], distributionNames: ['speakeasy-emulator'] })
      if (!backend?.available || !backend?.path) {
        return buildDynamicSetupRequired(backend || { name: 'speakeasy', available: false, error: 'speakeasy-emulator not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(
        backend.path,
        SPEAKEASY_SHELLCODE_SCRIPT,
        { sample_path: samplePath, arch: input.arch, offset: input.offset, timeout_sec: input.timeout_sec },
        (input.timeout_sec + 15) * 1000,
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'speakeasy', 'shellcode', JSON.stringify(result.parsed, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      const apiCount = result.parsed?.api_call_count || 0
      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          arch: input.arch,
          api_call_count: apiCount,
          api_calls_preview: (result.parsed?.api_calls_preview || []).slice(0, 25),
          artifact,
          summary: `Speakeasy emulated ${input.arch} shellcode (${result.parsed?.shellcode_size || 0} bytes): ${apiCount} API calls captured.`,
          recommended_next_tools: ['artifact.read', 'disasm.quick', 'c2.extract'],
          next_actions: [
            'Review API trace for C2 communication or payload staging.',
            'Use disasm.quick for static disassembly of the shellcode.',
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
