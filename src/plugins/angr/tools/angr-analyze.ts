/**
 * angr analyze tool â€?bounded angr static analysis against a sample.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from '../../docker-shared.js'
import {
  ArtifactRefSchema, BackendSchema, SharedMetricsSchema,
  normalizeError, runPythonJson,
  persistBackendArtifact, buildMetrics, buildDynamicSetupRequired,
  resolveSampleFile, resolveAnalysisBackends,
} from '../../docker-shared.js'

export const angrAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  analysis: z
    .enum(['cfg_fast'])
    .default('cfg_fast')
    .describe('angr analysis mode. cfg_fast is the bounded default.'),
  timeout_sec: z.number().int().min(5).max(300).default(60).describe('angr execution timeout in seconds.'),
  max_functions: z.number().int().min(1).max(200).default(25).describe('Maximum function previews to return.'),
  persist_artifact: z.boolean().default(true).describe('Persist the angr summary JSON as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const angrAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      analysis: z.string().optional(),
      arch: z.string().nullable().optional(),
      entry: z.string().nullable().optional(),
      function_count: z.number().int().nonnegative().optional(),
      functions: z.array(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const angrAnalyzeToolDefinition: ToolDefinition = {
  name: 'angr.analyze',
  description:
    'Run bounded angr static analysis against a sample. Use this when you explicitly want angr-backed CFG recovery or function discovery instead of the default Ghidra flow.',
  inputSchema: angrAnalyzeInputSchema,
  outputSchema: angrAnalyzeOutputSchema,
}

const ANGR_CFGFAST_SCRIPT = `
import json
import sys
import angr

payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
max_functions = int(payload.get("max_functions", 25))

project = angr.Project(sample_path, load_options={"auto_load_libs": False})
cfg = project.analyses.CFGFast(normalize=True)
functions = []
for addr, func in cfg.kb.functions.items():
    name = getattr(func, "name", None)
    if not name:
        continue
    block_count = len(getattr(func, "block_addrs", []) or [])
    functions.append({
        "address": hex(int(addr)),
        "name": name,
        "block_count": block_count,
        "returning": bool(getattr(func, "returning", False)),
        "unresolved_calls": bool(getattr(func, "has_unresolved_calls", False)),
        "unresolved_jumps": bool(getattr(func, "has_unresolved_jumps", False)),
    })

functions.sort(key=lambda item: (-item["block_count"], item["address"]))
graph = cfg.model.graph
print(json.dumps({
    "arch": str(project.arch),
    "entry": hex(int(project.entry)) if project.entry is not None else None,
    "node_count": len(graph.nodes()),
    "edge_count": len(graph.edges()),
    "function_count": len(functions),
    "functions": functions[:max_functions],
}, ensure_ascii=False))
`.trim()

export function createAngrAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = angrAnalyzeInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.angr
      if (!backend.available || !backend.path) {
        return buildDynamicSetupRequired(backend, startTime, angrAnalyzeToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(
        backend.path,
        ANGR_CFGFAST_SCRIPT,
        {
          sample_path: samplePath,
          max_functions: input.max_functions,
        },
        input.timeout_sec * 1000
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'angr',
          input.analysis,
          JSON.stringify(result.parsed, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id,
          analysis: input.analysis,
          arch: typeof result.parsed?.arch === 'string' ? result.parsed.arch : null,
          entry: typeof result.parsed?.entry === 'string' ? result.parsed.entry : null,
          function_count: Number(result.parsed?.function_count || 0),
          functions: Array.isArray(result.parsed?.functions) ? result.parsed.functions : [],
          artifact,
          summary: `angr CFGFast recovered ${Number(result.parsed?.function_count || 0)} function(s) for ${input.sample_id}.`,
          recommended_next_tools: ['artifact.read', 'code.functions.smart_recover', 'workflow.function_index_recover'],
          next_actions: [
            'Compare angr-recovered functions with existing Ghidra or pdata-based results when function coverage is weak.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, angrAnalyzeToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, angrAnalyzeToolDefinition.name),
      }
    }
  }
}
