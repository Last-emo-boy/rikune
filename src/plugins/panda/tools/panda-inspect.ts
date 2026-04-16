/**
 * PANDA inspect tool �?inspect PANDA/pandare runtime readiness.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from '../../docker-shared.js'
import {
  BackendSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson, buildMetrics, buildDynamicSetupRequired,
  resolveAnalysisBackends,
} from '../../docker-shared.js'

export const pandaInspectInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample identifier for context; PANDA inspect itself does not execute the sample.'),
  timeout_sec: z.number().int().min(1).max(30).default(15).describe('Backend probe timeout in seconds.'),
})

export const pandaInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().nullable().optional(),
      details: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const pandaInspectToolDefinition: ToolDefinition = {
  name: 'panda.inspect',
  description:
    'Inspect PANDA/pandare runtime readiness and record/replay caveats. Use this when you explicitly request PANDA-oriented dynamic analysis support from the MCP server.',
  inputSchema: pandaInspectInputSchema,
  outputSchema: pandaInspectOutputSchema,
  runtimeBackendHint: { type: 'inline', handler: 'executePandaInspect' },
}

const PANDA_INSPECT_SCRIPT = `
import json
import sys
import pandare

print(json.dumps({
    "pandare_version": getattr(pandare, "__version__", None),
    "module": "pandare",
    "note": "PANDA support is installed, but full record/replay workflows still require guest images and trace assets.",
}, ensure_ascii=False))
`.trim()

export function createPandaInspectHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = pandaInspectInputSchema.parse(args)
      if (input.sample_id) {
        ensureSampleExists(database, input.sample_id)
      }
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.panda
      if (!backend.available || !backend.path) {
        return buildDynamicSetupRequired(backend, startTime, pandaInspectToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(backend.path, PANDA_INSPECT_SCRIPT, {}, input.timeout_sec * 1000)

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id || null,
          details: result.parsed,
          summary: 'PANDA bindings are available. Guest images and replay assets are still external prerequisites.',
          recommended_next_tools: ['dynamic.dependencies', 'system.setup.guide', 'tool.help'],
          next_actions: [
            'Prepare guest images and trace assets before expecting full PANDA-backed dynamic workflows.',
          ],
        },
        metrics: buildMetrics(startTime, pandaInspectToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, pandaInspectToolDefinition.name),
      }
    }
  }
}
