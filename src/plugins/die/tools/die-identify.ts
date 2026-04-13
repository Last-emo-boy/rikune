/**
 * die.identify — Quick DIE identification (compact output).
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  buildMetrics, resolveSampleFile, resolveAnalysisBackends,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'die.identify'

export const dieIdentifyInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  timeout_sec: z.number().int().min(5).max(60).default(15).describe('DIE timeout.'),
})

export const dieIdentifyOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    identifications: z.array(z.string()).optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const dieIdentifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Quick Detect It Easy identification — returns a compact list of detected signatures without full detail.',
  inputSchema: dieIdentifyInputSchema,
  outputSchema: dieIdentifyOutputSchema,
}

export function createDieIdentifyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = dieIdentifyInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = resolveAnalysisBackends()
      const backend = backends.die
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'die', available: false, error: 'diec not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await executeCommand(backend.path, [samplePath], input.timeout_sec * 1000)

      const lines = result.stdout.trim().split(/\r?\n/).filter(Boolean)

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          identifications: lines,
          summary: `DIE quick ID: ${lines.length > 0 ? lines.join('; ') : 'no detections'}.`,
          recommended_next_tools: ['die.scan', 'packer.detect', 'pe.structure.analyze'],
          next_actions: [
            'Use die.scan for full detailed results with JSON output.',
          ],
        },
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
