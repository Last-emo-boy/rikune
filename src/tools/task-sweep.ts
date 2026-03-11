/**
 * task.sweep MCP tool
 * Reap stale running tasks and clear old finished records.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js'
import type { JobQueue } from '../job-queue.js'
import type { DatabaseManager } from '../database.js'

const TOOL_NAME = 'task.sweep'

export const taskSweepInputSchema = z.object({
  stale_running_ms: z
    .number()
    .int()
    .min(1000)
    .nullable()
    .optional()
    .describe('Optional stale-running threshold in milliseconds. Omit or null to disable automatic reaping.'),
  clear_finished_older_ms: z
    .number()
    .int()
    .min(60 * 1000)
    .optional()
    .default(24 * 60 * 60 * 1000)
    .describe('Clear completed/failed/cancelled jobs older than this threshold (default: 24 hours)'),
})

export type TaskSweepInput = z.infer<typeof taskSweepInputSchema>

export const taskSweepToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Sweep stale running tasks and clear old finished task records.',
  inputSchema: taskSweepInputSchema,
}

export function createTaskSweepHandler(
  jobQueue: JobQueue,
  database?: DatabaseManager
): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = taskSweepInputSchema.parse(args)
      const reaper = jobQueue as JobQueue & {
        reapStaleRunningJobs?: (maxRuntimeMs: number, nowMs?: number) => string[]
      }
      const reaped =
        typeof input.stale_running_ms === 'number' && typeof reaper.reapStaleRunningJobs === 'function'
          ? reaper.reapStaleRunningJobs(input.stale_running_ms)
          : []
      const reapedAnalyses = database
        ? typeof input.stale_running_ms === 'number'
          ? database.reapStaleAnalyses(input.stale_running_ms)
          : []
        : []
      const cleared = jobQueue.clearOldJobs(input.clear_finished_older_ms)

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: true,
                data: {
                  reaped_running_jobs: reaped,
                  reaped_count: reaped.length,
                  reaped_persisted_analyses: reapedAnalyses.map((item) => item.id),
                  reaped_persisted_analysis_count: reapedAnalyses.length,
                  cleared_finished_count: cleared,
                },
              },
              null,
              2
            ),
          },
        ],
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: false,
                errors: [message],
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      }
    }
  }
}
