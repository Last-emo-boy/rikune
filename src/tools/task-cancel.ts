/**
 * task.cancel MCP tool
 * Cancel queued/running analysis tasks.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js'
import type { JobQueue } from '../job-queue.js'

const TOOL_NAME = 'task.cancel'

export const taskCancelInputSchema = z.object({
  job_id: z.string().describe('Job id to cancel'),
  reason: z.string().optional().describe('Optional cancellation reason'),
})

export type TaskCancelInput = z.infer<typeof taskCancelInputSchema>

export const taskCancelToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Cancel a queued or running analysis task by job id.',
  inputSchema: taskCancelInputSchema,
}

export function createTaskCancelHandler(jobQueue: JobQueue): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = taskCancelInputSchema.parse(args)
      const cancelled = jobQueue.cancel(input.job_id, input.reason)
      if (!cancelled) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ok: false,
                  errors: [
                    `Unable to cancel job ${input.job_id}. It may not exist or is already finished.`,
                  ],
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: true,
                data: {
                  job_id: input.job_id,
                  cancelled: true,
                  reason: input.reason || null,
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

