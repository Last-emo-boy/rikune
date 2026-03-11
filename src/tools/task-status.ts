/**
 * task.status MCP tool
 * Query analysis task queue status and optional per-job details.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolHandler, ToolResult } from '../types.js'
import type { JobQueue, JobStatusType } from '../job-queue.js'

const TOOL_NAME = 'task.status'

export const taskStatusInputSchema = z.object({
  job_id: z.string().optional().describe('Optional job id for single-job lookup'),
  status: z
    .enum(['queued', 'running', 'completed', 'failed', 'cancelled'])
    .optional()
    .describe('Optional status filter'),
  include_result: z
    .boolean()
    .optional()
    .default(false)
    .describe('Include completed/failed job result payload for single-job lookup'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(100)
    .describe('Maximum number of jobs to return'),
})

export type TaskStatusInput = z.infer<typeof taskStatusInputSchema>

export const taskStatusToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Get queue/running/completed status for analysis tasks, or inspect a specific job.',
  inputSchema: taskStatusInputSchema,
}

export function createTaskStatusHandler(jobQueue: JobQueue): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = taskStatusInputSchema.parse(args)

      if (input.job_id) {
        const status = jobQueue.getStatus(input.job_id)
        if (!status) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    ok: false,
                    errors: [`Job not found: ${input.job_id}`],
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
                    job: status,
                    result: input.include_result ? jobQueue.getResult(input.job_id) : undefined,
                  },
                },
                null,
                2
              ),
            },
          ],
        }
      }

      const listStatus = (jobQueue as JobQueue & {
        listStatuses?: (status?: JobStatusType) => unknown[]
      }).listStatuses
      const rows = listStatus
        ? listStatus.call(jobQueue, input.status)
        : jobQueue.getJobsByStatus(input.status || 'queued')
      const limitedRows = rows.slice(0, input.limit)

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: true,
                data: {
                  queue_length: jobQueue.getQueueLength(),
                  total_jobs: jobQueue.getTotalJobs(),
                  count: limitedRows.length,
                  jobs: limitedRows,
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

