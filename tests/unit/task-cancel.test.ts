/**
 * Unit tests for task.cancel tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createTaskCancelHandler, taskCancelInputSchema } from '../../src/tools/task-cancel.js'
import type { JobQueue } from '../../src/job-queue.js'

describe('task.cancel tool', () => {
  let mockJobQueue: jest.Mocked<JobQueue>

  beforeEach(() => {
    mockJobQueue = {
      enqueue: jest.fn(),
      getStatus: jest.fn(),
      cancel: jest.fn().mockReturnValue(false),
    } as unknown as jest.Mocked<JobQueue>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = taskCancelInputSchema.safeParse({ job_id: 'job-abc123' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = taskCancelInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = taskCancelInputSchema.safeParse({ job_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent job', async () => {
      const handler = createTaskCancelHandler(mockJobQueue)

      const result = await handler({ job_id: 'nonexistent-job' })

      const parsed = JSON.parse(result.content[0].text)
      expect(parsed.ok).toBe(false)
    })
  })
})
