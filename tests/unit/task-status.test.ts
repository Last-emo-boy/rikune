/**
 * Unit tests for task.status tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createTaskStatusHandler, taskStatusInputSchema } from '../../src/tools/task-status.js'
import type { DatabaseManager } from '../../src/database.js'
import type { JobQueue } from '../../src/job-queue.js'

describe('task.status tool', () => {
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockJobQueue: jest.Mocked<JobQueue>

  beforeEach(() => {
    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    mockJobQueue = {
      enqueue: jest.fn(),
      getStatus: jest.fn(),
    } as unknown as jest.Mocked<JobQueue>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = taskStatusInputSchema.safeParse({ job_id: 'job-abc123' })
      expect(result.success).toBe(true)
    })

    test('should accept empty input (all optional)', () => {
      const result = taskStatusInputSchema.safeParse({})
      expect(result.success).toBe(true)
    })

    test('should reject invalid types', () => {
      const result = taskStatusInputSchema.safeParse({ job_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createTaskStatusHandler(mockJobQueue, mockDatabase)

      const result = await handler({ job_id: 'nonexistent-job' })

      const parsed = JSON.parse(result.content[0].text)
      expect(parsed.ok).toBe(false) // returns error for unknown job
    })
  })
})
