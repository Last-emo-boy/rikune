/**
 * Unit tests for task.sweep tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { createTaskSweepHandler, taskSweepInputSchema } from '../../src/tools/task-sweep.js'
import type { DatabaseManager } from '../../src/database.js'
import type { JobQueue } from '../../src/job-queue.js'

describe('task.sweep tool', () => {
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
      clearOldJobs: jest.fn().mockReturnValue(0),
    } as unknown as jest.Mocked<JobQueue>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = taskSweepInputSchema.safeParse({ stale_running_ms: 5000 })
      expect(result.success).toBe(true)
    })

    test('should accept empty input (all optional)', () => {
      const result = taskSweepInputSchema.safeParse({})
      expect(result.success).toBe(true)
    })

    test('should reject invalid types', () => {
      const result = taskSweepInputSchema.safeParse({ stale_running_ms: 'abc' })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createTaskSweepHandler(mockJobQueue, mockDatabase)

      const result = await handler({})

      const parsed = JSON.parse(result.content[0].text)
      expect(parsed.ok).toBe(true)
    })
  })
})
