/**
 * Unit tests for runtime-node task-store persistence and recovery.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, jest, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'

const testInbox = path.join(os.tmpdir(), 'rikune-task-store-persist-inbox')
const testOutbox = path.join(os.tmpdir(), 'rikune-task-store-persist-outbox')
process.env.RUNTIME_INBOX = testInbox
process.env.RUNTIME_OUTBOX = testOutbox

const executeTaskMock = jest.fn(async (task: { taskId: string }) => ({
  ok: true,
  taskId: task.taskId,
  logs: ['executor-finished'],
  result: { ok: true, data: { taskId: task.taskId } },
}))

jest.unstable_mockModule('../../../packages/runtime-node/src/executor.js', () => ({
  executeTask: executeTaskMock,
}))

let submitTask: typeof import('../../../packages/runtime-node/src/task-store.js').submitTask
let getTask: typeof import('../../../packages/runtime-node/src/task-store.js').getTask
let flushTaskStorePersistenceForTests: typeof import('../../../packages/runtime-node/src/task-store.js').flushTaskStorePersistenceForTests
let reloadTaskStoreFromDiskForTests: typeof import('../../../packages/runtime-node/src/task-store.js').reloadTaskStoreFromDiskForTests
let resetTaskStoreForTests: typeof import('../../../packages/runtime-node/src/task-store.js').resetTaskStoreForTests
let setTaskExecutorForTests: typeof import('../../../packages/runtime-node/src/task-store.js').setTaskExecutorForTests

const persistedStatePath = path.join(testOutbox, '.runtime-task-store.json')

async function waitForSetImmediate(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve))
}

async function waitForTaskCompletion(taskId: string): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const state = getTask(taskId)
    if (state?.status === 'completed' || state?.status === 'failed' || state?.status === 'cancelled') {
      return
    }
    await waitForSetImmediate()
  }
  throw new Error(`Timed out waiting for task ${taskId} to complete`)
}

beforeAll(async () => {
  ;({
    submitTask,
    getTask,
    flushTaskStorePersistenceForTests,
    reloadTaskStoreFromDiskForTests,
    resetTaskStoreForTests,
    setTaskExecutorForTests,
  } = await import('../../../packages/runtime-node/src/task-store.js'))
})

beforeEach(() => {
  executeTaskMock.mockReset()
  executeTaskMock.mockImplementation(async (task: { taskId: string }) => ({
    ok: true,
    taskId: task.taskId,
    logs: ['executor-finished'],
    result: { ok: true, data: { taskId: task.taskId } },
  }))
  fs.rmSync(testInbox, { recursive: true, force: true })
  fs.rmSync(testOutbox, { recursive: true, force: true })
  fs.mkdirSync(testInbox, { recursive: true })
  fs.mkdirSync(testOutbox, { recursive: true })
  resetTaskStoreForTests({ removePersistence: true })
  setTaskExecutorForTests(executeTaskMock as any)
})

afterEach(() => {
  setTaskExecutorForTests()
  resetTaskStoreForTests({ removePersistence: true })
  fs.rmSync(testInbox, { recursive: true, force: true })
  fs.rmSync(testOutbox, { recursive: true, force: true })
})

describe('runtime-node task-store persistence', () => {
  test('persists completed tasks and restores them from disk', async () => {
    const taskId = `persist-complete-${Date.now()}`

    submitTask({
      taskId,
      sampleId: 'sample-complete',
      tool: 'dynamic.spawn.native',
      args: {},
      timeoutMs: 1000,
    })

    await waitForTaskCompletion(taskId)
    flushTaskStorePersistenceForTests()
    reloadTaskStoreFromDiskForTests()

    const recovered = getTask(taskId)
    expect(fs.existsSync(persistedStatePath)).toBe(true)
    expect(recovered?.status).toBe('completed')
    expect(recovered?.result?.ok).toBe(true)
    expect(recovered?.logs).toContain('executor-finished')
  })

  test('marks in-flight tasks as failed when recovered after restart', async () => {
    const taskId = `persist-running-${Date.now()}`
    executeTaskMock.mockImplementation(() => new Promise(() => {}))

    submitTask({
      taskId,
      sampleId: 'sample-running',
      tool: 'dynamic.spawn.native',
      args: {},
      timeoutMs: 1000,
    })

    await waitForSetImmediate()
    expect(getTask(taskId)?.status).toBe('running')

    flushTaskStorePersistenceForTests()
    reloadTaskStoreFromDiskForTests()

    const recovered = getTask(taskId)
    expect(recovered?.status).toBe('failed')
    expect(recovered?.lastMessage).toContain('did not survive runtime restart')
    expect(recovered?.result?.errors?.[0]).toContain('did not survive runtime restart')
  })
})
