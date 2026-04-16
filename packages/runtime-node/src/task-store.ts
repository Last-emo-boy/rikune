/**
 * In-memory task store for asynchronous runtime execution.
 */

import type { ExecuteTask, ExecuteResult } from './executor.js'
import { executeTask } from './executor.js'
import { logger } from './logger.js'
import { killTaskProcesses, cleanupTaskOutbox } from './process-registry.js'
import { config } from './config.js'

export type TaskStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'

export interface TaskState {
  taskId: string
  status: TaskStatus
  result?: ExecuteResult
  logs: string[]
  submittedAt: number
  startedAt?: number
  completedAt?: number
  cancelled: boolean
  progressPercent?: number
  lastMessage?: string
}

const tasks = new Map<string, TaskState>()
const TASK_TTL_MS = 30 * 60 * 1000

function isTerminal(status: TaskStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled'
}

function purgeStaleTasks(): void {
  const now = Date.now()
  for (const [taskId, state] of tasks) {
    if (isTerminal(state.status) && state.completedAt && now - state.completedAt > TASK_TTL_MS) {
      tasks.delete(taskId)
      cleanupTaskOutbox(taskId, config.runtime.outbox)
      logger.debug({ taskId }, 'Purged stale task')
    }
  }
}

export function submitTask(task: ExecuteTask): { taskId: string; status: TaskStatus } {
  purgeStaleTasks()
  const state: TaskState = {
    taskId: task.taskId,
    status: 'queued',
    logs: [],
    submittedAt: Date.now(),
    cancelled: false,
  }
  tasks.set(task.taskId, state)

  setImmediate(() => {
    runTask(task, state).catch((err) => {
      logger.error({ err, taskId: task.taskId }, 'Unhandled task execution error')
      if (tasks.has(task.taskId)) {
        const s = tasks.get(task.taskId)!
        s.status = 'failed'
        s.completedAt = Date.now()
        s.result = {
          ok: false,
          taskId: task.taskId,
          errors: [String(err)],
          logs: s.logs,
        }
      }
    })
  })

  return { taskId: task.taskId, status: 'queued' }
}

async function runTask(task: ExecuteTask, state: TaskState): Promise<void> {
  if (state.cancelled) {
    state.status = 'cancelled'
    state.completedAt = Date.now()
    state.result = {
      ok: false,
      taskId: task.taskId,
      errors: ['Task was cancelled before execution started'],
      logs: state.logs,
    }
    return
  }

  state.status = 'running'
  state.startedAt = Date.now()

  const onLog = (msg: string) => {
    state.logs.push(msg)
  }
  const onProgress = (progress: number, message?: string) => {
    state.progressPercent = Math.max(0, Math.min(1, progress))
    if (message) state.lastMessage = message
  }

  try {
    const result = await executeTask(task, onLog, onProgress)
    if (state.cancelled) {
      state.status = 'cancelled'
    } else {
      state.status = result.ok ? 'completed' : 'failed'
    }
    state.completedAt = Date.now()
    state.result = result
    if (result.logs && result.logs.length > 0) {
      for (const line of result.logs) {
        if (!state.logs.includes(line)) {
          state.logs.push(line)
        }
      }
    }
  } catch (err) {
    state.status = 'failed'
    state.completedAt = Date.now()
    state.result = {
      ok: false,
      taskId: task.taskId,
      errors: [String(err)],
      logs: state.logs,
    }
  }
}

export function getTask(taskId: string): TaskState | undefined {
  return tasks.get(taskId)
}

export function cancelTask(taskId: string): { ok: boolean; wasRunning: boolean } {
  const state = tasks.get(taskId)
  if (!state) {
    return { ok: false, wasRunning: false }
  }
  state.cancelled = true
  if (state.status === 'queued') {
    state.status = 'cancelled'
    state.completedAt = Date.now()
    state.result = {
      ok: false,
      taskId,
      errors: ['Task was cancelled'],
      logs: state.logs,
    }
    return { ok: true, wasRunning: false }
  }
  if (state.status === 'running') {
    killTaskProcesses(taskId)
    state.status = 'cancelled'
    state.completedAt = Date.now()
    state.result = {
      ok: false,
      taskId,
      errors: ['Task was cancelled during execution'],
      logs: state.logs,
    }
    return { ok: true, wasRunning: true }
  }
  return { ok: true, wasRunning: false }
}

export function getLogs(taskId: string, offset = 0, limit = 1000): string[] {
  const state = tasks.get(taskId)
  if (!state) return []
  return state.logs.slice(offset, offset + limit)
}

export function listTasks(): TaskState[] {
  return Array.from(tasks.values())
}
