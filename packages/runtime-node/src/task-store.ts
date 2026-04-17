/**
 * In-memory task store for asynchronous runtime execution.
 */

import fs from 'fs'
import path from 'path'
import type { ExecuteTask, ExecuteResult } from './executor.js'
import { logger } from './logger.js'
import { killTaskProcesses, cleanupTaskOutbox } from './process-registry.js'
import { config } from './config.js'

export type TaskExecutor = (
  task: ExecuteTask,
  onLog?: (msg: string) => void,
  onProgress?: (progress: number, message?: string) => void,
) => Promise<ExecuteResult>

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

export interface TaskEvent {
  id: number
  type: 'submitted' | 'started' | 'progress' | 'log' | 'completed' | 'failed' | 'cancelled'
  taskId: string
  status: TaskStatus
  timestamp: number
  progressPercent?: number
  lastMessage?: string
  log?: string
  result?: ExecuteResult
}

const tasks = new Map<string, TaskState>()
const subscribers = new Set<(event: TaskEvent) => void>()
let nextEventId = 1
let executeTaskForTests: TaskExecutor | undefined
const TASK_TTL_MS = 30 * 60 * 1000
const TASK_STORE_STATE_FILE = '.runtime-task-store.json'
const RECOVERY_FAILURE_MESSAGE = 'Task did not survive runtime restart and was marked failed during recovery.'
export const RUNTIME_TASK_LIFECYCLE = {
  persistenceFileName: TASK_STORE_STATE_FILE,
  persistenceScope: 'runtime-outbox',
  terminalTaskTtlMs: TASK_TTL_MS,
  cleanupBehavior: 'terminal-tasks-purge-outbox-and-state',
  recoveryBehavior: 'queued-and-running-marked-failed-on-restart',
  terminalStatuses: ['completed', 'failed', 'cancelled'] as const,
  persistedStatuses: ['queued', 'running', 'completed', 'failed', 'cancelled'] as const,
  stateFilePath: () => getTaskStorePersistencePath(),
} as const
let persistTimer: NodeJS.Timeout | undefined

interface PersistedTaskStore {
  version: 1
  tasks: TaskState[]
}

function getTaskStorePersistencePath(): string {
  return path.join(config.runtime.outbox, TASK_STORE_STATE_FILE)
}

function ensureRuntimeOutboxExists(): void {
  if (!fs.existsSync(config.runtime.outbox)) {
    fs.mkdirSync(config.runtime.outbox, { recursive: true })
  }
}

function persistTaskStoreNow(): void {
  try {
    ensureRuntimeOutboxExists()
    const persistencePath = getTaskStorePersistencePath()
    const tempPath = `${persistencePath}.tmp`
    const payload: PersistedTaskStore = {
      version: 1,
      tasks: Array.from(tasks.values()).map((state) => ({
        ...state,
        logs: [...state.logs],
      })),
    }
    fs.writeFileSync(tempPath, JSON.stringify(payload, null, 2), 'utf8')
    fs.renameSync(tempPath, persistencePath)
  } catch (err) {
    logger.warn({ err }, 'Failed to persist runtime task store')
  }
}

function schedulePersistTaskStore(): void {
  if (persistTimer) {
    return
  }
  persistTimer = setTimeout(() => {
    persistTimer = undefined
    persistTaskStoreNow()
  }, 25)
  persistTimer.unref?.()
}

function normalizeRecoveredTaskState(state: TaskState): TaskState {
  if (state.status === 'queued' || state.status === 'running') {
    const completedAt = Date.now()
    return {
      ...state,
      status: 'failed',
      completedAt,
      cancelled: false,
      lastMessage: RECOVERY_FAILURE_MESSAGE,
      result: {
        ok: false,
        taskId: state.taskId,
        errors: [RECOVERY_FAILURE_MESSAGE],
        logs: state.logs,
      },
    }
  }
  return state
}

function loadPersistedTaskStore(): void {
  const persistencePath = getTaskStorePersistencePath()
  if (!fs.existsSync(persistencePath)) {
    return
  }

  try {
    const raw = fs.readFileSync(persistencePath, 'utf8')
    if (!raw.trim()) {
      return
    }
    const parsed = JSON.parse(raw) as Partial<PersistedTaskStore>
    if (parsed.version !== 1 || !Array.isArray(parsed.tasks)) {
      logger.warn({ persistencePath }, 'Ignoring runtime task store persistence with unsupported shape')
      return
    }

    tasks.clear()
    for (const entry of parsed.tasks) {
      if (!entry || typeof entry.taskId !== 'string' || typeof entry.status !== 'string' || !Array.isArray(entry.logs)) {
        continue
      }
      const recovered = normalizeRecoveredTaskState(entry)
      tasks.set(recovered.taskId, recovered)
    }
  } catch (err) {
    logger.warn({ err, persistencePath }, 'Failed to load persisted runtime task store')
  }
}

export function setTaskExecutorForTests(executor?: TaskExecutor): void {
  executeTaskForTests = executor
}

function isTerminal(status: TaskStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled'
}

function purgeStaleTasks(): void {
  const now = Date.now()
  let removed = false
  for (const [taskId, state] of tasks) {
    if (isTerminal(state.status) && state.completedAt && now - state.completedAt > TASK_TTL_MS) {
      tasks.delete(taskId)
      cleanupTaskOutbox(taskId, config.runtime.outbox)
      logger.debug({ taskId }, 'Purged stale task')
      removed = true
    }
  }
  if (removed) {
    schedulePersistTaskStore()
  }
}

function emitTaskEvent(
  state: TaskState,
  type: TaskEvent['type'],
  extras: Partial<Omit<TaskEvent, 'id' | 'type' | 'taskId' | 'status' | 'timestamp'>> = {},
): void {
  const event: TaskEvent = {
    id: nextEventId++,
    type,
    taskId: state.taskId,
    status: state.status,
    timestamp: Date.now(),
    progressPercent: state.progressPercent,
    lastMessage: state.lastMessage,
    ...extras,
  }
  for (const subscriber of subscribers) {
    try {
      subscriber(event)
    } catch (err) {
      logger.debug({ err, taskId: state.taskId, type }, 'Task event subscriber failed')
    }
  }
}

export function subscribeTaskEvents(subscriber: (event: TaskEvent) => void): () => void {
  subscribers.add(subscriber)
  return () => {
    subscribers.delete(subscriber)
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
  schedulePersistTaskStore()
  emitTaskEvent(state, 'submitted')

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
        schedulePersistTaskStore()
        emitTaskEvent(s, 'failed', { result: s.result })
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
    schedulePersistTaskStore()
    emitTaskEvent(state, 'cancelled', { result: state.result })
    return
  }

  state.status = 'running'
  state.startedAt = Date.now()
  schedulePersistTaskStore()
  emitTaskEvent(state, 'started')

  const onLog = (msg: string) => {
    state.logs.push(msg)
    schedulePersistTaskStore()
    emitTaskEvent(state, 'log', { log: msg })
  }
  const onProgress = (progress: number, message?: string) => {
    state.progressPercent = Math.max(0, Math.min(1, progress))
    if (message) state.lastMessage = message
    schedulePersistTaskStore()
    emitTaskEvent(state, 'progress')
  }

  try {
    const executor = executeTaskForTests ?? (await import('./executor.js')).executeTask
    const result = await executor(task, onLog, onProgress)
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
    schedulePersistTaskStore()
    emitTaskEvent(state, state.status === 'completed' ? 'completed' : state.status === 'cancelled' ? 'cancelled' : 'failed', { result })
  } catch (err) {
    state.status = 'failed'
    state.completedAt = Date.now()
    state.result = {
      ok: false,
      taskId: task.taskId,
      errors: [String(err)],
      logs: state.logs,
    }
    schedulePersistTaskStore()
    emitTaskEvent(state, 'failed', { result: state.result })
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
    schedulePersistTaskStore()
    emitTaskEvent(state, 'cancelled', { result: state.result })
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
    schedulePersistTaskStore()
    emitTaskEvent(state, 'cancelled', { result: state.result })
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

export function flushTaskStorePersistenceForTests(): void {
  if (persistTimer) {
    clearTimeout(persistTimer)
    persistTimer = undefined
  }
  persistTaskStoreNow()
}

export function reloadTaskStoreFromDiskForTests(): void {
  if (persistTimer) {
    clearTimeout(persistTimer)
    persistTimer = undefined
  }
  loadPersistedTaskStore()
}

export function resetTaskStoreForTests(options: { removePersistence?: boolean } = {}): void {
  if (persistTimer) {
    clearTimeout(persistTimer)
    persistTimer = undefined
  }
  tasks.clear()
  subscribers.clear()
  nextEventId = 1
  executeTaskForTests = undefined
  if (options.removePersistence) {
    try {
      fs.unlinkSync(getTaskStorePersistencePath())
    } catch {}
  }
}

loadPersistedTaskStore()
