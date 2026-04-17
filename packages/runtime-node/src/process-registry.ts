/**
 * Process registry for tracking spawned child processes per task.
 * Enables forcible cancellation of running tasks.
 */

import { type ChildProcess, spawn } from 'child_process'
import fs from 'fs'
import path from 'path'
import { logger } from './logger.js'

const registry = new Map<string, ChildProcess[]>()

export function registerProcess(taskId: string, child: ChildProcess): void {
  const list = registry.get(taskId) || []
  list.push(child)
  registry.set(taskId, list)

  const cleanup = () => {
    unregisterProcess(taskId, child)
  }
  child.once('close', cleanup)
  child.once('error', cleanup)
}

export function unregisterProcess(taskId: string, child: ChildProcess): void {
  const list = registry.get(taskId)
  if (!list) return
  const idx = list.indexOf(child)
  if (idx >= 0) {
    list.splice(idx, 1)
  }
  if (list.length === 0) {
    registry.delete(taskId)
  }
}

export function killTaskProcesses(taskId: string): void {
  const list = registry.get(taskId)
  if (!list || list.length === 0) return
  for (const child of list) {
    try {
      if (child.pid && !child.killed) {
        if (process.platform === 'win32') {
          // Kill the entire process tree on Windows
          spawn('taskkill', ['/T', '/F', '/PID', String(child.pid)], { stdio: 'ignore', windowsHide: true })
        } else {
          // Negative PID kills the process group on Unix-like systems
          try {
            process.kill(-child.pid, 'SIGTERM')
          } catch {
            child.kill('SIGTERM')
          }
        }
      }
    } catch (err) {
      logger.warn({ err, taskId, pid: child.pid }, 'Failed to kill child process')
    }
  }
  registry.delete(taskId)
}

export function cleanupTaskOutbox(taskId: string, outboxBase: string): void {
  try {
    const outboxDir = path.join(outboxBase, taskId)
    if (fs.existsSync(outboxDir)) {
      fs.rmSync(outboxDir, { recursive: true, force: true })
      logger.debug({ taskId }, 'Cleaned up task outbox directory')
    }
  } catch (err) {
    logger.warn({ err, taskId }, 'Failed to clean up task outbox directory')
  }
}
