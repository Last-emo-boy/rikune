import { randomUUID } from 'crypto'
import { hostname } from 'os'
import type { DatabaseManager } from './database.js'

export interface ContextWriteLeaseGuard {
  readonly lockKey: string
  readonly ownerToken: string
  /** Refreshes the heartbeat and throws if this writer no longer owns the lease. */
  assertOwned(): void
}

export interface ContextWriteLeaseOptions<T> {
  database: DatabaseManager
  lockKey: string
  staleMs: number
  label: string
  operation: (guard: ContextWriteLeaseGuard) => Promise<T>
}

/**
 * Serializes context-only persistence across processes with a SQLite CAS lease.
 * The filesystem lock remains a second compatibility boundary inside this lease.
 */
export async function withContextWriteLease<T>(options: ContextWriteLeaseOptions<T>): Promise<T> {
  if (!Number.isSafeInteger(options.staleMs) || options.staleMs < 3) {
    throw new Error('Context write lease staleMs must be an integer of at least 3ms.')
  }

  const ownerToken = randomUUID()
  const acquiredAtMs = Date.now()
  const acquiredAt = new Date(acquiredAtMs).toISOString()
  const acquired = options.database.tryAcquireContextWriteLease(
    {
      lock_key: options.lockKey,
      owner_token: ownerToken,
      host_id: hostname(),
      pid: process.pid,
      acquired_at: acquiredAt,
      heartbeat_at: acquiredAt,
    },
    new Date(acquiredAtMs - options.staleMs).toISOString()
  )
  if (!acquired.acquired) {
    throw new Error(`${options.label} is locked by another live context writer.`)
  }

  let lostError: Error | null = null
  const refresh = (): void => {
    if (lostError) throw lostError
    const heartbeatAt = new Date().toISOString()
    try {
      if (!options.database.heartbeatContextWriteLease(options.lockKey, ownerToken, heartbeatAt)) {
        lostError = new Error(`${options.label} lost its context write lease ownership.`)
      }
    } catch (error) {
      lostError = new Error(
        `${options.label} could not refresh its context write lease: ${
          error instanceof Error ? error.message : String(error)
        }`
      )
    }
    if (lostError) throw lostError
  }

  const heartbeatIntervalMs = Math.max(1, Math.floor(options.staleMs / 3))
  const heartbeatTimer = setInterval(() => {
    try {
      refresh()
    } catch {
      // The synchronous commit-boundary assertion reports the stored ownership failure.
    }
  }, heartbeatIntervalMs)
  heartbeatTimer.unref()

  const guard: ContextWriteLeaseGuard = {
    lockKey: options.lockKey,
    ownerToken,
    assertOwned: refresh,
  }

  try {
    return await options.operation(guard)
  } finally {
    clearInterval(heartbeatTimer)
    options.database.releaseContextWriteLease(options.lockKey, ownerToken)
  }
}
