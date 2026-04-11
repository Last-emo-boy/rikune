/**
 * Health Check Routes
 * GET /api/v1/health   — liveness probe (always 200 if process is up)
 * GET /api/v1/ready    — readiness probe (checks all dependencies)
 */

import type { ServerResponse } from 'http'
import type { DatabaseManager } from '../../database.js'
import type { StorageManager } from '../../storage/storage-manager.js'
import type { JobQueue } from '../../job-queue.js'

export interface HealthResponse {
  status: string
  uptime: number
  timestamp: string
  version?: string
}

export interface ReadinessResponse {
  status: 'ready' | 'degraded' | 'unavailable'
  uptime: number
  timestamp: string
  version?: string
  checks: Record<string, ComponentCheck>
}

export interface ComponentCheck {
  status: 'ok' | 'degraded' | 'fail'
  latencyMs?: number
  message?: string
}

export interface HealthDependencies {
  database?: DatabaseManager
  storageManager?: StorageManager
  jobQueue?: JobQueue
}

/** Singleton holder — set once during server init. */
let _deps: HealthDependencies = {}

export function setHealthDependencies(deps: HealthDependencies): void {
  _deps = deps
}

/**
 * Handle liveness check — always succeeds if process is alive.
 * GET /api/v1/health
 */
export async function handleHealthCheck(
  res: ServerResponse,
  version?: string
): Promise<void> {
  const health: HealthResponse = {
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: version || '1.0.0-beta.3',
  }

  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(health))
}

/**
 * Handle readiness check — verifies all dependencies.
 * GET /api/v1/ready
 */
export async function handleReadinessCheck(
  res: ServerResponse,
  version?: string,
): Promise<void> {
  const checks: Record<string, ComponentCheck> = {}

  // Database check
  if (_deps.database) {
    const start = Date.now()
    try {
      _deps.database.querySql<{ ok: number }>('SELECT 1 AS ok')
      checks.database = { status: 'ok', latencyMs: Date.now() - start }
    } catch (err) {
      checks.database = { status: 'fail', latencyMs: Date.now() - start, message: (err as Error).message }
    }
  } else {
    checks.database = { status: 'fail', message: 'not initialised' }
  }

  // Job queue check
  if (_deps.jobQueue) {
    checks.jobQueue = {
      status: 'ok',
      message: `queue=${_deps.jobQueue.getQueueLength()} total=${_deps.jobQueue.getTotalJobs()}`,
    }
  }

  // Determine overall status
  const allChecks = Object.values(checks)
  const hasFail = allChecks.some(c => c.status === 'fail')
  const hasDegraded = allChecks.some(c => c.status === 'degraded')
  const overall: ReadinessResponse['status'] = hasFail ? 'unavailable' : hasDegraded ? 'degraded' : 'ready'

  const body: ReadinessResponse = {
    status: overall,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: version || '1.0.0-beta.3',
    checks,
  }

  const httpStatus = overall === 'ready' ? 200 : overall === 'degraded' ? 200 : 503
  res.writeHead(httpStatus, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}
