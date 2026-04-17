/**
 * Health Check Routes
 * GET /api/v1/health   — liveness probe (always 200 if process is up)
 * GET /api/v1/ready    — readiness probe (checks all dependencies)
 */

import { spawn } from 'child_process'
import fs from 'fs'
import type { ServerResponse } from 'http'
import type { DatabaseManager } from '../../database.js'
import type { StorageManager } from '../../storage/storage-manager.js'
import type { JobQueue } from '../../job-queue.js'
import { config } from '../../config.js'
import type { RuntimeClientOptions } from '../../runtime-client/runtime-client.js'

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
  runtimeClient?: { health(): Promise<{ ok: boolean } | null> } | null
}

/** Singleton holder — set once during server init. */
let _deps: HealthDependencies = {}

export function setHealthDependencies(deps: HealthDependencies): void {
  _deps = deps
}

async function runCommandCheck(cmd: string, args: string[], timeoutMs = 5000): Promise<{ ok: boolean; message?: string }> {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { stdio: 'ignore', timeout: timeoutMs })
    let killed = false
    const timer = setTimeout(() => {
      killed = true
      proc.kill()
      resolve({ ok: false, message: 'timeout' })
    }, timeoutMs)
    proc.on('error', () => {
      clearTimeout(timer)
      if (!killed) resolve({ ok: false, message: 'not found' })
    })
    proc.on('close', (code) => {
      clearTimeout(timer)
      if (!killed) resolve({ ok: code === 0 })
    })
  })
}

async function checkGhidra(): Promise<ComponentCheck> {
  const ghidraDir = process.env.GHIDRA_INSTALL_DIR
  if (!ghidraDir || !fs.existsSync(ghidraDir)) {
    return { status: 'fail', message: `GHIDRA_INSTALL_DIR not found: ${ghidraDir || 'unset'}` }
  }
  const analyzeHeadless = `${ghidraDir}/support/analyzeHeadless`
  if (!fs.existsSync(analyzeHeadless)) {
    return { status: 'fail', message: 'analyzeHeadless missing' }
  }
  const javaRes = await runCommandCheck('java', ['-version'], 3000)
  if (!javaRes.ok) {
    return { status: 'fail', message: `Java unavailable: ${javaRes.message}` }
  }
  return { status: 'ok' }
}

async function checkPython(): Promise<ComponentCheck> {
  const res = await runCommandCheck('python3', ['--version'], 3000)
  if (!res.ok) {
    const fallback = await runCommandCheck('python', ['--version'], 3000)
    if (!fallback.ok) return { status: 'fail', message: 'Python not found' }
  }
  return { status: 'ok' }
}

async function checkExternalBackend(name: string, cmd: string, args: string[]): Promise<ComponentCheck> {
  const res = await runCommandCheck(cmd, args, 3000)
  return res.ok ? { status: 'ok' } : { status: 'fail', message: `${name} unavailable: ${res.message}` }
}

async function checkRuntimeConnection(): Promise<ComponentCheck> {
  if (config.runtime.mode === 'disabled') {
    return { status: 'ok', message: 'runtime disabled' }
  }
  const client = _deps.runtimeClient
  if (!client) {
    return { status: 'degraded', message: `runtime mode=${config.runtime.mode} but no runtime client connected` }
  }
  try {
    const health = await client.health()
    if (health?.ok) return { status: 'ok' }
    return { status: 'degraded', message: 'runtime node unhealthy' }
  } catch (err) {
    return { status: 'degraded', message: `runtime health check failed: ${(err as Error).message}` }
  }
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

  // Analyzer-specific backend checks
  if (config.node.role === 'analyzer' || config.node.role === 'hybrid') {
    checks.ghidra = await checkGhidra()
    checks.python = await checkPython()
    checks.rizin = await checkExternalBackend('rizin', 'rizin', ['-v'])
    checks.capa = await checkExternalBackend('capa', 'capa', ['--version'])
  }

  // Runtime connection check
  checks.runtime = await checkRuntimeConnection()

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
