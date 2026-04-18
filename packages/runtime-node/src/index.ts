/**
 * Rikune Runtime Node
 *
 * Lightweight execution worker that runs inside an isolated environment
 * (Windows Sandbox) and exposes dynamic analysis tools over HTTP.
 */

import { createServer } from 'http'
import os from 'os'
import fs from 'fs/promises'
import path from 'path'
import { spawn } from 'child_process'
import { logger } from './logger.js'
import { config } from './config.js'
import { createRuntimeRouter } from './router.js'
import { isIsolatedEnvironment } from './isolation.js'

function getPrimaryIp(): string | null {
  const interfaces = os.networkInterfaces()
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address
      }
    }
  }
  return null
}

function quotePowerShellString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

async function runPowerShellBestEffort(command: string, timeoutMs: number): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    const timeout = setTimeout(() => {
      child.kill()
      resolve({ code: null, stdout, stderr: stderr || `Timed out after ${timeoutMs}ms` })
    }, timeoutMs)
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })
    child.on('error', (err) => {
      clearTimeout(timeout)
      resolve({ code: null, stdout, stderr: err instanceof Error ? err.message : String(err) })
    })
    child.on('close', (code) => {
      clearTimeout(timeout)
      resolve({ code, stdout, stderr })
    })
  })
}

async function applyWindowsSandboxDefenderExclusions(): Promise<void> {
  if (process.platform !== 'win32' || config.runtime.mode !== 'sandbox') {
    return
  }
  if (process.env.RUNTIME_APPLY_DEFENDER_EXCLUSIONS === 'false') {
    logger.info('Runtime Defender exclusion setup disabled by RUNTIME_APPLY_DEFENDER_EXCLUSIONS=false')
    return
  }

  const candidatePaths = Array.from(new Set([
    config.runtime.inbox,
    config.runtime.outbox,
    'C:\\rikune-workers',
  ].filter(Boolean)))

  try {
    await Promise.all(candidatePaths.map((candidatePath) => fs.mkdir(candidatePath, { recursive: true }).catch(() => undefined)))
  } catch {
    // Directory creation is best-effort; Add-MpPreference below checks path existence.
  }

  const psPaths = candidatePaths.map(quotePowerShellString).join(',')
  const command = [
    `$defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue`,
    `if (-not $defenderService -or $defenderService.Status -ne 'Running') {`,
    `  Write-Output 'Windows Defender service is not running; skipping runtime exclusions'`,
    `  exit 0`,
    `}`,
    `$paths = @(${psPaths})`,
    'foreach ($p in $paths) {',
    '  if (Test-Path -LiteralPath $p) {',
    '    Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue',
    '  }',
    '}',
  ].join('; ')
  const result = await runPowerShellBestEffort(command, 15_000)
  if (result.code === 0) {
    logger.info({
      paths: candidatePaths,
      stdout: result.stdout.trim(),
    }, 'Completed Windows Defender exclusion setup for runtime sandbox paths')
    return
  }
  logger.warn({
    paths: candidatePaths,
    code: result.code,
    stderr: result.stderr.trim(),
    stdout: result.stdout.trim(),
  }, 'Failed to apply Windows Defender exclusions; continuing runtime startup')
}

async function main() {
  logger.info({ role: 'runtime', mode: config.runtime.mode }, 'Rikune runtime node starting...')

  if (config.runtime.mode === 'sandbox') {
    const isolated = await isIsolatedEnvironment()
    if (!isolated) {
      if (process.env.ALLOW_UNSAFE_RUNTIME === 'true') {
        logger.warn('ALLOW_UNSAFE_RUNTIME is set; continuing without verified isolation. THIS IS DANGEROUS.')
      } else {
        logger.error('Runtime node is configured for sandbox mode but isolation could not be verified. Refusing to start. Set ALLOW_UNSAFE_RUNTIME=true only for development.')
        process.exit(1)
      }
    }
    await applyWindowsSandboxDefenderExclusions()
  }

  const router = createRuntimeRouter()
  const server = createServer((req, res) => {
    router.handle(req, res).catch((err: unknown) => {
      logger.error({ err }, 'Unhandled router error')
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: 'Internal runtime error' }))
      }
    })
  })

  server.listen(config.server.port, config.server.host, () => {
    logger.info({ host: config.server.host, port: config.server.port }, 'Runtime HTTP server listening')
  })

  // Memory watchdog (A4.5)
  const memoryWatchdogInterval = setInterval(() => {
    const rss = process.memoryUsage().rss
    if (rss > config.runtime.maxRssBytes) {
      logger.error({ rss, maxRss: config.runtime.maxRssBytes }, 'Memory limit exceeded; exiting to allow restart')
      clearInterval(memoryWatchdogInterval)
      process.exit(1)
    }
  }, 30_000)

  // Write ready-file if configured (used by Windows Sandbox auto-discovery)
  if (config.runtime.readyFile) {
    const primaryIp = getPrimaryIp()
    const endpointHost = primaryIp || config.server.host
    const endpoint = `http://${endpointHost}:${config.server.port}`
    try {
      await fs.mkdir(path.dirname(config.runtime.readyFile), { recursive: true })
      await fs.writeFile(
        config.runtime.readyFile,
        JSON.stringify({ endpoint, host: endpointHost, port: config.server.port, pid: process.pid, readyAt: new Date().toISOString() }),
        'utf-8',
      )
      logger.info({ readyFile: config.runtime.readyFile, endpoint }, 'Wrote runtime ready file')
    } catch (err) {
      logger.warn({ err, readyFile: config.runtime.readyFile }, 'Failed to write runtime ready file')
    }
  }

  // Graceful shutdown
  const shutdown = () => {
    logger.info('Shutting down runtime node...')
    server.close(() => process.exit(0))
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

main().catch((err) => {
  logger.error({ err }, 'Runtime node failed to start')
  process.exit(1)
})
