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
