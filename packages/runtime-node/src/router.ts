/**
 * Minimal HTTP router for the runtime node.
 */

import { IncomingMessage, ServerResponse } from 'http'
import { URL } from 'url'
import fs from 'fs'
import path from 'path'
import { spawn } from 'child_process'
import { logger } from './logger.js'
import { config } from './config.js'
import { isIsolatedEnvironment } from './isolation.js'
import { submitTask, getTask, cancelTask, getLogs } from './task-store.js'

export interface Router {
  handle(req: IncomingMessage, res: ServerResponse): Promise<void>
}

const MAX_UPLOAD_BYTES = 500 * 1024 * 1024 // 500MB

export function createRuntimeRouter(): Router {
  return {
    async handle(req, res) {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`)
      const pathname = url.pathname
      const method = req.method || 'GET'

      logger.debug({ method, pathname }, 'Runtime request')

      // CORS — whitelist only if explicitly configured
      if (config.runtime.corsOrigin) {
        res.setHeader('Access-Control-Allow-Origin', config.runtime.corsOrigin)
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
      }
      if (method === 'OPTIONS') {
        res.writeHead(204)
        res.end()
        return
      }

      // API key check (if configured)
      if (config.runtime.apiKey) {
        const auth = req.headers.authorization || ''
        const expected = `Bearer ${config.runtime.apiKey}`
        if (auth !== expected) {
          res.writeHead(401, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Unauthorized' }))
          return
        }
      } else if (process.env.NODE_ENV === 'production') {
        logger.warn('RUNTIME_API_KEY is not set. The runtime node is exposed without authentication.')
      }

      // Routes
      if (method === 'GET' && pathname === '/health') {
        const isolated = await isIsolatedEnvironment()
        const healthDetails = await getDeepHealthChecks()
        const ok = healthDetails.inboxWritable && healthDetails.outboxWritable && healthDetails.pythonOk && healthDetails.workerOk
        res.writeHead(ok ? 200 : 503, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
          ok,
          role: 'runtime',
          isolation: isolated ? 'verified' : 'unverified',
          mode: config.runtime.mode,
          pid: process.pid,
          checks: healthDetails,
        }))
        return
      }

      if (method === 'POST' && pathname === '/upload') {
        const taskId = url.searchParams.get('taskId')
        if (!taskId || !/^[a-zA-Z0-9_-]+$/.test(taskId)) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Missing or invalid taskId query parameter' }))
          return
        }

        const inboxDir = config.runtime.inbox
        if (!fs.existsSync(inboxDir)) {
          fs.mkdirSync(inboxDir, { recursive: true })
        }
        const destPath = path.join(inboxDir, `${taskId}.sample`)
        const contentLength = parseInt(req.headers['content-length'] || '0', 10)
        if (contentLength > MAX_UPLOAD_BYTES) {
          res.writeHead(413, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Payload too large' }))
          return
        }

        try {
          const writeStream = fs.createWriteStream(destPath)
          let received = 0
          req.on('data', (chunk: Buffer) => {
            received += chunk.length
            if (received > MAX_UPLOAD_BYTES) {
              req.destroy()
              writeStream.destroy()
              return
            }
          })
          req.pipe(writeStream)
          await new Promise<void>((resolve, reject) => {
            writeStream.on('finish', resolve)
            writeStream.on('error', reject)
            req.on('error', reject)
          })
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true, inboxPath: destPath }))
        } catch (err) {
          try { fs.unlinkSync(destPath) } catch {}
          res.writeHead(500, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: `Upload failed: ${err}` }))
        }
        return
      }

      if (method === 'GET' && pathname.startsWith('/download/')) {
        const rest = pathname.slice('/download/'.length)
        const [taskId, ...artifactNameParts] = rest.split('/')
        const artifactName = decodeURIComponent(artifactNameParts.join('/'))
        if (!taskId || !artifactName || artifactName.includes('..') || /[\\/\x00]/.test(artifactName)) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Invalid download path or artifact name' }))
          return
        }
        const filePath = path.join(config.runtime.outbox, taskId, artifactName)
        const resolved = path.resolve(filePath)
        const outboxResolved = path.resolve(config.runtime.outbox)
        if (!resolved.startsWith(outboxResolved + path.sep)) {
          res.writeHead(403, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Forbidden path' }))
          return
        }
        if (!fs.existsSync(resolved)) {
          res.writeHead(404, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Artifact not found' }))
          return
        }
        const stat = fs.statSync(resolved)
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': stat.size.toString(),
          'Content-Disposition': `attachment; filename="${artifactName}"`,
        })
        fs.createReadStream(resolved).pipe(res)
        return
      }

      if (method === 'POST' && pathname === '/execute') {
        try {
          const freeBytes = getDiskFreeBytes(config.runtime.inbox)
          if (freeBytes !== null && freeBytes < config.runtime.minDiskSpaceBytes) {
            res.writeHead(503, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ ok: false, error: `Insufficient disk space on inbox volume (${Math.round(freeBytes / 1024 / 1024)}MB free, ${Math.round(config.runtime.minDiskSpaceBytes / 1024 / 1024)}MB required)` }))
            return
          }
          const payload = await readJsonBody(req) as { taskId: string; sampleId: string; tool: string; args: Record<string, unknown>; timeoutMs: number; runtimeBackendHint?: { type: string; handler: string } }
          const { taskId, sampleId, tool, args, timeoutMs = 120_000, runtimeBackendHint } = payload
          const result = submitTask({ taskId, sampleId, tool, args, timeoutMs, runtimeBackendHint })
          res.writeHead(202, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true, taskId: result.taskId, status: result.status }))
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: String(e) }))
        }
        return
      }

      if (method === 'GET' && pathname.startsWith('/tasks/')) {
        const rest = pathname.slice('/tasks/'.length)
        const [taskId, subResource] = rest.split('/')

        if (subResource === 'logs') {
          const offset = parseInt(url.searchParams.get('offset') || '0', 10)
          const limit = parseInt(url.searchParams.get('limit') || '1000', 10)
          const logs = getLogs(taskId, offset, limit)
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: true, taskId, offset, limit, logs }))
          return
        }

        if (subResource === 'cancel') {
          res.writeHead(405, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Use POST /tasks/:taskId/cancel' }))
          return
        }

        const state = getTask(taskId)
        if (!state) {
          res.writeHead(404, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: false, error: 'Task not found' }))
          return
        }
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
          ok: true,
          taskId: state.taskId,
          status: state.status,
          submittedAt: state.submittedAt,
          startedAt: state.startedAt,
          completedAt: state.completedAt,
          progressPercent: state.progressPercent,
          lastMessage: state.lastMessage,
          result: state.result,
        }))
        return
      }

      if (method === 'POST' && pathname.startsWith('/tasks/')) {
        const rest = pathname.slice('/tasks/'.length)
        const [taskId, subResource] = rest.split('/')
        if (subResource === 'cancel') {
          const cancelResult = cancelTask(taskId)
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ ok: cancelResult.ok, taskId, wasRunning: cancelResult.wasRunning }))
          return
        }
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: 'Not found' }))
        return
      }

      if (method === 'GET' && pathname === '/events') {
        res.writeHead(501, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: 'SSE events endpoint is not implemented. Use GET /tasks/:taskId for polling.' }))
        return
      }

      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Not found' }))
    },
  }
}

async function readJsonBody(req: IncomingMessage, maxBytes = 10 * 1024 * 1024): Promise<any> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let received = 0
    req.on('data', (chunk: Buffer) => {
      received += chunk.length
      if (received > maxBytes) {
        req.destroy()
        reject(new Error('Payload too large'))
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf-8')
        resolve(raw ? JSON.parse(raw) : {})
      } catch (e) {
        reject(e)
      }
    })
    req.on('error', reject)
  })
}

function getDiskFreeBytes(dir: string): number | null {
  try {
    // @ts-ignore — statfs is available in Node 18.15+ but types may lag
    const stats = fs.statfsSync(dir)
    if (stats && typeof stats.bavail === 'number' && typeof stats.bsize === 'number') {
      return stats.bavail * stats.bsize
    }
  } catch {
    // Fallback: try parent directory
    try {
      const parent = path.dirname(dir)
      // @ts-ignore
      const stats = fs.statfsSync(parent)
      if (stats && typeof stats.bavail === 'number' && typeof stats.bsize === 'number') {
        return stats.bavail * stats.bsize
      }
    } catch {}
  }
  return null
}

interface DeepHealthChecks {
  inboxWritable: boolean
  outboxWritable: boolean
  pythonOk: boolean
  workerOk: boolean
  diskFreeBytes: number | null
}

async function getDeepHealthChecks(): Promise<DeepHealthChecks> {
  const inbox = config.runtime.inbox
  const outbox = config.runtime.outbox

  let inboxWritable = false
  let outboxWritable = false
  try {
    fs.mkdirSync(inbox, { recursive: true })
    const testFile = path.join(inbox, '.health-test')
    fs.writeFileSync(testFile, 'ok')
    fs.unlinkSync(testFile)
    inboxWritable = true
  } catch {}

  try {
    fs.mkdirSync(outbox, { recursive: true })
    const testFile = path.join(outbox, '.health-test')
    fs.writeFileSync(testFile, 'ok')
    fs.unlinkSync(testFile)
    outboxWritable = true
  } catch {}

  let pythonOk = false
  try {
    const proc = spawn(config.runtime.pythonPath, ['--version'], { stdio: 'pipe' })
    await new Promise<void>((resolve, reject) => {
      proc.on('close', (code) => (code === 0 ? resolve() : reject(new Error('exit ' + code))))
      proc.on('error', reject)
    })
    pythonOk = true
  } catch {}

  let workerOk = false
  try {
    const workerPath = path.join(process.cwd(), 'workers', 'static_worker.py')
    workerOk = fs.existsSync(workerPath)
  } catch {}

  return {
    inboxWritable,
    outboxWritable,
    pythonOk,
    workerOk,
    diskFreeBytes: getDiskFreeBytes(inbox),
  }
}
