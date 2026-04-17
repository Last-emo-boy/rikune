/**
 * Rikune Windows Host Agent
 *
 * Runs on the Windows host and exposes an HTTP API for the remote Analyzer
 * to start / stop Windows Sandbox runtimes.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'http'
import fs from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { spawn, execFile } from 'child_process'
import { randomUUID } from 'crypto'
import os from 'os'
import net from 'net'
import { logger } from './logger.js'
import { buildWsbXml } from '@rikune/shared'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const PORT = parseInt(process.env.HOST_AGENT_PORT || '18082', 10)
const API_KEY = process.env.HOST_AGENT_API_KEY || ''
const RUNTIME_INTERNAL_PORT = 18081
const LISTEN_PORT_MIN = 18081
const LISTEN_PORT_MAX = 19000

interface ActiveSandbox {
  sandboxId: string
  sandboxDir: string
  wsbPath: string
  process: ReturnType<typeof spawn>
  endpoint: string
  runtimeHost: string
  listenPort: number
}

interface StartSandboxRequest {
  timeoutMs?: number
  runtimeApiKey?: string
}

const activeSandboxes = new Map<string, ActiveSandbox>()
const usedListenPorts = new Set<number>()

async function isPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = net.createServer()
    srv.once('error', () => resolve(false))
    srv.once('listening', () => {
      srv.close(() => resolve(true))
    })
    srv.listen(port)
  })
}

async function allocateListenPort(): Promise<number | null> {
  for (let p = LISTEN_PORT_MIN; p <= LISTEN_PORT_MAX; p++) {
    if (usedListenPorts.has(p)) continue
    if (await isPortAvailable(p)) {
      usedListenPorts.add(p)
      return p
    }
  }
  return null
}

function releaseListenPort(port: number): void {
  usedListenPorts.delete(port)
}

function findProjectRoot(startDir: string): string | null {
  let current = startDir
  for (let i = 0; i < 10; i++) {
    if (existsSync(path.join(current, 'workers')) && existsSync(path.join(current, 'packages'))) {
      return current
    }
    const parent = path.dirname(current)
    if (parent === current) break
    current = parent
  }
  return null
}

const projectRoot = findProjectRoot(__dirname) || process.cwd()

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

function existingExecutablePath(rawPath?: string): string | null {
  if (!rawPath || rawPath.trim().length === 0) {
    return null
  }
  const candidate = rawPath.trim().replace(/^"|"$/g, '')
  return existsSync(candidate) ? candidate : null
}

function findExecutableOnPath(command: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile('where.exe', [command], { windowsHide: true }, (err, stdout) => {
      if (err) {
        resolve(null)
        return
      }
      const found = stdout
        .toString()
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .filter((line) => !line.toLowerCase().includes('\\windowsapps\\'))
        .find((line) => existsSync(line))
      resolve(found || null)
    })
  })
}

async function resolveHostPythonPath(): Promise<string | null> {
  return (
    existingExecutablePath(process.env.HOST_AGENT_PYTHON_PATH) ||
    existingExecutablePath(process.env.RUNTIME_PYTHON_PATH) ||
    await findExecutableOnPath('python') ||
    await findExecutableOnPath('py')
  )
}

function requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
  if (!API_KEY) return true
  const auth = req.headers.authorization || ''
  const expected = `Bearer ${API_KEY}`
  if (auth !== expected) {
    res.writeHead(401, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: 'Unauthorized' }))
    return false
  }
  return true
}

async function readJsonBody(req: IncomingMessage, maxBytes = 10 * 1024 * 1024): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let body = ''
    let received = 0
    req.on('data', (chunk: string) => {
      received += Buffer.byteLength(chunk)
      if (received > maxBytes) {
        req.destroy()
        reject(new Error('Payload too large'))
        return
      }
      body += chunk
    })
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {})
      } catch (e) {
        reject(e)
      }
    })
    req.on('error', reject)
  })
}

async function writeWsbConfig(
  wsbPath: string,
  sandboxDir: string,
  runtimeEntryHost: string,
  runtimeApiKey?: string,
): Promise<void> {
  const inboxDir = path.join(sandboxDir, 'inbox')
  const outboxDir = path.join(sandboxDir, 'outbox')
  const runtimeDirHost = path.dirname(runtimeEntryHost)
  const runtimeFileName = path.basename(runtimeEntryHost)
  const workersDirHost = path.join(projectRoot, 'workers')
  const readyFileSandbox = 'C:\\rikune-outbox\\runtime.ready.json'
  const hostNodePath = existingExecutablePath(process.env.HOST_AGENT_NODE_PATH) || process.execPath
  const hostPythonPath = await resolveHostPythonPath()

  if (!hostPythonPath) {
    logger.warn(
      'No host Python executable found for Windows Sandbox mapping. Runtime health checks and Python-backed dynamic tools may fail. Set HOST_AGENT_PYTHON_PATH to a real python.exe.'
    )
  }

  const wsb = buildWsbXml({
    runtimeDirHost,
    runtimeFileName,
    workersDirHost,
    inboxDir,
    outboxDir,
    readyFileSandbox,
    runtimeApiKey,
    nodeDirHost: path.dirname(hostNodePath),
    nodeFileName: path.basename(hostNodePath),
    pythonDirHost: hostPythonPath ? path.dirname(hostPythonPath) : undefined,
    pythonFileName: hostPythonPath ? path.basename(hostPythonPath) : undefined,
  })
  await fs.writeFile(wsbPath, wsb, 'utf-8')
}

async function waitForRuntimeReady(
  sandboxDir: string,
  timeoutMs: number
): Promise<{ endpoint?: string; host?: string } | null> {
  const readyFile = path.join(sandboxDir, 'outbox', 'runtime.ready.json')
  const started = Date.now()
  const interval = 1000

  while (Date.now() - started < timeoutMs) {
    try {
      const raw = await fs.readFile(readyFile, 'utf-8')
      const data = JSON.parse(raw) as { endpoint?: string; host?: string }
      if (data.endpoint && typeof data.endpoint === 'string') {
        return data
      }
      return { endpoint: 'http://127.0.0.1:18081', host: '127.0.0.1' }
    } catch {
      await new Promise((r) => setTimeout(r, interval))
    }
  }
  return null
}

async function addPortProxy(sandboxIp: string, listenPort: number): Promise<void> {
  logger.warn('netsh portproxy is binding to all interfaces. Consider restricting network access.')
  return new Promise((resolve, reject) => {
    execFile(
      'netsh',
      ['interface', 'portproxy', 'delete', 'v4tov4', `listenport=${listenPort}`],
      () => {
        execFile(
          'netsh',
          [
            'interface',
            'portproxy',
            'add',
            'v4tov4',
            `listenport=${listenPort}`,
            `connectaddress=${sandboxIp}`,
            `connectport=${RUNTIME_INTERNAL_PORT}`,
          ],
          (err) => {
            if (err) return reject(err)
            resolve()
          }
        )
      }
    )
  })
}

async function removePortProxy(listenPort: number): Promise<void> {
  return new Promise((resolve) => {
    execFile(
      'netsh',
      ['interface', 'portproxy', 'delete', 'v4tov4', `listenport=${listenPort}`],
      () => resolve()
    )
  })
}

async function removeSandboxDir(sandboxDir: string, reason: string): Promise<void> {
  if (/^(1|true|yes|on)$/i.test(process.env.HOST_AGENT_KEEP_FAILED_SANDBOX || '')) {
    logger.warn({ sandboxDir, reason }, 'Keeping failed sandbox workspace for diagnostics')
    return
  }

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await fs.rm(sandboxDir, { recursive: true, force: true })
      return
    } catch (err) {
      logger.warn({ err, sandboxDir, attempt, reason }, 'Failed to remove sandbox workspace')
      await new Promise((resolve) => setTimeout(resolve, 500 * attempt))
    }
  }
}

async function startSandbox(
  body: unknown
): Promise<{ ok: boolean; endpoint?: string; sandboxId?: string; error?: string }> {
  if (process.platform !== 'win32') {
    return { ok: false, error: 'Windows Host Agent requires Windows platform' }
  }

  const request = (body && typeof body === 'object' ? body : {}) as StartSandboxRequest
  const timeoutMs = typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)
    ? Math.max(1000, request.timeoutMs)
    : 60000
  const runtimeApiKey = typeof request.runtimeApiKey === 'string' && request.runtimeApiKey.trim().length > 0
    ? request.runtimeApiKey.trim()
    : process.env.HOST_AGENT_RUNTIME_API_KEY || process.env.RUNTIME_API_KEY || API_KEY || undefined
  const listenPort = await allocateListenPort()
  if (listenPort === null) {
    return { ok: false, error: 'No available listen port for new Sandbox runtime' }
  }

  const workspaceRoot =
    process.env.HOST_AGENT_WORKSPACE || path.join(os.tmpdir(), 'rikune-host-agent')
  const sandboxDir = path.join(workspaceRoot, 'sandbox', randomUUID())
  await fs.mkdir(path.join(sandboxDir, 'inbox'), { recursive: true })
  await fs.mkdir(path.join(sandboxDir, 'outbox'), { recursive: true })

  const runtimeEntryHost = path.join(projectRoot, 'packages', 'runtime-node', 'dist', 'index.js')
  const workersDirHost = path.join(projectRoot, 'workers')
  if (!existsSync(runtimeEntryHost) || !existsSync(workersDirHost)) {
    releaseListenPort(listenPort)
    await fs.rm(sandboxDir, { recursive: true, force: true })
    return {
      ok: false,
      error:
        'Required runtime paths are missing. ' +
        `runtimeEntryHost=${runtimeEntryHost} (exists=${existsSync(runtimeEntryHost)}), ` +
        `workersDirHost=${workersDirHost} (exists=${existsSync(workersDirHost)}). ` +
        'Ensure the project is built (npm run build:runtime) and workers/ directory is present.',
    }
  }

  const wsbPath = path.join(sandboxDir, 'runtime.wsb')
  await writeWsbConfig(wsbPath, sandboxDir, runtimeEntryHost, runtimeApiKey)

  if (process.env.NODE_ENV === 'production' && !API_KEY) {
    logger.warn(
      'HOST_AGENT_API_KEY is not set. The sandbox runtime is exposed to all network interfaces.'
    )
  }

  logger.info({ sandboxDir, wsbPath, listenPort }, 'Launching Windows Sandbox via Host Agent')

  const sandboxProcess = spawn('C:\\Windows\\System32\\WindowsSandbox.exe', [wsbPath], {
    detached: true,
    windowsHide: true,
    stdio: 'ignore',
  })
  let sandboxExit: { code: number | null; signal: NodeJS.Signals | null } | null = null
  sandboxProcess.once('exit', (code, signal) => {
    sandboxExit = { code, signal }
    logger.warn({ sandboxDir, wsbPath, code, signal }, 'Windows Sandbox process exited before runtime readiness was confirmed')
  })

  const ready = await waitForRuntimeReady(sandboxDir, timeoutMs)
  if (!ready || !ready.host) {
    try {
      sandboxProcess.kill()
    } catch {}
    releaseListenPort(listenPort)
    await removeSandboxDir(sandboxDir, 'runtime_not_ready')
    const exitDetail = sandboxExit
      ? ` WindowsSandbox.exe exited with code=${sandboxExit.code ?? 'null'} signal=${sandboxExit.signal ?? 'null'}.`
      : ''
    return {
      ok: false,
      error:
        `Sandbox runtime did not become ready within timeout.${exitDetail} ` +
        `wsbPath=${wsbPath}`,
    }
  }

  try {
    await addPortProxy(ready.host, listenPort)
  } catch (err) {
    logger.warn(
      { err, listenPort },
      'Failed to add portproxy; external Analyzer may not reach the runtime'
    )
  }

  const hostIp = getPrimaryIp() || '127.0.0.1'
  const endpoint = `http://${hostIp}:${listenPort}`
  const sandboxId = randomUUID()

  activeSandboxes.set(sandboxId, {
    sandboxId,
    sandboxDir,
    wsbPath,
    process: sandboxProcess,
    endpoint,
    runtimeHost: ready.host,
    listenPort,
  })

  logger.info(
    { sandboxId, endpoint, runtimeHost: ready.host, listenPort },
    'Sandbox started and portproxied'
  )
  return { ok: true, endpoint, sandboxId }
}

async function stopSandbox(sandboxId: string): Promise<{ ok: boolean; error?: string }> {
  const box = activeSandboxes.get(sandboxId)
  if (!box) {
    return { ok: false, error: 'Sandbox not found' }
  }
  try {
    box.process.kill()
  } catch {}
  try {
    await removePortProxy(box.listenPort)
  } catch {}
  try {
    await removeSandboxDir(box.sandboxDir, 'stop_sandbox')
  } catch {}
  releaseListenPort(box.listenPort)
  activeSandboxes.delete(sandboxId)
  logger.info({ sandboxId, listenPort: box.listenPort }, 'Sandbox stopped and cleaned up')
  return { ok: true }
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host}`)

    if (req.method === 'POST' && url.pathname === '/sandbox/start') {
      if (!requireAuth(req, res)) return
      const body = await readJsonBody(req)
      const result = await startSandbox(body)
      const status = result.ok ? 200 : 500
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'POST' && url.pathname === '/sandbox/stop') {
      if (!requireAuth(req, res)) return
      const body = (await readJsonBody(req)) as { sandboxId?: string }
      const result = await stopSandbox(body.sandboxId || '')
      const status = result.ok ? 200 : 404
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'GET' && url.pathname === '/sandbox/health') {
      if (!requireAuth(req, res)) return
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(
        JSON.stringify({
          ok: true,
          sandboxes: Array.from(activeSandboxes.values()).map((b) => ({
            sandboxId: b.sandboxId,
            endpoint: b.endpoint,
            runtimeHost: b.runtimeHost,
          })),
        })
      )
      return
    }

    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: 'Not found' }))
  } catch (err) {
    logger.error({ err }, 'Unhandled request error')
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Internal error' }))
    }
  }
})

server.listen(PORT, () => {
  logger.info({ port: PORT, apiKeyConfigured: !!API_KEY }, 'Windows Host Agent listening')
})

process.on('SIGTERM', async () => {
  logger.info('Shutting down Windows Host Agent...')
  for (const [id] of activeSandboxes) {
    await stopSandbox(id).catch(() => {})
  }
  server.close(() => process.exit(0))
})
process.on('SIGINT', async () => {
  for (const [id] of activeSandboxes) {
    await stopSandbox(id).catch(() => {})
  }
  server.close(() => process.exit(0))
})
