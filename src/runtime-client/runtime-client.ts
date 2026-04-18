/**
 * Analyzer-side HTTP client for communicating with the Runtime node.
 */

import http from 'http'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { logger } from '../logger.js'
import type { WorkerResult, ArtifactRef, RuntimeBackendHint } from '../plugins/sdk.js'
import type { RuntimeSidecarUpload } from './sidecar-staging.js'

export interface RuntimeBackendCapability {
  type: RuntimeBackendHint['type']
  handler: string
  description: string
  requiresSample: boolean
}

export interface RuntimeBackendHintValidationResult {
  supported: boolean | null
  capability?: RuntimeBackendCapability
  capabilities?: RuntimeBackendCapability[]
}

export interface RuntimeExecuteRequest {
  taskId: string
  sampleId: string
  tool: string
  args: Record<string, unknown>
  timeoutMs: number
  sampleInboxPath?: string
  runtimeBackendHint?: RuntimeBackendHint
}

export interface RuntimeUploadOptions {
  sidecars?: RuntimeSidecarUpload[]
  preserveFilename?: boolean
}

export interface RuntimeExecuteResponse {
  ok: boolean
  taskId: string
  result?: WorkerResult
  artifactRefs?: { name: string; path: string }[]
  logs?: string[]
  errors?: string[]
  capabilities?: RuntimeBackendCapability[]
}

export interface RuntimeHealthResponse {
  ok: boolean
  role: string
  isolation: string
  mode: string
  pid: number
  features?: {
    taskUploadManifest?: boolean
    sidecarUpload?: boolean
    runtimeBackendCapabilities?: boolean
    taskEvents?: boolean
  }
}

export interface RuntimeSseEvent {
  event: string
  id?: string
  data: unknown
}

export interface RuntimeEventSubscription {
  close(): void
}

export interface RuntimeEventStreamOptions {
  taskId?: string
  onOpen?: () => void
  onEvent: (event: RuntimeSseEvent) => void
  onError?: (error: Error) => void
}

export interface RuntimeClientOptions {
  endpoint: string
  apiKey?: string
  healthCheckTimeoutMs?: number
}

function cloneRuntimeBackendCapabilities(capabilities: RuntimeBackendCapability[]): RuntimeBackendCapability[] {
  return capabilities.map((capability) => ({ ...capability }))
}

function parseRuntimeBackendCapabilities(body: string): RuntimeBackendCapability[] | null {
  try {
    const payload = JSON.parse(body) as {
      data?: {
        runtime_backends?: unknown
      }
    }
    const entries = payload?.data?.runtime_backends
    if (!Array.isArray(entries)) {
      return null
    }

    const capabilities: RuntimeBackendCapability[] = []
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') {
        continue
      }
      const candidate = entry as Partial<RuntimeBackendCapability>
      if (
        (candidate.type === 'python-worker' || candidate.type === 'spawn' || candidate.type === 'inline')
        && typeof candidate.handler === 'string'
        && typeof candidate.description === 'string'
        && typeof candidate.requiresSample === 'boolean'
      ) {
        capabilities.push({
          type: candidate.type,
          handler: candidate.handler,
          description: candidate.description,
          requiresSample: candidate.requiresSample,
        })
      }
    }

    return capabilities
  } catch (err) {
    logger.debug({ err }, 'Runtime capabilities response parsing failed')
    return null
  }
}

export function createRuntimeClient(options: RuntimeClientOptions) {
  let endpoint = options.endpoint
  const apiKey = options.apiKey
  let capabilitiesCache: RuntimeBackendCapability[] | null = null

  function replaceCapabilitiesCache(capabilities: RuntimeBackendCapability[] | null) {
    capabilitiesCache = capabilities ? cloneRuntimeBackendCapabilities(capabilities) : null
  }

  function invalidateCapabilitiesCache() {
    replaceCapabilitiesCache(null)
  }

  function setEndpoint(newEndpoint: string) {
    endpoint = newEndpoint
    invalidateCapabilitiesCache()
  }

  function getEndpoint(): string {
    return endpoint
  }

  async function health(): Promise<RuntimeHealthResponse | null> {
    try {
      const res = await get('/health')
      if (res.statusCode !== 200) return null
      return JSON.parse(res.body) as RuntimeHealthResponse
    } catch (err) {
      logger.debug({ err }, 'Runtime health check failed')
      return null
    }
  }

  async function getCapabilities(options: { forceRefresh?: boolean } = {}): Promise<RuntimeBackendCapability[] | null> {
    if (!options.forceRefresh && capabilitiesCache) {
      return cloneRuntimeBackendCapabilities(capabilitiesCache)
    }

    try {
      const res = await get('/capabilities')
      if (res.statusCode !== 200) {
        invalidateCapabilitiesCache()
        return null
      }
      const capabilities = parseRuntimeBackendCapabilities(res.body)
      if (!capabilities) {
        invalidateCapabilitiesCache()
        return null
      }
      replaceCapabilitiesCache(capabilities)
      return cloneRuntimeBackendCapabilities(capabilities)
    } catch (err) {
      invalidateCapabilitiesCache()
      logger.debug({ err }, 'Runtime capability discovery failed')
      return null
    }
  }

  async function validateRuntimeBackendHint(
    hint: RuntimeBackendHint,
    options: { forceRefresh?: boolean } = {},
  ): Promise<RuntimeBackendHintValidationResult> {
    const capabilities = await getCapabilities(options)
    if (!capabilities) {
      return { supported: null }
    }

    const capability = capabilities.find((entry) => entry.type === hint.type && entry.handler === hint.handler)
    return {
      supported: capability !== undefined,
      capability,
      capabilities,
    }
  }

  async function execute(
    req: RuntimeExecuteRequest,
    opts?: { onProgress?: (progress: number, message?: string) => void },
  ): Promise<RuntimeExecuteResponse> {
    if (req.runtimeBackendHint) {
      const validation = await validateRuntimeBackendHint(req.runtimeBackendHint)
      if (validation.supported === false) {
        if (validation.capabilities) {
          replaceCapabilitiesCache(validation.capabilities)
        }
        return {
          ok: false,
          taskId: req.taskId,
          errors: [`Unsupported runtime backend hint: ${req.runtimeBackendHint.type}/${req.runtimeBackendHint.handler}`],
          capabilities: validation.capabilities,
        }
      }
    }

    const submitRes = await post('/execute', req)
    const submitBody = JSON.parse(submitRes.body) as {
      ok?: boolean
      taskId?: string
      status?: string
      error?: string
      capabilities?: RuntimeBackendCapability[]
    }
    if (submitRes.statusCode !== 202 || !submitBody.ok) {
      const responseCapabilities = Array.isArray(submitBody.capabilities) ? submitBody.capabilities : null
      if (responseCapabilities) {
        replaceCapabilitiesCache(responseCapabilities)
      } else if (typeof submitBody.error === 'string' && submitBody.error.startsWith('Unsupported runtime backend hint:')) {
        invalidateCapabilitiesCache()
      }
      return {
        ok: false,
        taskId: req.taskId,
        errors: [submitBody.error || `Task submission failed: HTTP ${submitRes.statusCode}`],
        capabilities: responseCapabilities || undefined,
      }
    }

    const pollIntervalMs = 3000
    const maxWaitMs = req.timeoutMs + 30_000
    const started = Date.now()
    let hasReportedRunning = false

    while (Date.now() - started < maxWaitMs) {
      const statusRes = await get(`/tasks/${req.taskId}`)
      const statusBody = JSON.parse(statusRes.body) as {
        ok?: boolean
        status?: string
        result?: RuntimeExecuteResponse
        error?: string
        progressPercent?: number
        lastMessage?: string
      }
      if (!statusBody.ok) {
        return {
          ok: false,
          taskId: req.taskId,
          errors: [statusBody.error || 'Task status query failed'],
        }
      }
      if (statusBody.status === 'completed') {
        opts?.onProgress?.(1, statusBody.lastMessage || 'Runtime execution completed')
        return statusBody.result || { ok: false, taskId: req.taskId, errors: ['Task finished without a result'] }
      }
      if (statusBody.status === 'failed' || statusBody.status === 'cancelled') {
        opts?.onProgress?.(1, statusBody.lastMessage || `Runtime execution ${statusBody.status}`)
        return statusBody.result || { ok: false, taskId: req.taskId, errors: [`Task ${statusBody.status}`] }
      }
      if (statusBody.status === 'running') {
        if (typeof statusBody.progressPercent === 'number') {
          opts?.onProgress?.(statusBody.progressPercent, statusBody.lastMessage || 'Runtime running...')
        } else if (!hasReportedRunning) {
          opts?.onProgress?.(0, 'Task started on runtime node')
          hasReportedRunning = true
        }
      }
      await new Promise((r) => setTimeout(r, pollIntervalMs))
    }

    // Timeout exceeded — attempt cancellation and return error
    try {
      await post(`/tasks/${req.taskId}/cancel`, {})
    } catch {}
    return {
      ok: false,
      taskId: req.taskId,
      errors: [`Task timed out after ${maxWaitMs}ms`],
    }
  }

  function isLocalhost(urlStr: string): boolean {
    const u = new URL(urlStr)
    return u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '::1' || u.hostname === '[::1]'
  }

  function sanitizeRuntimeUploadName(value: string, fallback: string): string {
    const basename = path
      .basename((value || fallback).replace(/\\/g, '/'))
      .replace(/[<>:"|?*\x00-\x1f]/g, '_')
      .replace(/^\.+$/, '')
      .slice(0, 160)
    return basename || fallback
  }

  async function uploadSample(
    taskId: string,
    localSamplePath: string,
    inboxHostDir: string,
    options: RuntimeUploadOptions = {},
  ): Promise<void> {
    const sidecars = options.sidecars || []
    const primaryFilename = options.preserveFilename === false
      ? `${taskId}.sample`
      : path.basename(localSamplePath) || `${taskId}.sample`
    if (isLocalhost(endpoint)) {
      const destDir = path.join(inboxHostDir, taskId)
      await fs.promises.mkdir(destDir, { recursive: true })
      const destPath = path.join(destDir, sanitizeRuntimeUploadName(primaryFilename, `${taskId}.sample`))
      await fs.promises.copyFile(localSamplePath, destPath)
      const legacyPath = path.join(inboxHostDir, `${taskId}.sample`)
      await fs.promises.copyFile(localSamplePath, legacyPath)
      const manifestFiles: Array<{ name: string; role: 'primary' | 'sidecar'; size: number; uploadedAt: string }> = [{
        name: path.basename(destPath),
        role: 'primary',
        size: (await fs.promises.stat(destPath)).size,
        uploadedAt: new Date().toISOString(),
      }]
      for (const sidecar of sidecars) {
        const name = sanitizeRuntimeUploadName(sidecar.name || path.basename(sidecar.path), 'sidecar.bin')
        const sidecarDest = path.join(destDir, name)
        await fs.promises.copyFile(sidecar.path, sidecarDest)
        manifestFiles.push({
          name,
          role: 'sidecar',
          size: (await fs.promises.stat(sidecarDest)).size,
          uploadedAt: new Date().toISOString(),
        })
      }
      await fs.promises.writeFile(
        path.join(destDir, 'upload-manifest.json'),
        JSON.stringify({
          schema: 'rikune.runtime_upload_manifest.v1',
          taskId,
          primary: path.basename(destPath),
          files: manifestFiles,
        }, null, 2),
        'utf8',
      )
      return
    }
    await uploadRuntimeFile(taskId, localSamplePath, primaryFilename, 'primary')
    if (sidecars.length === 0) {
      return
    }

    const runtimeHealth = await health()
    if (runtimeHealth?.features?.sidecarUpload !== true) {
      logger.warn({ taskId, endpoint, sidecarCount: sidecars.length }, 'Runtime node does not advertise sidecar upload support; skipping sidecars')
      return
    }

    for (const sidecar of sidecars) {
      await uploadRuntimeFile(taskId, sidecar.path, sidecar.name || path.basename(sidecar.path), 'sidecar')
    }
  }

  async function uploadRuntimeFile(taskId: string, localPath: string, filename: string, role: 'primary' | 'sidecar'): Promise<void> {
    const url = new URL('/upload', endpoint)
    url.searchParams.set('taskId', taskId)
    url.searchParams.set('filename', sanitizeRuntimeUploadName(filename, role === 'primary' ? `${taskId}.sample` : 'sidecar.bin'))
    url.searchParams.set('role', role)
    const stat = fs.statSync(localPath)
    const stream = fs.createReadStream(localPath)
    await new Promise<void>((resolve, reject) => {
      const req = http.request(
        {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + url.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': stat.size.toString(),
            ...(apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}),
          },
          timeout: 120_000,
        },
        (res) => {
          const chunks: Buffer[] = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => {
            const body = Buffer.concat(chunks).toString('utf-8')
            if (res.statusCode === 200) {
              resolve()
            } else {
              reject(new Error(`Upload failed: HTTP ${res.statusCode}, ${body}`))
            }
          })
        },
      )
      req.on('error', reject)
      req.on('timeout', () => {
        req.destroy()
        reject(new Error('Upload timeout'))
      })
      stream.pipe(req)
    })
  }

  async function downloadArtifacts(taskId: string, outboxHostDir: string, artifactNames: string[]): Promise<string[]> {
    if (isLocalhost(endpoint)) {
      const downloaded: string[] = []
      for (const name of artifactNames) {
        const src = path.join(outboxHostDir, taskId, name)
        if (fs.existsSync(src)) {
          downloaded.push(src)
        }
      }
      return downloaded
    }
    const downloaded: string[] = []
    const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rikune-runtime-'))
    for (const name of artifactNames) {
      const url = new URL(`/download/${encodeURIComponent(taskId)}/${encodeURIComponent(name)}`, endpoint)
      const destPath = path.join(tempDir, `${taskId}_${name}`)
      try {
        await downloadFile(url, destPath)
        downloaded.push(destPath)
      } catch (err) {
        logger.warn({ taskId, name, err }, 'Failed to download artifact from runtime')
      }
    }
    return downloaded
  }

  async function downloadFile(url: URL, destPath: string): Promise<void> {
    const file = fs.createWriteStream(destPath)
    await new Promise<void>((resolve, reject) => {
      const req = http.get(
        {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + url.search,
          headers: apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {},
          timeout: 60_000,
        },
        (res) => {
          if (res.statusCode !== 200) {
            res.resume()
            reject(new Error(`Download failed: HTTP ${res.statusCode}`))
            return
          }
          res.pipe(file)
          file.on('finish', () => {
            file.close()
            resolve()
          })
        },
      )
      req.on('error', reject)
      req.on('timeout', () => {
        req.destroy()
        reject(new Error('Download timeout'))
      })
    })
  }

  function get(path: string): Promise<{ statusCode: number; body: string }> {
    return request('GET', path)
  }

  function subscribeEvents(options: RuntimeEventStreamOptions): RuntimeEventSubscription {
    const url = new URL('/events', endpoint)
    if (options.taskId) {
      url.searchParams.set('taskId', options.taskId)
    }

    let closed = false
    let buffer = ''
    let currentEvent = 'message'
    let currentId: string | undefined
    let dataLines: string[] = []

    const dispatchEvent = () => {
      if (dataLines.length === 0) {
        currentEvent = 'message'
        currentId = undefined
        return
      }

      const payloadText = dataLines.join('\n')
      let payload: unknown = payloadText
      try {
        payload = JSON.parse(payloadText)
      } catch {
        payload = payloadText
      }

      options.onEvent({
        event: currentEvent,
        id: currentId,
        data: payload,
      })

      currentEvent = 'message'
      currentId = undefined
      dataLines = []
    }

    const processBuffer = () => {
      while (true) {
        const newlineIndex = buffer.indexOf('\n')
        if (newlineIndex < 0) {
          return
        }

        let line = buffer.slice(0, newlineIndex)
        buffer = buffer.slice(newlineIndex + 1)
        if (line.endsWith('\r')) {
          line = line.slice(0, -1)
        }

        if (!line) {
          dispatchEvent()
          continue
        }

        if (line.startsWith(':')) {
          continue
        }

        if (line.startsWith('event:')) {
          currentEvent = line.slice('event:'.length).trim() || 'message'
          continue
        }

        if (line.startsWith('id:')) {
          currentId = line.slice('id:'.length).trim() || undefined
          continue
        }

        if (line.startsWith('data:')) {
          dataLines.push(line.slice('data:'.length).trimStart())
        }
      }
    }

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'GET',
        headers: {
          Accept: 'text/event-stream',
          ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
        },
        timeout: 30000,
      },
      (res) => {
        if (res.statusCode !== 200) {
          const err = new Error(`Runtime events subscription failed: HTTP ${res.statusCode}`)
          res.resume()
          options.onError?.(err)
          return
        }

        options.onOpen?.()
        res.setEncoding('utf8')
        res.on('data', (chunk: string) => {
          buffer += chunk
          processBuffer()
        })
        res.on('end', () => {
          if (!closed) {
            dispatchEvent()
            options.onError?.(new Error('Runtime events stream ended unexpectedly'))
          }
        })
        res.on('error', (error) => {
          if (!closed) {
            options.onError?.(error instanceof Error ? error : new Error(String(error)))
          }
        })
      },
    )

    req.on('error', (error) => {
      if (!closed) {
        options.onError?.(error instanceof Error ? error : new Error(String(error)))
      }
    })
    req.on('timeout', () => {
      req.destroy(new Error('Runtime events subscription timed out'))
    })
    req.end()

    return {
      close() {
        closed = true
        req.destroy()
      },
    }
  }

  function post(path: string, body: unknown): Promise<{ statusCode: number; body: string }> {
    return request('POST', path, body)
  }

  function request(method: string, path: string, body?: unknown): Promise<{ statusCode: number; body: string }> {
    return new Promise((resolve, reject) => {
      const url = new URL(path, endpoint)
      const headers: Record<string, string> = {
        'Accept': 'application/json',
      }
      if (apiKey) {
        headers['Authorization'] = `Bearer ${apiKey}`
      }

      let payload: string | undefined
      if (body !== undefined) {
        payload = JSON.stringify(body)
        headers['Content-Type'] = 'application/json'
        headers['Content-Length'] = Buffer.byteLength(payload).toString()
      }

      const req = http.request(
        {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + url.search,
          method,
          headers,
          timeout: 30000,
        },
        (res) => {
          const chunks: Buffer[] = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => {
            resolve({ statusCode: res.statusCode || 0, body: Buffer.concat(chunks).toString('utf-8') })
          })
        },
      )

      req.on('error', reject)
      req.on('timeout', () => {
        req.destroy()
        reject(new Error('Request timeout'))
      })

      if (payload) {
        req.write(payload)
      }
      req.end()
    })
  }

  return {
    health,
    getCapabilities,
    validateRuntimeBackendHint,
    execute,
    uploadSample,
    downloadArtifacts,
    invalidateCapabilitiesCache,
    setEndpoint,
    getEndpoint,
    subscribeEvents,
    recover: undefined as (() => Promise<boolean>) | undefined,
  }
}
