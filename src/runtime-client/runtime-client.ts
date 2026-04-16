/**
 * Analyzer-side HTTP client for communicating with the Runtime node.
 */

import http from 'http'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { logger } from '../logger.js'
import type { WorkerResult, ArtifactRef, RuntimeBackendHint } from '../plugins/sdk.js'

export interface RuntimeExecuteRequest {
  taskId: string
  sampleId: string
  tool: string
  args: Record<string, unknown>
  timeoutMs: number
  sampleInboxPath?: string
  runtimeBackendHint?: RuntimeBackendHint
}

export interface RuntimeExecuteResponse {
  ok: boolean
  taskId: string
  result?: WorkerResult
  artifactRefs?: { name: string; path: string }[]
  logs?: string[]
  errors?: string[]
}

export interface RuntimeHealthResponse {
  ok: boolean
  role: string
  isolation: string
  mode: string
  pid: number
}

export interface RuntimeClientOptions {
  endpoint: string
  apiKey?: string
  healthCheckTimeoutMs?: number
}

export function createRuntimeClient(options: RuntimeClientOptions) {
  let endpoint = options.endpoint
  const apiKey = options.apiKey

  function setEndpoint(newEndpoint: string) {
    endpoint = newEndpoint
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

  async function execute(
    req: RuntimeExecuteRequest,
    opts?: { onProgress?: (progress: number, message?: string) => void },
  ): Promise<RuntimeExecuteResponse> {
    const submitRes = await post('/execute', req)
    const submitBody = JSON.parse(submitRes.body) as { ok?: boolean; taskId?: string; status?: string; error?: string }
    if (submitRes.statusCode !== 202 || !submitBody.ok) {
      return {
        ok: false,
        taskId: req.taskId,
        errors: [submitBody.error || `Task submission failed: HTTP ${submitRes.statusCode}`],
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

  async function uploadSample(taskId: string, localSamplePath: string, inboxHostDir: string): Promise<void> {
    if (isLocalhost(endpoint)) {
      const destDir = inboxHostDir
      await fs.promises.mkdir(destDir, { recursive: true })
      const destPath = path.join(destDir, `${taskId}.sample`)
      await fs.promises.copyFile(localSamplePath, destPath)
      return
    }
    const url = new URL(`/upload?taskId=${encodeURIComponent(taskId)}`, endpoint)
    const stat = fs.statSync(localSamplePath)
    const stream = fs.createReadStream(localSamplePath)
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

  return { health, execute, uploadSample, downloadArtifacts, setEndpoint, recover: undefined as (() => Promise<boolean>) | undefined }
}
