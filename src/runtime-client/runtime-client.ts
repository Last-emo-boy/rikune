/**
 * Analyzer-side HTTP client for communicating with the Runtime node.
 */

import http from 'http'
import https from 'https'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { logger } from '../logger.js'
import type {
  ArtifactRef,
  RuntimeBackendCapability,
  RuntimeSseEvent,
  RuntimeTaskSnapshot,
  ToolRuntimeContract,
  TrustedLookupResolver,
  WorkerResult,
} from '@rikune/shared'
import {
  assertTrustedHttpEndpoint,
  createTrustedLookup,
  RuntimeBackendCapabilitySchema,
  findRuntimeBackendCapability,
} from '@rikune/shared'
import { validateRuntimeEndpointFromHostAgent } from '../infrastructure/trusted-runtime-endpoint.js'
import type { RuntimeSidecarUpload } from './sidecar-staging.js'

export type { RuntimeBackendCapability } from '@rikune/shared'
export type { RuntimeSseEvent, RuntimeTaskSnapshot } from '@rikune/shared'

export interface RuntimeContractValidationResult {
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
  runtime?: ToolRuntimeContract
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
  /** Resolver used by every new raw HTTP/TLS socket for this client. */
  resolveEndpointAddresses?: TrustedLookupResolver
}

/**
 * Provenance supplied by an internal recovery path when a runtime rotates to
 * a new listener. The parent endpoint must already be trusted by that path.
 */
export interface RuntimeEndpointUpdateOptions {
  trustedParentEndpoint?: string
  /** Backend asserted by a response from the trusted Host Agent. */
  trustedHostAgentBackend?: string
  /** Provenance from the local Windows Sandbox launcher; host/IP may rotate. */
  trustedLocalSandboxLaunch?: boolean
}

function cloneRuntimeBackendCapabilities(
  capabilities: RuntimeBackendCapability[]
): RuntimeBackendCapability[] {
  return capabilities.map((capability) => {
    const clone: RuntimeBackendCapability = { ...capability }
    if (capability.modes) clone.modes = [...capability.modes]
    if (capability.requiredProfiles) clone.requiredProfiles = [...capability.requiredProfiles]
    if (capability.requiredTools) clone.requiredTools = [...capability.requiredTools]
    if (capability.optionalTools) clone.optionalTools = [...capability.optionalTools]
    if (capability.produces) clone.produces = [...capability.produces]
    if (capability.capabilities) clone.capabilities = [...capability.capabilities]
    if (capability.safety) clone.safety = [...capability.safety]
    if (capability.policy) {
      clone.policy = { ...capability.policy }
      if (capability.policy.allowedBackends) {
        clone.policy.allowedBackends = [...capability.policy.allowedBackends]
      }
      if (capability.policy.notes) {
        clone.policy.notes = [...capability.policy.notes]
      }
    }
    if (capability.isolation) {
      clone.isolation = { ...capability.isolation }
      if (capability.isolation.backends) {
        clone.isolation.backends = [...capability.isolation.backends]
      }
    }
    if (capability.fallback) {
      clone.fallback = capability.fallback.map((entry) => ({ ...entry }))
    }
    return clone
  })
}

function parseRuntimeBackendCapabilityEntries(entries: unknown): RuntimeBackendCapability[] | null {
  if (!Array.isArray(entries)) {
    return null
  }

  const capabilities: RuntimeBackendCapability[] = []
  for (const entry of entries) {
    const parsed = RuntimeBackendCapabilitySchema.safeParse(entry)
    if (
      !parsed.success ||
      typeof parsed.data.description !== 'string' ||
      typeof parsed.data.requiresSample !== 'boolean'
    ) {
      return null
    }
    capabilities.push(parsed.data as RuntimeBackendCapability)
  }

  return capabilities
}

function parseRuntimeBackendCapabilities(body: string): RuntimeBackendCapability[] | null {
  try {
    const payload = JSON.parse(body) as {
      ok?: unknown
      data?: {
        runtime_backends?: unknown
      }
    }
    if (payload?.ok !== true) {
      return null
    }
    return parseRuntimeBackendCapabilityEntries(payload.data?.runtime_backends)
  } catch (err) {
    logger.debug({ err }, 'Runtime capabilities response parsing failed')
    return null
  }
}

function validateRuntimePathSegment(value: unknown, label: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value === '.' ||
    value === '..' ||
    value.includes('\0') ||
    value.includes('/') ||
    value.includes('\\') ||
    path.posix.isAbsolute(value) ||
    path.win32.isAbsolute(value)
  ) {
    throw new Error(`Invalid runtime ${label}: expected a non-empty path segment`)
  }
  return value
}

function assertPathWithinDirectory(rootPath: string, candidatePath: string): void {
  const relativePath = path.relative(path.resolve(rootPath), path.resolve(candidatePath))
  if (
    relativePath.length === 0 ||
    relativePath === '..' ||
    relativePath.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativePath)
  ) {
    throw new Error('Resolved runtime artifact path escapes its expected directory')
  }
}

function getRequestHostname(url: URL): string {
  const { hostname } = url
  return hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname
}

export function createRuntimeClient(options: RuntimeClientOptions) {
  // Validate before retaining the endpoint or allowing the API key to reach
  // any request sink. Private/LAN addresses remain valid; metadata and
  // unspecified addresses are rejected by the shared policy.
  assertTrustedHttpEndpoint(options.endpoint, { label: 'runtime endpoint' })
  let endpoint = options.endpoint.trim()
  const apiKey = options.apiKey
  const trustedLookup = createTrustedLookup(options.resolveEndpointAddresses)
  const httpAgent = new http.Agent({ keepAlive: true, lookup: trustedLookup })
  const httpsAgent = new https.Agent({ keepAlive: true, lookup: trustedLookup })
  let capabilitiesCache: RuntimeBackendCapability[] | null = null

  function replaceCapabilitiesCache(capabilities: RuntimeBackendCapability[] | null) {
    capabilitiesCache = capabilities ? cloneRuntimeBackendCapabilities(capabilities) : null
  }

  function invalidateCapabilitiesCache() {
    replaceCapabilitiesCache(null)
  }

  function setEndpoint(newEndpoint: string, updateOptions: RuntimeEndpointUpdateOptions = {}) {
    if (updateOptions.trustedLocalSandboxLaunch === true) {
      const parsed = assertTrustedHttpEndpoint(newEndpoint, { label: 'runtime endpoint' })
      if (parsed.url.protocol !== 'http:') {
        throw new Error('Local Windows Sandbox runtime endpoints must use http.')
      }
    } else if (updateOptions.trustedParentEndpoint) {
      validateRuntimeEndpointFromHostAgent(
        newEndpoint,
        updateOptions.trustedParentEndpoint,
        updateOptions.trustedHostAgentBackend,
        'runtime endpoint'
      )
    } else if (apiKey) {
      // Without explicit provenance, a keyed client cannot move its
      // credentials across origins, including to another port.
      assertTrustedHttpEndpoint(newEndpoint, {
        label: 'runtime endpoint',
        configuredEndpoint: endpoint,
        credentialSource: 'configured',
      })
    } else {
      assertTrustedHttpEndpoint(newEndpoint, { label: 'runtime endpoint' })
    }
    endpoint = newEndpoint.trim()
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

  async function getCapabilities(
    options: { forceRefresh?: boolean } = {}
  ): Promise<RuntimeBackendCapability[] | null> {
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

  async function validateRuntimeContract(
    contract: ToolRuntimeContract,
    options: { forceRefresh?: boolean } = {}
  ): Promise<RuntimeContractValidationResult> {
    const capabilities = await getCapabilities(options)
    if (!capabilities) {
      return { supported: null }
    }

    const capability = findRuntimeBackendCapability(capabilities, contract)
    return {
      supported: capability !== undefined,
      capability,
      capabilities,
    }
  }

  async function execute(
    req: RuntimeExecuteRequest,
    opts?: { onProgress?: (progress: number, message?: string) => void }
  ): Promise<RuntimeExecuteResponse> {
    if (req.runtime) {
      const validation = await validateRuntimeContract(req.runtime)
      if (validation.supported === false) {
        if (validation.capabilities) {
          replaceCapabilitiesCache(validation.capabilities)
        }
        return {
          ok: false,
          taskId: req.taskId,
          errors: [`Unsupported runtime contract: ${req.runtime.type}/${req.runtime.handler}`],
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
      capabilities?: unknown
    }
    if (submitRes.statusCode !== 202 || !submitBody.ok) {
      const hasResponseCapabilities = submitBody.capabilities !== undefined
      const responseCapabilities = hasResponseCapabilities
        ? parseRuntimeBackendCapabilityEntries(submitBody.capabilities)
        : null
      if (hasResponseCapabilities) {
        if (responseCapabilities) {
          replaceCapabilitiesCache(responseCapabilities)
        } else {
          invalidateCapabilitiesCache()
        }
      } else if (
        typeof submitBody.error === 'string' &&
        submitBody.error.startsWith('Unsupported runtime contract:')
      ) {
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
      const statusBody = JSON.parse(statusRes.body) as RuntimeTaskSnapshot & {
        ok?: boolean
        result?: RuntimeExecuteResponse
        error?: string
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
        return (
          statusBody.result || {
            ok: false,
            taskId: req.taskId,
            errors: ['Task finished without a result'],
          }
        )
      }
      if (statusBody.status === 'failed' || statusBody.status === 'cancelled') {
        opts?.onProgress?.(1, statusBody.lastMessage || `Runtime execution ${statusBody.status}`)
        return (
          statusBody.result || {
            ok: false,
            taskId: req.taskId,
            errors: [`Task ${statusBody.status}`],
          }
        )
      }
      if (statusBody.status === 'running') {
        if (typeof statusBody.progressPercent === 'number') {
          opts?.onProgress?.(
            statusBody.progressPercent,
            statusBody.lastMessage || 'Runtime running...'
          )
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
    return (
      u.hostname === '127.0.0.1' ||
      u.hostname === 'localhost' ||
      u.hostname === '::1' ||
      u.hostname === '[::1]'
    )
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
    options: RuntimeUploadOptions = {}
  ): Promise<void> {
    const sidecars = options.sidecars || []
    const primaryFilename =
      options.preserveFilename === false
        ? `${taskId}.sample`
        : path.basename(localSamplePath) || `${taskId}.sample`
    if (isLocalhost(endpoint)) {
      const destDir = path.join(inboxHostDir, taskId)
      await fs.promises.mkdir(destDir, { recursive: true })
      const destPath = path.join(
        destDir,
        sanitizeRuntimeUploadName(primaryFilename, `${taskId}.sample`)
      )
      await fs.promises.copyFile(localSamplePath, destPath)
      const legacyPath = path.join(inboxHostDir, `${taskId}.sample`)
      await fs.promises.copyFile(localSamplePath, legacyPath)
      const manifestFiles: Array<{
        name: string
        role: 'primary' | 'sidecar'
        size: number
        uploadedAt: string
      }> = [
        {
          name: path.basename(destPath),
          role: 'primary',
          size: (await fs.promises.stat(destPath)).size,
          uploadedAt: new Date().toISOString(),
        },
      ]
      for (const sidecar of sidecars) {
        const name = sanitizeRuntimeUploadName(
          sidecar.name || path.basename(sidecar.path),
          'sidecar.bin'
        )
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
        JSON.stringify(
          {
            schema: 'rikune.runtime_upload_manifest.v1',
            taskId,
            primary: path.basename(destPath),
            files: manifestFiles,
          },
          null,
          2
        ),
        'utf8'
      )
      return
    }
    await uploadRuntimeFile(taskId, localSamplePath, primaryFilename, 'primary')
    if (sidecars.length === 0) {
      return
    }

    const runtimeHealth = await health()
    if (runtimeHealth?.features?.sidecarUpload !== true) {
      logger.warn(
        { taskId, endpoint, sidecarCount: sidecars.length },
        'Runtime node does not advertise sidecar upload support; skipping sidecars'
      )
      return
    }

    for (const sidecar of sidecars) {
      await uploadRuntimeFile(
        taskId,
        sidecar.path,
        sidecar.name || path.basename(sidecar.path),
        'sidecar'
      )
    }
  }

  async function uploadRuntimeFile(
    taskId: string,
    localPath: string,
    filename: string,
    role: 'primary' | 'sidecar'
  ): Promise<void> {
    const url = new URL('/upload', endpoint)
    url.searchParams.set('taskId', taskId)
    url.searchParams.set(
      'filename',
      sanitizeRuntimeUploadName(filename, role === 'primary' ? `${taskId}.sample` : 'sidecar.bin')
    )
    url.searchParams.set('role', role)
    const stat = fs.statSync(localPath)
    const stream = fs.createReadStream(localPath)
    await new Promise<void>((resolve, reject) => {
      const transport = url.protocol === 'https:' ? https : http
      const req = transport.request(
        {
          hostname: getRequestHostname(url),
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + url.search,
          agent: url.protocol === 'https:' ? httpsAgent : httpAgent,
          lookup: trustedLookup,
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': stat.size.toString(),
            ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
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
        }
      )
      req.on('error', reject)
      req.on('timeout', () => {
        req.destroy()
        reject(new Error('Upload timeout'))
      })
      stream.pipe(req)
    })
  }

  async function downloadArtifacts(
    taskId: string,
    outboxHostDir: string,
    artifactNames: string[]
  ): Promise<string[]> {
    if (!Array.isArray(artifactNames)) {
      throw new Error('Invalid runtime artifact names: expected an array of basenames')
    }
    const validatedTaskId = validateRuntimePathSegment(taskId, 'task ID')
    const validatedArtifactNames: string[] = []
    for (const name of artifactNames as unknown[]) {
      validatedArtifactNames.push(validateRuntimePathSegment(name, 'artifact name'))
    }

    if (isLocalhost(endpoint)) {
      const downloaded: string[] = []
      const taskOutboxDir = path.join(outboxHostDir, validatedTaskId)
      assertPathWithinDirectory(outboxHostDir, taskOutboxDir)
      let taskOutboxStat: fs.Stats
      try {
        taskOutboxStat = await fs.promises.lstat(taskOutboxDir)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
          return downloaded
        }
        throw error
      }
      if (!taskOutboxStat.isDirectory() || taskOutboxStat.isSymbolicLink()) {
        throw new Error('Runtime task outbox must be a real directory, not a symbolic link')
      }

      const [outboxRealPath, taskOutboxRealPath] = await Promise.all([
        fs.promises.realpath(outboxHostDir),
        fs.promises.realpath(taskOutboxDir),
      ])
      assertPathWithinDirectory(outboxRealPath, taskOutboxRealPath)

      for (const name of validatedArtifactNames) {
        const src = path.join(taskOutboxDir, name)
        assertPathWithinDirectory(taskOutboxDir, src)
        let sourceStat: fs.Stats
        try {
          sourceStat = await fs.promises.lstat(src)
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
            continue
          }
          throw error
        }
        if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) {
          throw new Error('Runtime artifact must be a real file, not a symbolic link')
        }
        const sourceRealPath = await fs.promises.realpath(src)
        assertPathWithinDirectory(taskOutboxRealPath, sourceRealPath)
        downloaded.push(sourceRealPath)
      }
      return downloaded
    }
    const downloaded: string[] = []
    const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rikune-runtime-'))
    const downloadTargets = validatedArtifactNames.map((name) => {
      const destPath = path.join(tempDir, `${validatedTaskId}_${name}`)
      assertPathWithinDirectory(tempDir, destPath)
      return {
        name,
        url: new URL(
          `/download/${encodeURIComponent(validatedTaskId)}/${encodeURIComponent(name)}`,
          endpoint
        ),
        destPath,
      }
    })
    for (const { name, url, destPath } of downloadTargets) {
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
      const transport = url.protocol === 'https:' ? https : http
      const req = transport.get(
        {
          hostname: getRequestHostname(url),
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + url.search,
          agent: url.protocol === 'https:' ? httpsAgent : httpAgent,
          lookup: trustedLookup,
          headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {},
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
        }
      )
      req.on('error', reject)
      req.on('timeout', () => {
        req.destroy()
        reject(new Error('Download timeout'))
      })
    })
  }

  async function close(): Promise<void> {
    httpAgent.destroy()
    httpsAgent.destroy()
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

    const transport = url.protocol === 'https:' ? https : http
    const req = transport.request(
      {
        hostname: getRequestHostname(url),
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        agent: url.protocol === 'https:' ? httpsAgent : httpAgent,
        lookup: trustedLookup,
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
      }
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

  function request(
    method: string,
    path: string,
    body?: unknown
  ): Promise<{ statusCode: number; body: string }> {
    return new Promise((resolve, reject) => {
      const url = new URL(path, endpoint)
      const headers: Record<string, string> = {
        Accept: 'application/json',
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

      const transport = url.protocol === 'https:' ? https : http
      const req = transport.request(
        {
          hostname: getRequestHostname(url),
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + url.search,
          agent: url.protocol === 'https:' ? httpsAgent : httpAgent,
          lookup: trustedLookup,
          method,
          headers,
          timeout: 30000,
        },
        (res) => {
          const chunks: Buffer[] = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode || 0,
              body: Buffer.concat(chunks).toString('utf-8'),
            })
          })
        }
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
    validateRuntimeContract,
    execute,
    uploadSample,
    downloadArtifacts,
    invalidateCapabilitiesCache,
    setEndpoint,
    getEndpoint,
    subscribeEvents,
    close,
    recover: undefined as (() => Promise<boolean>) | undefined,
  }
}
