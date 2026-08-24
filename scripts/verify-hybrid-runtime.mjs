#!/usr/bin/env node

import { randomUUID } from 'node:crypto'
import path from 'node:path'
import process from 'node:process'
import { setTimeout } from 'node:timers'
import { fileURLToPath, URL } from 'node:url'

const STRONG_API_KEY_PATTERN = /^[\x21-\x7e]{32,}$/u
const START_REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu
const START_REQUEST_CORRELATION = 'request-id-v2'
const START_CLEANUP_TIMEOUT_MS = 30_000
const DEFAULT_START_CLIENT_BUFFER_MS = 15_000
const DEFAULT_STOP_SERVER_TIMEOUT_MS = 120_000
const DEFAULT_STOP_CLIENT_BUFFER_MS = 15_000
const MAX_TIMEOUT_MS = 2_147_483_647
const LOCAL_RUNTIME_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', 'host.docker.internal'])

class RequestTransportError extends Error {}

function requireTimeoutMs(name, value, minimum = 1) {
  if (!Number.isSafeInteger(value) || value < minimum || value > MAX_TIMEOUT_MS) {
    throw new Error(`${name} must be an integer between ${minimum} and ${MAX_TIMEOUT_MS}`)
  }
  return value
}

export function resolveHybridTimeoutContract({
  requestTimeoutMs = 30_000,
  startServerTimeoutMs = requestTimeoutMs,
  startClientBufferMs = DEFAULT_START_CLIENT_BUFFER_MS,
  stopServerTimeoutMs = DEFAULT_STOP_SERVER_TIMEOUT_MS,
  stopClientBufferMs = DEFAULT_STOP_CLIENT_BUFFER_MS,
} = {}) {
  const request = requireTimeoutMs('requestTimeoutMs', requestTimeoutMs)
  const server = requireTimeoutMs('startServerTimeoutMs', startServerTimeoutMs, 1_000)
  const buffer = requireTimeoutMs('startClientBufferMs', startClientBufferMs)
  const stopServer = requireTimeoutMs('stopServerTimeoutMs', stopServerTimeoutMs, 1_000)
  const stopBuffer = requireTimeoutMs('stopClientBufferMs', stopClientBufferMs)
  const startClientDeadlineMs = server + START_CLEANUP_TIMEOUT_MS + buffer + 1
  const stopClientDeadlineMs = stopServer + stopBuffer + 1
  if (!Number.isSafeInteger(startClientDeadlineMs) || startClientDeadlineMs > MAX_TIMEOUT_MS) {
    throw new Error('Hybrid start timeout contract exceeds the supported client deadline')
  }
  if (!Number.isSafeInteger(stopClientDeadlineMs) || stopClientDeadlineMs > MAX_TIMEOUT_MS) {
    throw new Error('Hybrid stop timeout contract exceeds the supported client deadline')
  }
  return {
    requestTimeoutMs: request,
    startServerTimeoutMs: server,
    startServerExecutionBudgetMs: server,
    startCleanupTimeoutMs: START_CLEANUP_TIMEOUT_MS,
    startClientBufferMs: buffer,
    startClientDeadlineMs,
    stopServerTimeoutMs: stopServer,
    stopClientBufferMs: stopBuffer,
    stopClientDeadlineMs,
  }
}

function requireStrongApiKey(name, value) {
  const normalized = String(value || '').trim()
  if (!STRONG_API_KEY_PATTERN.test(normalized)) {
    throw new Error(`${name} must contain at least 32 printable non-space ASCII characters`)
  }
  return normalized
}

function parseBoolean(value) {
  return /^(1|true|yes|on)$/iu.test(String(value || ''))
}

function requireEndpoint(name, value, allowInsecureRuntimeHttp) {
  let endpoint
  try {
    endpoint = new URL(String(value || ''))
  } catch {
    throw new Error(`${name} must be an absolute HTTP(S) URL`)
  }
  if (endpoint.username || endpoint.password) {
    throw new Error(`${name} must not contain URL userinfo credentials`)
  }
  if (endpoint.protocol === 'https:') return endpoint
  if (endpoint.protocol !== 'http:') {
    throw new Error(`${name} must use HTTP or HTTPS`)
  }
  if (!LOCAL_RUNTIME_HOSTS.has(endpoint.hostname) && !allowInsecureRuntimeHttp) {
    throw new Error(`${name} plaintext HTTP requires explicit isolated-network opt-in`)
  }
  return endpoint
}

function endpointPath(endpoint, suffix) {
  const base = new URL(endpoint.href)
  base.pathname = `${base.pathname.replace(/\/+$/u, '')}/${suffix.replace(/^\/+/, '')}`
  base.search = ''
  base.hash = ''
  return base.href
}

async function requestJson({
  fetchImpl,
  createTimeoutSignal,
  url,
  label,
  apiKey,
  method = 'GET',
  body,
  timeoutMs,
}) {
  let response
  try {
    response = await fetchImpl(url, {
      method,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/json',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: createTimeoutSignal(timeoutMs),
    })
  } catch {
    throw new RequestTransportError(`${label} request failed`)
  }
  if (!response?.ok) {
    throw new Error(`${label} returned HTTP ${Number(response?.status) || 0}`)
  }
  try {
    const payload = await response.json()
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('invalid payload')
    }
    return payload
  } catch {
    throw new Error(`${label} returned invalid JSON`)
  }
}

function requireCorrelatedSandboxes(health, label) {
  if (health?.sandboxStartRequestCorrelation !== START_REQUEST_CORRELATION) {
    throw new Error(`${label} does not support ${START_REQUEST_CORRELATION}`)
  }
  if (
    health?.sandboxStartContract?.timeoutScope !== 'absolute-start-deadline' ||
    health?.sandboxStartContract?.cleanupTimeoutMs !== START_CLEANUP_TIMEOUT_MS ||
    health?.sandboxStartContract?.statusPath !== '/sandbox/start/status'
  ) {
    throw new Error(`${label} returned an incompatible sandbox start deadline contract`)
  }
  if (health?.sandboxStopContract?.timeoutScope !== 'absolute-stop-deadline') {
    throw new Error(`${label} returned an incompatible sandbox stop deadline contract`)
  }
  if (!Array.isArray(health.sandboxes)) {
    throw new Error(`${label} returned an invalid sandboxes contract`)
  }
  return health.sandboxes.map((sandbox) => {
    if (
      !sandbox ||
      typeof sandbox !== 'object' ||
      Array.isArray(sandbox) ||
      typeof sandbox.sandboxId !== 'string' ||
      sandbox.sandboxId.trim().length === 0 ||
      typeof sandbox.requestId !== 'string' ||
      sandbox.requestId.trim().length === 0
    ) {
      throw new Error(`${label} returned an invalid correlated sandbox record`)
    }
    return {
      sandboxId: sandbox.sandboxId.trim(),
      requestId: sandbox.requestId.trim(),
    }
  })
}

async function waitUntilDeadline(deadlineMs, nowImpl, sleepImpl) {
  const remainingMs = deadlineMs - nowImpl()
  if (remainingMs > 0) {
    await sleepImpl(remainingMs)
  }
}

async function requestStartStatus({
  fetchImpl,
  createTimeoutSignal,
  hostAgentEndpoint,
  hostAgentApiKey,
  requestId,
  requestTimeoutMs,
}) {
  const statusUrl = new URL(endpointPath(hostAgentEndpoint, 'sandbox/start/status'))
  statusUrl.searchParams.set('requestId', requestId)
  const status = await requestJson({
    fetchImpl,
    createTimeoutSignal,
    url: statusUrl.href,
    label: 'Host Agent sandbox start status',
    apiKey: hostAgentApiKey,
    timeoutMs: requestTimeoutMs,
  })
  if (
    status.ok !== true ||
    status.requestId !== requestId ||
    !['pending', 'active', 'settled', 'unknown'].includes(status.state)
  ) {
    throw new Error('Host Agent returned an invalid sandbox start status contract')
  }
  if (
    status.state === 'active' &&
    (typeof status.sandboxId !== 'string' || status.sandboxId.trim().length === 0)
  ) {
    throw new Error('Host Agent returned an active start status without sandboxId')
  }
  return status
}

async function stopCorrelatedSandbox({
  fetchImpl,
  createTimeoutSignal,
  sleepImpl,
  nowImpl,
  hostAgentEndpoint,
  hostAgentApiKey,
  requestId,
  sandboxId,
  timeoutContract,
}) {
  let lastStopError
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const stopSettlementDeadlineMs = nowImpl() + timeoutContract.stopClientDeadlineMs
    let waitForStopSettlement = false
    try {
      const stopped = await requestJson({
        fetchImpl,
        createTimeoutSignal,
        url: endpointPath(hostAgentEndpoint, 'sandbox/stop'),
        label: 'Sandbox stop',
        apiKey: hostAgentApiKey,
        method: 'POST',
        body: {
          sandboxId,
          requestId,
          timeoutMs: timeoutContract.stopServerTimeoutMs,
        },
        timeoutMs: timeoutContract.stopClientDeadlineMs,
      })
      if (stopped.ok !== true) {
        throw new Error('Sandbox stop did not report ok=true')
      }
    } catch (error) {
      lastStopError = error
      waitForStopSettlement = error instanceof RequestTransportError
    }
    if (waitForStopSettlement) {
      await waitUntilDeadline(stopSettlementDeadlineMs, nowImpl, sleepImpl)
    }

    const status = await requestStartStatus({
      fetchImpl,
      createTimeoutSignal,
      hostAgentEndpoint,
      hostAgentApiKey,
      requestId,
      requestTimeoutMs: timeoutContract.requestTimeoutMs,
    })
    if (status.state !== 'active') {
      return
    }
    sandboxId = status.sandboxId.trim()
    if (attempt < 2) {
      await sleepImpl(100)
    }
  }
  throw new AggregateError(
    lastStopError ? [lastStopError] : [],
    'Correlated sandbox remained active after stop reconciliation'
  )
}

async function reconcileAmbiguousStart({
  fetchImpl,
  createTimeoutSignal,
  sleepImpl,
  nowImpl,
  hostAgentEndpoint,
  hostAgentApiKey,
  requestId,
  timeoutContract,
}) {
  const settlementDeadlineMs = nowImpl() + timeoutContract.requestTimeoutMs
  let status = await requestStartStatus({
    fetchImpl,
    createTimeoutSignal,
    hostAgentEndpoint,
    hostAgentApiKey,
    requestId,
    requestTimeoutMs: timeoutContract.requestTimeoutMs,
  })
  while (status.state === 'pending') {
    const remainingMs = settlementDeadlineMs - nowImpl()
    if (remainingMs <= 0) {
      throw new Error('Sandbox start remained pending beyond its settlement contract')
    }
    await sleepImpl(Math.min(100, remainingMs))
    status = await requestStartStatus({
      fetchImpl,
      createTimeoutSignal,
      hostAgentEndpoint,
      hostAgentApiKey,
      requestId,
      requestTimeoutMs: timeoutContract.requestTimeoutMs,
    })
  }
  if (status.state === 'active') {
    await stopCorrelatedSandbox({
      fetchImpl,
      createTimeoutSignal,
      sleepImpl,
      nowImpl,
      hostAgentEndpoint,
      hostAgentApiKey,
      requestId,
      sandboxId: status.sandboxId.trim(),
      timeoutContract,
    })
  }
}

function validateRuntimeEndpoint({
  endpoint,
  hostAgentEndpoint,
  backend,
  allowInsecureRuntimeHttp,
}) {
  const runtimeEndpoint = requireEndpoint(
    'Runtime Node endpoint',
    endpoint,
    allowInsecureRuntimeHttp
  )
  if (backend === 'windows-sandbox') {
    const runtimePort = Number(runtimeEndpoint.port)
    if (!Number.isInteger(runtimePort) || runtimePort < 18081 || runtimePort > 19000) {
      throw new Error('Windows Sandbox Runtime Node endpoint uses an unexpected port')
    }
    if (
      LOCAL_RUNTIME_HOSTS.has(hostAgentEndpoint.hostname) &&
      runtimeEndpoint.hostname !== hostAgentEndpoint.hostname
    ) {
      throw new Error('Local Windows Sandbox Runtime Node host differs from the Host Agent host')
    }
  }
  return runtimeEndpoint
}

export async function verifyHybridRuntimeLifecycle({
  environment = process.env,
  fetchImpl = globalThis.fetch,
  timeoutMs = 30_000,
  startServerTimeoutMs = timeoutMs,
  startClientBufferMs = DEFAULT_START_CLIENT_BUFFER_MS,
  stopServerTimeoutMs = DEFAULT_STOP_SERVER_TIMEOUT_MS,
  stopClientBufferMs = DEFAULT_STOP_CLIENT_BUFFER_MS,
  createTimeoutSignal = (durationMs) => globalThis.AbortSignal.timeout(durationMs),
  nowImpl = () => Date.now(),
  sleepImpl = (durationMs) =>
    new Promise((resolve) => {
      setTimeout(resolve, durationMs)
    }),
  requestIdFactory = () => randomUUID(),
} = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('A Fetch implementation is required')
  if (typeof createTimeoutSignal !== 'function') {
    throw new Error('A timeout signal factory is required')
  }
  if (typeof nowImpl !== 'function' || typeof sleepImpl !== 'function') {
    throw new Error('Clock and sleep implementations are required')
  }
  const timeoutContract = resolveHybridTimeoutContract({
    requestTimeoutMs: timeoutMs,
    startServerTimeoutMs,
    startClientBufferMs,
    stopServerTimeoutMs,
    stopClientBufferMs,
  })
  const requestId = requestIdFactory()
  if (typeof requestId !== 'string' || !START_REQUEST_ID_PATTERN.test(requestId)) {
    throw new Error('The sandbox start requestId factory must return a UUID string')
  }
  const allowInsecureRuntimeHttp = parseBoolean(environment.RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP)
  const hostAgentEndpoint = requireEndpoint(
    'RUNTIME_HOST_AGENT_ENDPOINT',
    environment.RUNTIME_HOST_AGENT_ENDPOINT,
    allowInsecureRuntimeHttp
  )
  const hostAgentApiKey = requireStrongApiKey(
    'RUNTIME_HOST_AGENT_API_KEY',
    environment.RUNTIME_HOST_AGENT_API_KEY
  )
  const runtimeApiKey = requireStrongApiKey('RUNTIME_API_KEY', environment.RUNTIME_API_KEY)
  if (hostAgentApiKey === runtimeApiKey) {
    throw new Error('Host Agent and Runtime Node API keys must be distinct')
  }

  const health = await requestJson({
    fetchImpl,
    createTimeoutSignal,
    url: endpointPath(hostAgentEndpoint, 'sandbox/health'),
    label: 'Host Agent health',
    apiKey: hostAgentApiKey,
    timeoutMs: timeoutContract.requestTimeoutMs,
  })
  if (health.ok !== true) throw new Error('Host Agent health did not report ok=true')
  requireCorrelatedSandboxes(health, 'Host Agent health')

  let sandboxId
  let primaryError
  let cleanupError
  let startNeedsReconciliation = false
  let waitForStartSettlement = false
  let startSettlementDeadlineMs = 0
  try {
    startSettlementDeadlineMs = nowImpl() + timeoutContract.startClientDeadlineMs
    let started
    try {
      started = await requestJson({
        fetchImpl,
        createTimeoutSignal,
        url: endpointPath(hostAgentEndpoint, 'sandbox/start'),
        label: 'Sandbox start',
        apiKey: hostAgentApiKey,
        method: 'POST',
        body: {
          requestId,
          runtimeApiKey,
          timeoutMs: timeoutContract.startServerTimeoutMs,
          hypervStopOnRelease: true,
        },
        timeoutMs: timeoutContract.startClientDeadlineMs,
      })
    } catch (error) {
      startNeedsReconciliation = true
      waitForStartSettlement = error instanceof RequestTransportError
      throw error
    }
    const candidateSandboxId =
      typeof started.sandboxId === 'string' && started.sandboxId.trim().length > 0
        ? started.sandboxId.trim()
        : undefined
    if (candidateSandboxId) {
      // A directly returned ID belongs to this request and is safe to stop even
      // when another response field fails validation.
      sandboxId = candidateSandboxId
    } else {
      startNeedsReconciliation = true
    }
    if (
      started.ok !== true ||
      !candidateSandboxId ||
      started.requestId !== requestId ||
      typeof started.endpoint !== 'string'
    ) {
      throw new Error('Sandbox start returned an invalid lifecycle contract')
    }
    const runtimeEndpoint = validateRuntimeEndpoint({
      endpoint: started.endpoint,
      hostAgentEndpoint,
      backend: String(started.backend || ''),
      allowInsecureRuntimeHttp,
    })
    const runtimeHealth = await requestJson({
      fetchImpl,
      createTimeoutSignal,
      url: endpointPath(runtimeEndpoint, 'health'),
      label: 'Runtime Node health',
      apiKey: runtimeApiKey,
      timeoutMs: timeoutContract.requestTimeoutMs,
    })
    if (runtimeHealth.ok !== true) throw new Error('Runtime Node health did not report ok=true')
  } catch (error) {
    primaryError = error
  } finally {
    if (sandboxId) {
      try {
        await stopCorrelatedSandbox({
          fetchImpl,
          createTimeoutSignal,
          sleepImpl,
          nowImpl,
          hostAgentEndpoint,
          hostAgentApiKey,
          requestId,
          sandboxId,
          timeoutContract,
        })
      } catch (error) {
        cleanupError = error
      }
    } else if (startNeedsReconciliation) {
      try {
        if (waitForStartSettlement) {
          await waitUntilDeadline(startSettlementDeadlineMs, nowImpl, sleepImpl)
        }
        await reconcileAmbiguousStart({
          fetchImpl,
          createTimeoutSignal,
          sleepImpl,
          nowImpl,
          hostAgentEndpoint,
          hostAgentApiKey,
          requestId,
          timeoutContract,
        })
      } catch (error) {
        cleanupError = error
      }
    }
  }

  if (primaryError && cleanupError) {
    throw new AggregateError(
      [primaryError, cleanupError],
      'Hybrid runtime verification and cleanup failed'
    )
  }
  if (primaryError) throw primaryError
  if (cleanupError) throw cleanupError
  return { ok: true }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : ''
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    await verifyHybridRuntimeLifecycle()
    process.stdout.write('Hybrid runtime lifecycle verification passed\n')
  } catch (error) {
    process.stderr.write(`Hybrid runtime lifecycle verification failed: ${error.message}\n`)
    process.exitCode = 1
  }
}
