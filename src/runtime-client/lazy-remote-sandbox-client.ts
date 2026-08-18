/**
 * Lazy analyzer-side client for remote Windows Sandbox runtimes.
 *
 * The analyzer should not launch Windows Sandbox merely because an MCP client
 * connected or queried health. This wrapper starts the sandbox only when a
 * delegated runtime operation actually needs the Runtime Node.
 */

import type { Config } from '../config.js'
import { logger } from '../logger.js'
import {
  assertTrustedHttpEndpoint,
  createTrustedFetch,
  endpointUrl,
  type ParsedHttpServiceEndpoint,
  type TrustedFetch,
} from '@rikune/shared'
import { validateRuntimeEndpointFromHostAgent } from '../infrastructure/trusted-runtime-endpoint.js'
import {
  createRuntimeClient,
  type RuntimeBackendCapability,
  type RuntimeContractValidationResult,
  type RuntimeEventStreamOptions,
  type RuntimeEventSubscription,
  type RuntimeExecuteRequest,
  type RuntimeExecuteResponse,
  type RuntimeHealthResponse,
  type RuntimeEndpointUpdateOptions,
  type RuntimeUploadOptions,
} from './runtime-client.js'

type RuntimeClient = ReturnType<typeof createRuntimeClient>

function validateHostAgentEndpoint(value: string): ParsedHttpServiceEndpoint {
  return assertTrustedHttpEndpoint(value, { label: 'runtime.hostAgentEndpoint' })
}

export class HostAgentSandboxStartError extends Error {
  constructor(
    message: string,
    readonly status?: number
  ) {
    super(message)
    this.name = 'HostAgentSandboxStartError'
  }
}

export function createLazyRemoteSandboxRuntimeClient(config: Config): RuntimeClient {
  let client: RuntimeClient | null = null
  let startPromise: Promise<RuntimeClient> | null = null
  let hostAgentFetch: TrustedFetch | null = null
  let closed = false

  async function startSandbox(): Promise<RuntimeClient> {
    if (closed) {
      throw new Error('Remote-sandbox runtime client is closed')
    }
    if (client) {
      return client
    }
    if (startPromise) {
      return startPromise
    }

    startPromise = (async () => {
      if (!config.runtime.hostAgentEndpoint) {
        throw new Error('runtime.hostAgentEndpoint is required for remote-sandbox runtime mode')
      }

      let hostAgentEndpoint: ParsedHttpServiceEndpoint
      try {
        hostAgentEndpoint = validateHostAgentEndpoint(config.runtime.hostAgentEndpoint)
      } catch (err) {
        throw new HostAgentSandboxStartError(
          `Configured Host Agent endpoint is not trusted: ${err instanceof Error ? err.message : String(err)}`
        )
      }
      const startUrl = endpointUrl(hostAgentEndpoint.url, '/sandbox/start')
      hostAgentFetch ??= createTrustedFetch({
        allowedOrigins: [hostAgentEndpoint.origin],
        label: 'runtime.hostAgentEndpoint',
      })

      const startRes = await hostAgentFetch(startUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(config.runtime.hostAgentApiKey
            ? { Authorization: `Bearer ${config.runtime.hostAgentApiKey}` }
            : {}),
        },
        body: JSON.stringify({
          timeoutMs: config.runtime.healthCheckTimeoutMs,
          runtimeApiKey: config.runtime.apiKey,
        }),
        signal: AbortSignal.timeout(60_000),
      })

      if (!startRes.ok) {
        const body = await startRes.text().catch(() => '')
        throw new HostAgentSandboxStartError(
          `Host agent failed to start sandbox: HTTP ${startRes.status}${body ? ` ${body}` : ''}`,
          startRes.status
        )
      }

      const startData = (await startRes.json()) as {
        ok?: boolean
        endpoint?: string
        sandboxId?: string
        backend?: string
      }
      if (!startData.ok || typeof startData.endpoint !== 'string' || !startData.endpoint.trim()) {
        throw new HostAgentSandboxStartError(
          `Host agent returned an unsuccessful sandbox start: ${JSON.stringify(startData)}`
        )
      }

      let runtimeEndpoint: ParsedHttpServiceEndpoint
      try {
        runtimeEndpoint = validateRuntimeEndpointFromHostAgent(
          startData.endpoint,
          hostAgentEndpoint.url.toString(),
          startData.backend
        )
      } catch (err) {
        throw new HostAgentSandboxStartError(
          `Host Agent returned an untrusted runtime endpoint: ${err instanceof Error ? err.message : String(err)}`
        )
      }

      const next = createRuntimeClient({
        endpoint: startData.endpoint.trim(),
        apiKey: config.runtime.apiKey,
      })
      next.recover = recover
      client = next
      logger.info(
        { endpoint: runtimeEndpoint.url.toString(), sandboxId: startData.sandboxId },
        'Remote-sandbox runtime connected'
      )
      logger.warn(
        'Dynamic analysis will execute actual samples inside the remote Windows Sandbox. Ensure the sandbox is properly isolated.'
      )
      return next
    })()

    try {
      return await startPromise
    } finally {
      startPromise = null
    }
  }

  async function recover(options?: { forceRefreshCapabilities?: boolean }): Promise<boolean> {
    if (closed) {
      return false
    }
    const previous = client
    client = null
    await previous?.close?.()
    try {
      const next = await startSandbox()
      if (options?.forceRefreshCapabilities) {
        await next.getCapabilities({ forceRefresh: true })
      }
      return true
    } catch (err) {
      logger.warn({ err }, 'Remote-sandbox lazy launch/recovery attempt failed')
      return false
    }
  }

  const lazyClient = {
    async health(): Promise<RuntimeHealthResponse | null> {
      if (!client) {
        return null
      }
      return client.health()
    },

    async getCapabilities(
      options: { forceRefresh?: boolean } = {}
    ): Promise<RuntimeBackendCapability[] | null> {
      return (await startSandbox()).getCapabilities(options)
    },

    async validateRuntimeContract(
      hint: Parameters<RuntimeClient['validateRuntimeContract']>[0],
      options: { forceRefresh?: boolean } = {}
    ): Promise<RuntimeContractValidationResult> {
      return (await startSandbox()).validateRuntimeContract(hint, options)
    },

    async execute(
      req: RuntimeExecuteRequest,
      opts?: { onProgress?: (progress: number, message?: string) => void }
    ): Promise<RuntimeExecuteResponse> {
      return (await startSandbox()).execute(req, opts)
    },

    async uploadSample(
      taskId: string,
      localSamplePath: string,
      inboxHostDir: string,
      options?: RuntimeUploadOptions
    ): Promise<void> {
      return (await startSandbox()).uploadSample(taskId, localSamplePath, inboxHostDir, options)
    },

    async downloadArtifacts(
      taskId: string,
      outboxHostDir: string,
      artifactNames: string[]
    ): Promise<string[]> {
      return (await startSandbox()).downloadArtifacts(taskId, outboxHostDir, artifactNames)
    },

    invalidateCapabilitiesCache(): void {
      client?.invalidateCapabilitiesCache()
    },

    async close(): Promise<void> {
      closed = true
      const pending = startPromise
      if (pending) {
        await pending.catch(() => {})
      }
      const current = client
      client = null
      await current?.close?.()
      const fetchClient = hostAgentFetch
      hostAgentFetch = null
      if (fetchClient) {
        await fetchClient.close().catch(() => {})
      }
    },

    setEndpoint(newEndpoint: string, updateOptions?: RuntimeEndpointUpdateOptions): void {
      if (closed) {
        throw new Error('Remote-sandbox runtime client is closed')
      }
      if (!client) {
        if (
          config.runtime.apiKey &&
          !updateOptions?.trustedParentEndpoint &&
          updateOptions?.trustedLocalSandboxLaunch !== true
        ) {
          throw new Error(
            'Cannot attach a keyed runtime endpoint without a trusted parent endpoint'
          )
        }
        if (updateOptions?.trustedParentEndpoint) {
          validateRuntimeEndpointFromHostAgent(
            newEndpoint,
            updateOptions.trustedParentEndpoint,
            updateOptions.trustedHostAgentBackend
          )
        }
        if (updateOptions?.trustedLocalSandboxLaunch === true) {
          const parsed = assertTrustedHttpEndpoint(newEndpoint, {
            label: 'local sandbox runtime endpoint',
          })
          if (parsed.url.protocol !== 'http:') {
            throw new Error('Local Windows Sandbox runtime endpoints must use http.')
          }
        }
        client = createRuntimeClient({ endpoint: newEndpoint, apiKey: config.runtime.apiKey })
        client.recover = recover
        return
      }
      client.setEndpoint(newEndpoint, updateOptions)
    },

    getEndpoint(): string {
      return client?.getEndpoint() ?? ''
    },

    subscribeEvents(options: RuntimeEventStreamOptions): RuntimeEventSubscription {
      if (!client) {
        return { close() {} }
      }
      return client.subscribeEvents(options)
    },

    recover,
  }

  return lazyClient as RuntimeClient
}
