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
  createRuntimeClient,
  type RuntimeBackendCapability,
  type RuntimeBackendHintValidationResult,
  type RuntimeEventStreamOptions,
  type RuntimeEventSubscription,
  type RuntimeExecuteRequest,
  type RuntimeExecuteResponse,
  type RuntimeHealthResponse,
} from './runtime-client.js'

type RuntimeClient = ReturnType<typeof createRuntimeClient>

export class HostAgentSandboxStartError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message)
    this.name = 'HostAgentSandboxStartError'
  }
}

export function createLazyRemoteSandboxRuntimeClient(config: Config): RuntimeClient {
  let client: RuntimeClient | null = null
  let startPromise: Promise<RuntimeClient> | null = null

  async function startSandbox(): Promise<RuntimeClient> {
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

      const startRes = await fetch(`${config.runtime.hostAgentEndpoint}/sandbox/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(config.runtime.hostAgentApiKey ? { Authorization: `Bearer ${config.runtime.hostAgentApiKey}` } : {}),
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
          startRes.status,
        )
      }

      const startData = (await startRes.json()) as { ok?: boolean; endpoint?: string; sandboxId?: string }
      if (!startData.ok || !startData.endpoint) {
        throw new HostAgentSandboxStartError(
          `Host agent returned an unsuccessful sandbox start: ${JSON.stringify(startData)}`,
        )
      }

      const next = createRuntimeClient({
        endpoint: startData.endpoint,
        apiKey: config.runtime.apiKey,
      })
      next.recover = recover
      client = next
      logger.info({ endpoint: startData.endpoint, sandboxId: startData.sandboxId }, 'Remote-sandbox runtime connected')
      logger.warn('Dynamic analysis will execute actual samples inside the remote Windows Sandbox. Ensure the sandbox is properly isolated.')
      return next
    })()

    try {
      return await startPromise
    } finally {
      startPromise = null
    }
  }

  async function recover(options?: { forceRefreshCapabilities?: boolean }): Promise<boolean> {
    client = null
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

    async getCapabilities(options: { forceRefresh?: boolean } = {}): Promise<RuntimeBackendCapability[] | null> {
      return (await startSandbox()).getCapabilities(options)
    },

    async validateRuntimeBackendHint(
      hint: Parameters<RuntimeClient['validateRuntimeBackendHint']>[0],
      options: { forceRefresh?: boolean } = {},
    ): Promise<RuntimeBackendHintValidationResult> {
      return (await startSandbox()).validateRuntimeBackendHint(hint, options)
    },

    async execute(
      req: RuntimeExecuteRequest,
      opts?: { onProgress?: (progress: number, message?: string) => void },
    ): Promise<RuntimeExecuteResponse> {
      return (await startSandbox()).execute(req, opts)
    },

    async uploadSample(taskId: string, localSamplePath: string, inboxHostDir: string): Promise<void> {
      return (await startSandbox()).uploadSample(taskId, localSamplePath, inboxHostDir)
    },

    async downloadArtifacts(taskId: string, outboxHostDir: string, artifactNames: string[]): Promise<string[]> {
      return (await startSandbox()).downloadArtifacts(taskId, outboxHostDir, artifactNames)
    },

    invalidateCapabilitiesCache(): void {
      client?.invalidateCapabilitiesCache()
    },

    setEndpoint(newEndpoint: string): void {
      if (!client) {
        client = createRuntimeClient({ endpoint: newEndpoint, apiKey: config.runtime.apiKey })
        client.recover = recover
        return
      }
      client.setEndpoint(newEndpoint)
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
