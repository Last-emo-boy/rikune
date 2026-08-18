/**
 * Testable runtime recovery logic for analyzer → runtime reconnection.
 */

import { logger } from '../logger.js'
import type { Config } from '../config.js'
import {
  assertTrustedHttpEndpoint,
  createTrustedFetch,
  endpointUrl,
  type ParsedHttpServiceEndpoint,
} from '@rikune/shared'
import { validateRuntimeEndpointFromHostAgent } from '../infrastructure/trusted-runtime-endpoint.js'
import { createRuntimeClient } from './runtime-client.js'
import type { RuntimeConnection } from './sandbox-launcher.js'
import type { SandboxLauncher } from './sandbox-launcher.js'

export interface RecoveryContext {
  config: Config
  runtimeClient: ReturnType<typeof createRuntimeClient> | null
  runtimeConnection: RuntimeConnection | null
  sandboxLauncher: SandboxLauncher | null
}

export interface RuntimeRecovery {
  recover(options?: { forceRefreshCapabilities?: boolean }): Promise<boolean>
  setRuntimeClient(client: ReturnType<typeof createRuntimeClient> | null): void
  setRuntimeConnection(connection: RuntimeConnection | null): void
  setSandboxLauncher(launcher: SandboxLauncher | null): void
}

function validateHostAgentEndpoint(value: string): ParsedHttpServiceEndpoint {
  return assertTrustedHttpEndpoint(value, { label: 'runtime.hostAgentEndpoint' })
}

export function createRuntimeRecovery(ctx: RecoveryContext): RuntimeRecovery {
  let { config, runtimeClient, runtimeConnection, sandboxLauncher } = ctx
  let recoveryInFlight: Promise<boolean> | null = null

  async function refreshRuntimeCapabilitiesIfRequested(options?: {
    forceRefreshCapabilities?: boolean
  }) {
    if (!options?.forceRefreshCapabilities || !runtimeClient?.getCapabilities) {
      return
    }
    try {
      await runtimeClient.getCapabilities({ forceRefresh: true })
    } catch (err) {
      logger.debug({ err }, 'Runtime capability refresh after recovery failed')
    }
  }

  async function performRecovery(options?: {
    forceRefreshCapabilities?: boolean
  }): Promise<boolean> {
    if (config.runtime.mode === 'remote-sandbox' && config.runtime.hostAgentEndpoint) {
      let trustedFetch: ReturnType<typeof createTrustedFetch> | null = null
      try {
        const hostAgentEndpoint = validateHostAgentEndpoint(config.runtime.hostAgentEndpoint)
        const trustedHostAgentEndpoint = config.runtime.hostAgentEndpoint.trim()
        trustedFetch = createTrustedFetch({
          allowedOrigins: [hostAgentEndpoint.origin],
          label: 'runtime.hostAgentEndpoint',
        })
        const startRes = await trustedFetch(endpointUrl(hostAgentEndpoint.url, '/sandbox/start'), {
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
          await startRes.body?.cancel().catch(() => {})
          return false
        }
        const startData = (await startRes.json()) as {
          ok?: boolean
          endpoint?: string
          sandboxId?: string
          backend?: string
        }
        if (!startData.ok || typeof startData.endpoint !== 'string' || !startData.endpoint.trim()) {
          return false
        }
        const runtimeEndpoint = validateRuntimeEndpointFromHostAgent(
          startData.endpoint,
          trustedHostAgentEndpoint,
          startData.backend
        )
        const validatedEndpoint = startData.endpoint.trim()
        if (!runtimeClient) {
          runtimeClient = createRuntimeClient({
            endpoint: validatedEndpoint,
            apiKey: config.runtime.apiKey,
          })
        } else {
          runtimeClient.setEndpoint(validatedEndpoint, {
            trustedParentEndpoint: trustedHostAgentEndpoint,
            ...(startData.backend ? { trustedHostAgentBackend: startData.backend } : {}),
          })
          runtimeClient.invalidateCapabilitiesCache?.()
        }
        await refreshRuntimeCapabilitiesIfRequested(options)
        logger.info(
          { endpoint: runtimeEndpoint.url.toString(), sandboxId: startData.sandboxId },
          'Remote-sandbox runtime recovered'
        )
        return true
      } catch (err) {
        logger.warn({ err }, 'Remote-sandbox recovery attempt failed')
      } finally {
        if (trustedFetch) {
          await trustedFetch.close().catch(() => {})
        }
      }
    }
    if (config.runtime.mode === 'auto-sandbox' && sandboxLauncher) {
      try {
        await sandboxLauncher.teardown()
        runtimeConnection = null
        const newConnection = await sandboxLauncher.launch()
        if (newConnection) {
          assertTrustedHttpEndpoint(newConnection.endpoint, {
            label: 'auto-sandbox runtime endpoint',
          })
          if (!runtimeClient) {
            runtimeClient = createRuntimeClient({
              endpoint: newConnection.endpoint,
              apiKey: config.runtime.apiKey,
            })
          } else {
            runtimeClient.setEndpoint(newConnection.endpoint, { trustedLocalSandboxLaunch: true })
            runtimeClient.invalidateCapabilitiesCache?.()
          }
          runtimeConnection = newConnection
          await refreshRuntimeCapabilitiesIfRequested(options)
          logger.info({ endpoint: newConnection.endpoint }, 'Auto-sandbox runtime recovered')
          return true
        }
      } catch (err) {
        logger.warn({ err }, 'Auto-sandbox recovery attempt failed')
      }
    }
    return false
  }

  function recover(options?: { forceRefreshCapabilities?: boolean }): Promise<boolean> {
    if (recoveryInFlight) {
      return recoveryInFlight
    }

    const attempt = performRecovery(options).finally(() => {
      if (recoveryInFlight === attempt) {
        recoveryInFlight = null
      }
    })
    recoveryInFlight = attempt
    return attempt
  }

  return {
    recover,
    setRuntimeClient(client) {
      if (runtimeClient && runtimeClient !== client) {
        void runtimeClient.close?.()
      }
      runtimeClient = client
    },
    setRuntimeConnection(connection) {
      runtimeConnection = connection
    },
    setSandboxLauncher(launcher) {
      sandboxLauncher = launcher
    },
  }
}
