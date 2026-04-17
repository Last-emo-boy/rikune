/**
 * Testable runtime recovery logic for analyzer → runtime reconnection.
 */

import { logger } from '../logger.js'
import type { Config } from '../config.js'
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

export function createRuntimeRecovery(ctx: RecoveryContext): RuntimeRecovery {
  let { config, runtimeClient, runtimeConnection, sandboxLauncher } = ctx

  async function refreshRuntimeCapabilitiesIfRequested(options?: { forceRefreshCapabilities?: boolean }) {
    if (!options?.forceRefreshCapabilities || !runtimeClient?.getCapabilities) {
      return
    }
    try {
      await runtimeClient.getCapabilities({ forceRefresh: true })
    } catch (err) {
      logger.debug({ err }, 'Runtime capability refresh after recovery failed')
    }
  }

  async function recoverRemoteSandbox(options?: { forceRefreshCapabilities?: boolean }): Promise<boolean> {
    if (config.runtime.mode === 'remote-sandbox' && config.runtime.hostAgentEndpoint) {
      try {
        const startRes = await fetch(`${config.runtime.hostAgentEndpoint}/sandbox/start`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(config.runtime.hostAgentApiKey ? { Authorization: `Bearer ${config.runtime.hostAgentApiKey}` } : {}),
          },
          body: JSON.stringify({ timeoutMs: config.runtime.healthCheckTimeoutMs }),
          signal: AbortSignal.timeout(60_000),
        })
        if (!startRes.ok) return false
        const startData = (await startRes.json()) as { ok?: boolean; endpoint?: string; sandboxId?: string }
        if (!startData.ok || !startData.endpoint) return false
        if (!runtimeClient) {
          runtimeClient = createRuntimeClient({ endpoint: startData.endpoint, apiKey: config.runtime.apiKey })
        } else {
          runtimeClient.setEndpoint(startData.endpoint)
          runtimeClient.invalidateCapabilitiesCache?.()
        }
        await refreshRuntimeCapabilitiesIfRequested(options)
        logger.info({ endpoint: startData.endpoint, sandboxId: startData.sandboxId }, 'Remote-sandbox runtime recovered')
        return true
      } catch (err) {
        logger.warn({ err }, 'Remote-sandbox recovery attempt failed')
      }
    }
    if (config.runtime.mode === 'auto-sandbox' && sandboxLauncher) {
      try {
        await sandboxLauncher.teardown()
        runtimeConnection = null
        const newConnection = await sandboxLauncher.launch()
        if (newConnection) {
          runtimeConnection = newConnection
          if (!runtimeClient) {
            runtimeClient = createRuntimeClient({ endpoint: newConnection.endpoint, apiKey: config.runtime.apiKey })
          } else {
            runtimeClient.setEndpoint(newConnection.endpoint)
            runtimeClient.invalidateCapabilitiesCache?.()
          }
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

  return {
    recover: recoverRemoteSandbox,
    setRuntimeClient(client) {
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
