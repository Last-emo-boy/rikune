import type { PluginServerInterface } from '../plugins/sdk.js'
import type { ToolRegistrar, PromptRegistrar, ResourceRegistrar, SamplingClient } from './registrar.js'
import { createDelegatingServer } from '../runtime-client/delegation-server.js'

export interface RuntimeBridgeDeps {
  runtimeClient?: any
  sandboxDir?: string | null
  workspaceManager?: any
  database?: any
  resolvePrimarySamplePath?: any
}

export class PluginRuntimeBridge {
  constructor(private deps: RuntimeBridgeDeps) {}

  createServerForPlugin(
    baseServer: ToolRegistrar & PromptRegistrar & ResourceRegistrar & SamplingClient,
    pluginId: string,
    executionDomain?: string
  ): PluginServerInterface {
    if (executionDomain === 'dynamic') {
      return createDelegatingServer(
        baseServer,
        pluginId,
        this.deps.runtimeClient ?? null,
        this.deps.workspaceManager,
        this.deps.database,
        this.deps.resolvePrimarySamplePath,
        this.deps.sandboxDir ?? null
      ) as PluginServerInterface
    }
    return baseServer as PluginServerInterface
  }
}
