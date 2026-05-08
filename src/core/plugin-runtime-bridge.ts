import type { PluginServerInterface } from '../plugins/sdk.js'
import type {
  ToolRegistrar,
  PromptRegistrar,
  ResourceRegistrar,
  SamplingClient,
} from './registrar.js'
import { config } from '../config.js'
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
    _executionDomain?: string
  ): PluginServerInterface {
    if (config.node.role === 'analyzer') {
      return createDelegatingServer(
        baseServer,
        pluginId,
        this.deps.runtimeClient ?? null,
        this.deps.workspaceManager,
        this.deps.database,
        this.deps.resolvePrimarySamplePath,
        this.deps.sandboxDir ?? null
      )
    }
    return baseServer as PluginServerInterface
  }
}
