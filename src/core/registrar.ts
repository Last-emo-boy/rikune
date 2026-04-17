import type {
  ClientCapabilities,
  CreateMessageRequest,
  CreateMessageResult,
  CreateMessageResultWithTools,
  Implementation,
} from '@modelcontextprotocol/sdk/types.js'
import type { ToolDefinition, PromptDefinition } from '../types.js'

export interface ToolRegistrar {
  registerTool(definition: ToolDefinition, handler: any): void
  unregisterTool(canonicalName: string): void
  getToolDefinitions(): ToolDefinition[]
}

export interface PromptRegistrar {
  registerPrompt(definition: PromptDefinition, handler: any): void
  getPromptDefinitions(): PromptDefinition[]
}

export interface ResourceRegistrar {
  registerResource(
    meta: { uri: string; name: string; description?: string; mimeType?: string },
    handler: () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>,
  ): void
}

export interface SamplingClient {
  getClientCapabilities(): ClientCapabilities | undefined
  getClientVersion(): Implementation | undefined
  createMessage(
    params: CreateMessageRequest['params']
  ): Promise<CreateMessageResult | CreateMessageResultWithTools>
}

export interface PluginManagerSetter {
  setPluginManager(mgr: any): void
}
