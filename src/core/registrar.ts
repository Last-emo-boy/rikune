import type {
  ClientCapabilities,
  CreateMessageRequest,
  CreateMessageResult,
  CreateMessageResultWithTools,
  ElicitResult,
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
    meta: {
      uri: string
      name: string
      title?: string
      description?: string
      mimeType?: string
      size?: number
      annotations?: {
        audience?: Array<'user' | 'assistant'>
        priority?: number
        lastModified?: string
      }
    },
    handler: () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>
  ): void
  registerResourceTemplate(meta: {
    uriTemplate: string
    name: string
    title?: string
    description?: string
    mimeType?: string
    annotations?: {
      audience?: Array<'user' | 'assistant'>
      priority?: number
      lastModified?: string
    }
  }): void
}

export interface SamplingClient {
  getClientCapabilities(): ClientCapabilities | undefined
  getClientVersion(): Implementation | undefined
  createMessage(
    params: CreateMessageRequest['params']
  ): Promise<CreateMessageResult | CreateMessageResultWithTools>
}

export interface ElicitationClient {
  supportsElicitation(): boolean
  elicit(params: Record<string, unknown>): Promise<ElicitResult>
}

export interface PluginManagerSetter {
  setPluginManager(mgr: any): void
}
