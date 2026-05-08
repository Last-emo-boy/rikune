import type { ToolRegistrar } from '../registrar.js'
import { getPluginManager } from '../plugins.js'
import type { RuntimeContractValidationResult } from '../../runtime-client/runtime-client.js'
import type { ToolRuntimeContract } from '../../types.js'
import { toolHelpToolDefinition, createToolHelpHandler } from '../../tools/tool-help.js'
import {
  toolReadinessToolDefinition,
  createToolReadinessHandler,
} from '../../tools/tool-readiness.js'
import {
  toolsDiscoverToolDefinition,
  createToolsDiscoverHandler,
} from '../../tools/tools-discover.js'

interface UtilityToolOptions {
  runtimeClient?: {
    getEndpoint?(): string
    validateRuntimeContract?(
      contract: ToolRuntimeContract,
      options?: { forceRefresh?: boolean }
    ): Promise<RuntimeContractValidationResult>
  } | null
  runtimeMode?: string
}

export function registerUtilityTools(
  server: ToolRegistrar,
  options: UtilityToolOptions = {}
): void {
  server.registerTool(
    toolHelpToolDefinition,
    createToolHelpHandler(() => server.getToolDefinitions())
  )
  server.registerTool(
    toolReadinessToolDefinition,
    createToolReadinessHandler(() => server.getToolDefinitions(), getPluginManager, {
      runtimeClient: options.runtimeClient,
      runtimeMode: options.runtimeMode,
    })
  )
  server.registerTool(toolsDiscoverToolDefinition, createToolsDiscoverHandler(getPluginManager()))
}
