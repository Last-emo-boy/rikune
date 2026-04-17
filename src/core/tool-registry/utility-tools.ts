import type { ToolRegistrar } from '../registrar.js'
import { getPluginManager } from '../plugins.js'
import { toolHelpToolDefinition, createToolHelpHandler } from '../../tools/tool-help.js'
import { toolsDiscoverToolDefinition, createToolsDiscoverHandler } from '../../tools/tools-discover.js'

export function registerUtilityTools(server: ToolRegistrar): void {
  server.registerTool(toolHelpToolDefinition, createToolHelpHandler(() => server.getToolDefinitions()))
  server.registerTool(toolsDiscoverToolDefinition, createToolsDiscoverHandler(getPluginManager()))
}
