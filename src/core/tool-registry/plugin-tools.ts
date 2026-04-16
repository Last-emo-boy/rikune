import type { MCPServer } from '../server.js'
import { getPluginManager } from '../plugins.js'
import {
  pluginListToolDefinition, createPluginListHandler,
  pluginEnableToolDefinition, createPluginEnableHandler,
  pluginDisableToolDefinition, createPluginDisableHandler,
} from '../../tools/plugin-list.js'

export function registerPluginTools(server: MCPServer): void {
  server.registerTool(pluginListToolDefinition, createPluginListHandler(server))
  server.registerTool(pluginEnableToolDefinition, createPluginEnableHandler(server))
  server.registerTool(pluginDisableToolDefinition, createPluginDisableHandler(server))
}

export { getPluginManager }
