import type { ToolRegistrar } from '../registrar.js'
import { getPluginManager } from '../plugins.js'
import {
  pluginListToolDefinition,
  createPluginListHandler,
  pluginEnableToolDefinition,
  createPluginEnableHandler,
  pluginDisableToolDefinition,
  createPluginDisableHandler,
} from '../../tools/plugin-list.js'
import { isStaticDockerProfile } from '../static-profile-lock.js'

export function registerPluginTools(server: ToolRegistrar): void {
  server.registerTool(pluginListToolDefinition, createPluginListHandler(server))
  if (isStaticDockerProfile()) return
  server.registerTool(pluginEnableToolDefinition, createPluginEnableHandler(server))
  server.registerTool(pluginDisableToolDefinition, createPluginDisableHandler(server))
}

export { getPluginManager }
