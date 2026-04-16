import type { MCPServer } from '../server.js'
import {
  configValidateToolDefinition, createConfigValidateHandler,
} from '../../tools/config-validate.js'

export function registerDiagnosticsTools(server: MCPServer): void {
  server.registerTool(configValidateToolDefinition, createConfigValidateHandler(server))
}
