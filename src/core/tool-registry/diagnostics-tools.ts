import type { ToolRegistrar } from '../registrar.js'
import {
  configValidateToolDefinition, createConfigValidateHandler,
} from '../../tools/config-validate.js'

export function registerDiagnosticsTools(server: ToolRegistrar): void {
  server.registerTool(configValidateToolDefinition, createConfigValidateHandler())
}
