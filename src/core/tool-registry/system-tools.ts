import type { MCPServer } from '../server.js'
import type { ToolDeps } from '../tool-registry.js'
import { systemHealthToolDefinition, createSystemHealthHandler } from '../../tools/system-health.js'
import { systemSetupGuideToolDefinition, createSystemSetupGuideHandler } from '../../tools/system-setup-guide.js'
import { setupRemediateToolDefinition, createSetupRemediateHandler } from '../../tools/setup-remediate.js'

export interface SystemToolHandlers {
  systemHealthHandler: ReturnType<typeof createSystemHealthHandler>
  systemSetupGuideHandler: ReturnType<typeof createSystemSetupGuideHandler>
}

export function registerSystemTools(server: MCPServer, deps: ToolDeps): SystemToolHandlers {
  const { workspaceManager, database, cacheManager } = deps
  const systemHealthHandler = createSystemHealthHandler(workspaceManager, database, { cacheManager, runtimeClient: deps.runtimeClient })
  const systemSetupGuideHandler = createSystemSetupGuideHandler()
  server.registerTool(systemHealthToolDefinition, systemHealthHandler)
  server.registerTool(systemSetupGuideToolDefinition, systemSetupGuideHandler)
  server.registerTool(setupRemediateToolDefinition, createSetupRemediateHandler(workspaceManager, database, cacheManager, {
    healthHandler: systemHealthHandler,
    setupGuideHandler: systemSetupGuideHandler,
  }))
  return { systemHealthHandler, systemSetupGuideHandler }
}
