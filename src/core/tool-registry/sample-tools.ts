import type { MCPServer } from '../server.js'
import type { ToolDeps } from '../tool-registry.js'
import { sampleIngestToolDefinition, createSampleIngestHandler } from '../../tools/sample-ingest.js'
import { sampleRequestUploadToolDefinition, createSampleRequestUploadHandler } from '../../tools/sample-request-upload.js'
import { sampleProfileGetToolDefinition, createSampleProfileGetHandler } from '../../tools/sample-profile-get.js'

export function registerSampleTools(server: MCPServer, deps: ToolDeps): void {
  const { workspaceManager, database, policyGuard, config } = deps
  server.registerTool(sampleIngestToolDefinition, createSampleIngestHandler(workspaceManager, database, policyGuard))
  server.registerTool(sampleRequestUploadToolDefinition, createSampleRequestUploadHandler(database, { apiPort: config.api.port }))
  server.registerTool(sampleProfileGetToolDefinition, createSampleProfileGetHandler(database, workspaceManager))
}
