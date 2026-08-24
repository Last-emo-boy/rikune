import type { ToolRegistrar } from '../registrar.js'
import type { ToolDeps } from '../tool-registry.js'
import { sampleIngestToolDefinition, createSampleIngestHandler } from '../../tools/sample-ingest.js'
import {
  sampleRequestUploadToolDefinition,
  createSampleRequestUploadHandler,
} from '../../tools/sample-request-upload.js'
import {
  sampleProfileGetToolDefinition,
  createSampleProfileGetHandler,
} from '../../tools/sample-profile-get.js'
import {
  analysisContextGetToolDefinition,
  createAnalysisContextGetHandler,
} from '../../tools/analysis-context-get.js'
import { sampleDeleteToolDefinition, createSampleDeleteHandler } from '../../tools/sample-delete.js'

export function registerSampleTools(server: ToolRegistrar, deps: ToolDeps): void {
  const { workspaceManager, database, policyGuard, config, jobQueue, cacheManager } = deps
  if (!deps.sampleOperationGate) {
    throw new Error('sample.ingest registration requires SampleOperationGate')
  }
  server.registerTool(
    sampleIngestToolDefinition,
    createSampleIngestHandler(workspaceManager, database, policyGuard, deps.sampleOperationGate)
  )
  server.registerTool(
    sampleRequestUploadToolDefinition,
    createSampleRequestUploadHandler(database, {
      apiPort: config.api.port,
      baseUrl: config.api.publicBaseUrl,
    })
  )
  server.registerTool(
    sampleProfileGetToolDefinition,
    createSampleProfileGetHandler(database, workspaceManager, { jobQueue, cacheManager })
  )
  server.registerTool(
    analysisContextGetToolDefinition,
    createAnalysisContextGetHandler(database, jobQueue)
  )
  if (deps.sampleDeletionService) {
    server.registerTool(
      sampleDeleteToolDefinition,
      createSampleDeleteHandler(deps.sampleDeletionService)
    )
  }
}
