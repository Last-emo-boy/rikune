import type { ToolRegistrar } from '../registrar.js'
import type { ToolDeps } from '../tool-registry.js'
import { artifactReadToolDefinition, createArtifactReadHandler } from '../../tools/artifact-read.js'
import { artifactsListToolDefinition, createArtifactsListHandler } from '../../tools/artifacts-list.js'
import { artifactsDiffToolDefinition, createArtifactsDiffHandler } from '../../tools/artifacts-diff.js'
import { artifactDownloadToolDefinition, createArtifactDownloadHandler } from '../../tools/artifact-download.js'

export function registerArtifactTools(server: ToolRegistrar, deps: ToolDeps): void {
  const { workspaceManager, database, storageManager } = deps
  server.registerTool(artifactReadToolDefinition, createArtifactReadHandler(workspaceManager, database))
  server.registerTool(artifactsListToolDefinition, createArtifactsListHandler(workspaceManager, database))
  server.registerTool(artifactsDiffToolDefinition, createArtifactsDiffHandler(workspaceManager, database))
  server.registerTool(artifactDownloadToolDefinition, createArtifactDownloadHandler(database, { storageManager, workspaceManager }))
}
