import type { ToolRegistrar, SamplingClient } from '../registrar.js'
import type { ToolDeps } from '../tool-registry.js'
import type { AnalyzePipelineDependencies } from '../../workflows/analyze-pipeline.js'
import {
  triageWorkflowToolDefinition,
  createTriageWorkflowHandler,
} from '../../workflows/triage.js'
import {
  analyzeAutoWorkflowToolDefinition,
  createAnalyzeAutoWorkflowHandler,
} from '../../workflows/analyze-auto.js'
import {
  analyzeWorkflowPromoteToolDefinition,
  analyzeWorkflowStartToolDefinition,
  analyzeWorkflowStatusToolDefinition,
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
  createAnalyzeWorkflowStatusHandler,
} from '../../workflows/analyze-pipeline.js'
import {
  workflowRunToolDefinition,
  createWorkflowRunHandler,
} from '../../workflows/workflow-run.js'
import { createSampleRequestUploadHandler } from '../../tools/sample-request-upload.js'
import {
  reconstructWorkflowToolDefinition,
  createReconstructWorkflowHandler,
} from '../../workflows/reconstruct.js'
import {
  deepStaticWorkflowToolDefinition,
  createDeepStaticWorkflowHandler,
} from '../../workflows/deep-static.js'
import {
  functionIndexRecoverWorkflowToolDefinition,
  createFunctionIndexRecoverWorkflowHandler,
} from '../../workflows/function-index-recover.js'
import {
  semanticNameReviewWorkflowToolDefinition,
  createSemanticNameReviewWorkflowHandler,
} from '../../workflows/semantic-name-review.js'
import {
  functionExplanationReviewWorkflowToolDefinition,
  createFunctionExplanationReviewWorkflowHandler,
} from '../../workflows/function-explanation-review.js'
import {
  moduleReconstructionReviewWorkflowToolDefinition,
  createModuleReconstructionReviewWorkflowHandler,
} from '../../workflows/module-reconstruction-review.js'
import { isStaticDockerProfile } from '../static-profile-lock.js'

async function createWorkflowRuntimeDependencies(
  deps: ToolDeps
): Promise<AnalyzePipelineDependencies> {
  if (isStaticDockerProfile()) {
    return { staticOnly: true, sampleOperationGate: deps.sampleOperationGate }
  }
  if (!deps.runtimeClient) {
    return { sampleOperationGate: deps.sampleOperationGate }
  }
  const [{ sandboxExecuteToolDefinition }, { createRuntimeDelegatedToolHandler }, workspace] =
    await Promise.all([
      import('../../plugins/dynamic/tools/sandbox-execute.js'),
      import('../../runtime-client/delegation-server.js'),
      import('../../sample/sample-workspace.js'),
    ])
  return {
    sampleOperationGate: deps.sampleOperationGate,
    sandboxExecute: createRuntimeDelegatedToolHandler({
      definition: sandboxExecuteToolDefinition,
      pluginId: 'dynamic',
      runtimeClient: deps.runtimeClient,
      workspaceManager: deps.workspaceManager,
      database: deps.database,
      policyGuard: deps.policyGuard,
      resolvePrimarySamplePath: workspace.resolvePrimarySamplePath,
      sandboxDir: deps.sandboxDir ?? null,
    }),
  }
}

export function registerWorkflowTools(
  server: ToolRegistrar & SamplingClient,
  deps: ToolDeps
): Promise<void> {
  return registerWorkflowToolsAsync(server, deps)
}

async function registerWorkflowToolsAsync(
  server: ToolRegistrar & SamplingClient,
  deps: ToolDeps
): Promise<void> {
  const { workspaceManager, database, cacheManager, policyGuard, jobQueue } = deps
  const runtimeDependencies = await createWorkflowRuntimeDependencies(deps)
  const analyzeStartHandler = createAnalyzeWorkflowStartHandler(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    server,
    runtimeDependencies,
    jobQueue
  )
  const analyzePromoteHandler = createAnalyzeWorkflowPromoteHandler(
    workspaceManager,
    database,
    cacheManager,
    policyGuard,
    server,
    runtimeDependencies,
    jobQueue
  )
  const analyzeStatusHandler = createAnalyzeWorkflowStatusHandler(database, {}, jobQueue)
  const requestUploadHandler = createSampleRequestUploadHandler(database, {
    apiPort: deps.config.api.port,
    baseUrl: deps.config.api.publicBaseUrl,
  })
  server.registerTool(
    workflowRunToolDefinition,
    createWorkflowRunHandler({
      requestUpload: requestUploadHandler,
      start: analyzeStartHandler,
      status: analyzeStatusHandler,
      promote: analyzePromoteHandler,
    })
  )
  // The static OCI exposes one public workflow gateway. Compatibility and
  // deep workflow definitions are deliberately absent from the registry, so
  // progressive activation cannot instantiate a forbidden handler directly.
  if (isStaticDockerProfile()) return
  server.registerTool(
    triageWorkflowToolDefinition,
    createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
      analyzeStart: analyzeStartHandler,
    })
  )
  server.registerTool(analyzeWorkflowStartToolDefinition, analyzeStartHandler)
  server.registerTool(analyzeWorkflowStatusToolDefinition, analyzeStatusHandler)
  server.registerTool(analyzeWorkflowPromoteToolDefinition, analyzePromoteHandler)
  server.registerTool(
    analyzeAutoWorkflowToolDefinition,
    createAnalyzeAutoWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      server,
      {
        analyzeStartHandler,
        analyzePromoteHandler,
      },
      jobQueue
    )
  )
  server.registerTool(
    reconstructWorkflowToolDefinition,
    createReconstructWorkflowHandler(workspaceManager, database, cacheManager, undefined, jobQueue)
  )
  server.registerTool(
    deepStaticWorkflowToolDefinition,
    createDeepStaticWorkflowHandler(workspaceManager, database, cacheManager, jobQueue)
  )
  server.registerTool(
    functionIndexRecoverWorkflowToolDefinition,
    createFunctionIndexRecoverWorkflowHandler(workspaceManager, database, cacheManager)
  )
  server.registerTool(
    semanticNameReviewWorkflowToolDefinition,
    createSemanticNameReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      server,
      undefined,
      jobQueue
    )
  )
  server.registerTool(
    functionExplanationReviewWorkflowToolDefinition,
    createFunctionExplanationReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      server,
      undefined,
      jobQueue
    )
  )
  server.registerTool(
    moduleReconstructionReviewWorkflowToolDefinition,
    createModuleReconstructionReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      server,
      undefined,
      jobQueue
    )
  )
}
