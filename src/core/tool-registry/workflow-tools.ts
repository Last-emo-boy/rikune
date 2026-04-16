import type { ToolRegistrar, SamplingClient } from '../registrar.js'
import type { ToolDeps } from '../tool-registry.js'
import { triageWorkflowToolDefinition, createTriageWorkflowHandler } from '../../workflows/triage.js'
import { analyzeAutoWorkflowToolDefinition, createAnalyzeAutoWorkflowHandler } from '../../workflows/analyze-auto.js'
import {
  analyzeWorkflowPromoteToolDefinition,
  analyzeWorkflowStartToolDefinition,
  analyzeWorkflowStatusToolDefinition,
  createAnalyzeWorkflowPromoteHandler,
  createAnalyzeWorkflowStartHandler,
  createAnalyzeWorkflowStatusHandler,
} from '../../workflows/analyze-pipeline.js'
import { reconstructWorkflowToolDefinition, createReconstructWorkflowHandler } from '../../workflows/reconstruct.js'
import { deepStaticWorkflowToolDefinition, createDeepStaticWorkflowHandler } from '../../workflows/deep-static.js'
import { functionIndexRecoverWorkflowToolDefinition, createFunctionIndexRecoverWorkflowHandler } from '../../workflows/function-index-recover.js'
import { semanticNameReviewWorkflowToolDefinition, createSemanticNameReviewWorkflowHandler } from '../../workflows/semantic-name-review.js'
import { functionExplanationReviewWorkflowToolDefinition, createFunctionExplanationReviewWorkflowHandler } from '../../workflows/function-explanation-review.js'
import { moduleReconstructionReviewWorkflowToolDefinition, createModuleReconstructionReviewWorkflowHandler } from '../../workflows/module-reconstruction-review.js'

export function registerWorkflowTools(server: ToolRegistrar & SamplingClient, deps: ToolDeps): void {
  const { workspaceManager, database, cacheManager, policyGuard, jobQueue } = deps
  server.registerTool(triageWorkflowToolDefinition, createTriageWorkflowHandler(workspaceManager, database, cacheManager, {
    analyzeStart: createAnalyzeWorkflowStartHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue),
  }))
  server.registerTool(analyzeWorkflowStartToolDefinition, createAnalyzeWorkflowStartHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(analyzeWorkflowStatusToolDefinition, createAnalyzeWorkflowStatusHandler(database, {}, jobQueue))
  server.registerTool(analyzeWorkflowPromoteToolDefinition, createAnalyzeWorkflowPromoteHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(analyzeAutoWorkflowToolDefinition, createAnalyzeAutoWorkflowHandler(workspaceManager, database, cacheManager, policyGuard, server, {}, jobQueue))
  server.registerTool(reconstructWorkflowToolDefinition, createReconstructWorkflowHandler(workspaceManager, database, cacheManager, undefined, jobQueue))
  server.registerTool(deepStaticWorkflowToolDefinition, createDeepStaticWorkflowHandler(workspaceManager, database, cacheManager, jobQueue))
  server.registerTool(functionIndexRecoverWorkflowToolDefinition, createFunctionIndexRecoverWorkflowHandler(workspaceManager, database, cacheManager))
  server.registerTool(semanticNameReviewWorkflowToolDefinition, createSemanticNameReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))
  server.registerTool(functionExplanationReviewWorkflowToolDefinition, createFunctionExplanationReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))
  server.registerTool(moduleReconstructionReviewWorkflowToolDefinition, createModuleReconstructionReviewWorkflowHandler(workspaceManager, database, cacheManager, server, undefined, jobQueue))
}
