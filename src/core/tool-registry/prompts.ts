import type { MCPServer } from '../server.js'
import {
  semanticNameReviewPromptDefinition,
  createSemanticNameReviewPromptHandler,
} from '../../prompts/semantic-name-review.js'
import {
  functionExplanationReviewPromptDefinition,
  createFunctionExplanationReviewPromptHandler,
} from '../../prompts/function-explanation-review.js'
import {
  moduleReconstructionReviewPromptDefinition,
  createModuleReconstructionReviewPromptHandler,
} from '../../prompts/module-reconstruction-review.js'

export function registerPrompts(server: MCPServer): void {
  server.registerPrompt(semanticNameReviewPromptDefinition, createSemanticNameReviewPromptHandler())
  server.registerPrompt(functionExplanationReviewPromptDefinition, createFunctionExplanationReviewPromptHandler())
  server.registerPrompt(moduleReconstructionReviewPromptDefinition, createModuleReconstructionReviewPromptHandler())
}
