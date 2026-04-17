import type { ToolRegistrar, SamplingClient } from '../registrar.js'
import { llmAnalyzeToolDefinition, createLlmAnalyzeHandler } from '../../llm/llm-analyze.js'

export function registerLlmTools(server: ToolRegistrar & SamplingClient): void {
  server.registerTool(llmAnalyzeToolDefinition, createLlmAnalyzeHandler(server))
}
