import type { MCPServer } from '../server.js'
import { llmAnalyzeToolDefinition, createLlmAnalyzeHandler } from '../../llm/llm-analyze.js'

export function registerLlmTools(server: MCPServer): void {
  server.registerTool(llmAnalyzeToolDefinition, createLlmAnalyzeHandler(server))
}
