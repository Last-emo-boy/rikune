/**
 * Shared helpers for LLM sampling/review tools.
 */

import type {
  CreateMessageResult,
  CreateMessageResultWithTools,
  TextContent,
} from '@modelcontextprotocol/sdk/types.js'

export type SamplingResult = CreateMessageResult | CreateMessageResultWithTools

export function extractTextBlocks(result: SamplingResult): string {
  const blocks = Array.isArray(result.content) ? result.content : [result.content]
  return blocks
    .filter((block): block is TextContent => block?.type === 'text')
    .map((block) => block.text || '')
    .join('\n')
    .trim()
}
