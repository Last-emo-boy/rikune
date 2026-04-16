/**
 * Response size guard
 *
 * Progressively prunes oversized tool results to fit LLM token budgets.
 */

import type { CallToolResult, TextContent } from '@modelcontextprotocol/sdk/types.js'
import pino from 'pino'

/**
 * Maximum response size in bytes before truncation kicks in.
 * ~200KB of JSON ≈ ~50-60K tokens — well within most LLM context windows.
 */
const MAX_RESPONSE_BYTES = 200 * 1024

function rebuildResult(original: CallToolResult, data: Record<string, unknown>): CallToolResult {
  const text = JSON.stringify(data)
  return {
    ...original,
    content: [{ type: 'text' as const, text }],
    structuredContent: data,
  }
}

function hardTruncateResult(original: CallToolResult, text: string): CallToolResult {
  const maxBytes = MAX_RESPONSE_BYTES
  // Binary-search a safe UTF-8 cut point
  let lo = 0, hi = Math.min(text.length, maxBytes)
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1
    if (Buffer.byteLength(text.slice(0, mid), 'utf8') <= maxBytes) {
      lo = mid
    } else {
      hi = mid - 1
    }
  }
  const truncated = text.slice(0, lo)
  const suffix = '\n\n[TRUNCATED: response exceeded token budget. Use more specific queries or request individual stages.]'
  const finalText = truncated + suffix
  return {
    ...original,
    content: [{ type: 'text' as const, text: finalText }],
    structuredContent: undefined,
  }
}

/**
 * Guard against oversized responses that would exceed LLM token limits.
 *
 * Strategy:
 *  1. Serialize once and measure byte length.
 *  2. If within budget → return as-is.
 *  3. Otherwise, progressively prune heavy fields:
 *     a. Strip `raw_results` from historical `run.stages[].result`
 *     b. Strip top-level `raw_results`
 *     c. Strip `run.stages[].result` entirely (keep stage metadata)
 *     d. As final fallback, hard-truncate the JSON text.
 *  4. Tag the response so the LLM knows data was trimmed.
 */
export function guardResponseSize(result: CallToolResult, logger: pino.Logger): CallToolResult {
  const text = (result.content as TextContent[])?.[0]?.text
  if (!text || Buffer.byteLength(text, 'utf8') <= MAX_RESPONSE_BYTES) {
    return result
  }

  // Try to parse and prune structured data
  let data: Record<string, unknown>
  try {
    data = JSON.parse(text)
  } catch (e) {
    logger.debug({ err: e }, 'Result text is not valid JSON, applying hard truncation')
    return hardTruncateResult(result, text)
  }

  // Phase 1: Strip raw_results from historical run.stages[].result
  const run = data.run as Record<string, unknown> | undefined
  if (run && Array.isArray(run.stages)) {
    for (const stage of run.stages as Array<Record<string, unknown>>) {
      if (stage.result && typeof stage.result === 'object' && !Array.isArray(stage.result)) {
        delete (stage.result as Record<string, unknown>).raw_results
      }
    }
  }
  let pruned = JSON.stringify(data)
  if (Buffer.byteLength(pruned, 'utf8') <= MAX_RESPONSE_BYTES) {
    data._response_trimmed = 'raw_results removed from historical stages to fit token budget'
    return rebuildResult(result, data)
  }

  // Phase 2: Strip top-level raw_results from stage_result
  const stageResult = data.stage_result as Record<string, unknown> | undefined
  if (stageResult && typeof stageResult === 'object') {
    delete stageResult.raw_results
  }
  // Also strip top-level data.raw_results
  delete data.raw_results
  pruned = JSON.stringify(data)
  if (Buffer.byteLength(pruned, 'utf8') <= MAX_RESPONSE_BYTES) {
    data._response_trimmed = 'raw_results removed from response to fit token budget'
    return rebuildResult(result, data)
  }

  // Phase 3: Strip all stage results entirely (keep metadata)
  if (run && Array.isArray(run.stages)) {
    for (const stage of run.stages as Array<Record<string, unknown>>) {
      if (stage.result) {
        stage.result = { _omitted: 'stage result removed to fit token budget' }
      }
    }
  }
  pruned = JSON.stringify(data)
  if (Buffer.byteLength(pruned, 'utf8') <= MAX_RESPONSE_BYTES) {
    data._response_trimmed = 'stage results omitted from run history to fit token budget; use workflow.analyze.status with include_stage_results=false or query individual stages'
    return rebuildResult(result, data)
  }

  // Phase 4: Hard truncate
  data._response_trimmed = 'response heavily truncated to fit token budget'
  return hardTruncateResult(result, JSON.stringify(data))
}
