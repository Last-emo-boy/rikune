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

function hardTruncateResult(
  original: CallToolResult,
  text: string,
  structuredData?: Record<string, unknown>
): CallToolResult {
  const maxBytes = MAX_RESPONSE_BYTES
  // Binary-search a safe UTF-8 cut point
  let lo = 0,
    hi = Math.min(text.length, maxBytes)
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1
    if (Buffer.byteLength(text.slice(0, mid), 'utf8') <= maxBytes) {
      lo = mid
    } else {
      hi = mid - 1
    }
  }
  const truncated = text.slice(0, lo)
  const suffix =
    '\n\n[TRUNCATED: response exceeded token budget. Use more specific queries or request individual stages.]'
  const finalText = truncated + suffix
  return {
    ...original,
    content: [{ type: 'text' as const, text: finalText }],
    structuredContent:
      structuredData ||
      ({
        ok: false,
        warnings: [
          'Response exceeded the MCP response size budget and could not be structurally pruned.',
        ],
      } as Record<string, unknown>),
  }
}

function payloadRoot(data: Record<string, unknown>): Record<string, unknown> {
  const nested = data.data
  return nested && typeof nested === 'object' && !Array.isArray(nested)
    ? (nested as Record<string, unknown>)
    : data
}

function setTrimmedMarker(data: Record<string, unknown>, message: string): void {
  if (Array.isArray(data.warnings)) {
    data.warnings = [...data.warnings.map(String), message]
    return
  }
  data.warnings = [message]
}

function pruneRunStageRawResults(root: Record<string, unknown>): void {
  const run = root.run as Record<string, unknown> | undefined
  if (!run || !Array.isArray(run.stages)) {
    return
  }
  for (const stage of run.stages as Array<Record<string, unknown>>) {
    if (stage.result && typeof stage.result === 'object' && !Array.isArray(stage.result)) {
      delete (stage.result as Record<string, unknown>).raw_results
    }
  }
}

function pruneTopLevelRawResults(root: Record<string, unknown>): void {
  const stageResult = root.stage_result as Record<string, unknown> | undefined
  if (stageResult && typeof stageResult === 'object' && !Array.isArray(stageResult)) {
    delete stageResult.raw_results
  }
  delete root.raw_results
}

function omitRunStageResults(root: Record<string, unknown>): void {
  const run = root.run as Record<string, unknown> | undefined
  if (!run || !Array.isArray(run.stages)) {
    return
  }
  for (const stage of run.stages as Array<Record<string, unknown>>) {
    if (stage.result) {
      stage.result = { _omitted: 'stage result removed to fit token budget' }
    }
  }
}

function omitLiveStageResult(root: Record<string, unknown>): void {
  if (root.stage_result) {
    root.stage_result = {
      _omitted:
        'latest stage result removed to fit token budget; query the specific stage artifact or rerun with narrower output',
    }
  }
  const run = root.run as Record<string, unknown> | undefined
  if (run && Array.isArray(run.stages)) {
    for (const stage of run.stages as Array<Record<string, unknown>>) {
      if (Array.isArray(stage.artifact_refs) && stage.artifact_refs.length > 20) {
        stage.artifact_refs = stage.artifact_refs.slice(0, 20)
      }
    }
  }
  delete root.runtime_explanation_graph
  delete root.unpack_plan
  delete root.unpack_execution
  delete root.diff_digests
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
  const root = payloadRoot(data)

  // Phase 1: Strip raw_results from historical run.stages[].result
  pruneRunStageRawResults(root)
  let pruned = JSON.stringify(data)
  if (Buffer.byteLength(pruned, 'utf8') <= MAX_RESPONSE_BYTES) {
    setTrimmedMarker(data, 'raw_results removed from historical stages to fit token budget')
    return rebuildResult(result, data)
  }

  // Phase 2: Strip top-level raw_results from stage_result
  pruneTopLevelRawResults(root)
  pruned = JSON.stringify(data)
  if (Buffer.byteLength(pruned, 'utf8') <= MAX_RESPONSE_BYTES) {
    setTrimmedMarker(data, 'raw_results removed from response to fit token budget')
    return rebuildResult(result, data)
  }

  // Phase 3: Strip all stage results entirely (keep metadata)
  omitRunStageResults(root)
  pruned = JSON.stringify(data)
  if (Buffer.byteLength(pruned, 'utf8') <= MAX_RESPONSE_BYTES) {
    setTrimmedMarker(
      data,
      'stage results omitted from run history to fit token budget; use workflow.analyze.status with include_stage_results=false or query individual stages'
    )
    return rebuildResult(result, data)
  }

  // Phase 4: Strip latest stage result and optional heavyweight digests.
  omitLiveStageResult(root)
  pruned = JSON.stringify(data)
  if (Buffer.byteLength(pruned, 'utf8') <= MAX_RESPONSE_BYTES) {
    setTrimmedMarker(
      data,
      'latest stage result and heavyweight digests omitted to fit token budget; use artifact.read or a stage-specific tool for details'
    )
    return rebuildResult(result, data)
  }

  // Phase 5: Hard truncate text, but keep structuredContent present so MCP tools with
  // outputSchema do not fail with "did not return structured content".
  setTrimmedMarker(data, 'response heavily truncated to fit token budget')
  return hardTruncateResult(result, JSON.stringify(data), data)
}
