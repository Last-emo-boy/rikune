/**
 * Error handling module
 * Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6, 31.3
 */

export { ErrorCategory } from './types.js'
export type { ErrorContext, ErrorResult } from './types.js'

import { ErrorCategory } from './types.js'
import type { ErrorContext, ErrorResult } from './types.js'

/**
 * Classify an error into an ErrorCategory based on its message
 */
export function classifyError(error: Error): ErrorCategory {
  const msg = error.message.toLowerCase()

  if (msg.includes('timed out') || msg.includes('timeout')) return ErrorCategory.TIMEOUT
  if (msg.includes('out of memory') || msg.includes('enospc') || msg.includes('resource exhausted')) return ErrorCategory.RESOURCE_EXHAUSTED
  if (msg.includes('worker unavailable') || msg.includes('connection refused')) return ErrorCategory.WORKER_UNAVAILABLE
  if (msg.includes('invalid input') || msg.includes('validation failed')) return ErrorCategory.INVALID_INPUT
  if (msg.includes('parse error') || msg.includes('malformed pe')) return ErrorCategory.PARSE_ERROR
  if (msg.includes('policy denied') || msg.includes('unauthorized')) return ErrorCategory.POLICY_DENIED
  if (msg.includes('not found')) return ErrorCategory.NOT_FOUND
  if (msg.includes('partial') && msg.includes('result')) return ErrorCategory.PARTIAL_SUCCESS

  return ErrorCategory.UNKNOWN
}

/**
 * Calculate exponential backoff delay with jitter
 */
export function exponentialBackoff(
  attempt: number,
  baseDelay: number = 1000,
  maxDelay: number = 30000
): number {
  const delay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay)
  const jitter = delay * 0.2 * Math.random()
  return delay + jitter
}

const RETRYABLE_CATEGORIES = new Set([
  ErrorCategory.TIMEOUT,
  ErrorCategory.RESOURCE_EXHAUSTED,
  ErrorCategory.WORKER_UNAVAILABLE,
])

/**
 * Handle an error and determine retry/fallback behavior
 */
export function handleError(error: Error, context: ErrorContext): ErrorResult {
  const category = classifyError(error)

  // Parse errors with PE analysis tools get a fallback
  if (category === ErrorCategory.PARSE_ERROR) {
    if (context.tool === 'pe.fingerprint') {
      return {
        shouldRetry: true,
        backoffMs: exponentialBackoff(context.attempt),
        fallbackAction: 'use_lief_instead_of_pefile',
      }
    }
    return { shouldRetry: false }
  }

  // Partial success: don't retry, just log
  if (category === ErrorCategory.PARTIAL_SUCCESS) {
    return { shouldRetry: false, fallbackAction: 'log_warning' }
  }

  // Non-retryable categories
  if (!RETRYABLE_CATEGORIES.has(category)) {
    if (category === ErrorCategory.UNKNOWN) {
      return { shouldRetry: false, fallbackAction: 'log_error' }
    }
    return { shouldRetry: false }
  }

  // Retryable: check if max retries exceeded
  if (context.attempt >= context.maxRetries) {
    return { shouldRetry: false, fallbackAction: 'notify_admin' }
  }

  return {
    shouldRetry: true,
    backoffMs: exponentialBackoff(context.attempt),
  }
}

/**
 * Format an error message with context for logging
 */
export function formatErrorMessage(
  category: ErrorCategory,
  error: Error,
  context: ErrorContext
): string {
  return `[${category}] ${context.tool} (sample: ${context.sampleId}, attempt ${context.attempt}/${context.maxRetries}): ${error.message}`
}
