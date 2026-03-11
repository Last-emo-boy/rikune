/**
 * Error handling and classification module
 * Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6
 */

import { ErrorCategory, ErrorContext, ErrorResult } from './types.js'

/**
 * Classify an error into a category
 * Requirements: 22.1, 22.2, 22.3
 */
export function classifyError(error: Error): ErrorCategory {
  const message = error.message.toLowerCase()

  // Timeout errors
  if (message.includes('timeout') || message.includes('timed out')) {
    return ErrorCategory.TIMEOUT
  }

  // Resource exhaustion
  if (
    message.includes('out of memory') ||
    message.includes('resource exhausted') ||
    message.includes('enomem') ||
    message.includes('enospc')
  ) {
    return ErrorCategory.RESOURCE_EXHAUSTED
  }

  // Worker unavailable
  if (
    message.includes('worker unavailable') ||
    message.includes('connection refused') ||
    message.includes('econnrefused')
  ) {
    return ErrorCategory.WORKER_UNAVAILABLE
  }

  // Invalid input
  if (
    message.includes('invalid input') ||
    message.includes('validation failed') ||
    message.includes('invalid argument')
  ) {
    return ErrorCategory.INVALID_INPUT
  }

  // Parse errors
  if (
    message.includes('parse error') ||
    message.includes('malformed') ||
    message.includes('invalid pe')
  ) {
    return ErrorCategory.PARSE_ERROR
  }

  // Policy denied
  if (
    message.includes('policy denied') ||
    message.includes('permission denied') ||
    message.includes('unauthorized')
  ) {
    return ErrorCategory.POLICY_DENIED
  }

  // Not found
  if (message.includes('not found') || message.includes('enoent')) {
    return ErrorCategory.NOT_FOUND
  }

  // Partial success
  if (message.includes('partial')) {
    return ErrorCategory.PARTIAL_SUCCESS
  }

  return ErrorCategory.UNKNOWN
}

/**
 * Calculate exponential backoff delay
 * Requirements: 22.4
 * 
 * Formula: min(baseMs * 2^attempt, maxMs) + jitter
 */
export function exponentialBackoff(
  attempt: number,
  baseMs: number = 1000,
  maxMs: number = 30000
): number {
  const exponentialDelay = Math.min(baseMs * Math.pow(2, attempt), maxMs)
  // Add jitter (0-20% of delay) to prevent thundering herd
  const jitter = Math.random() * 0.2 * exponentialDelay
  return Math.floor(exponentialDelay + jitter)
}

/**
 * Handle an error and determine retry strategy
 * Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6
 */
export function handleError(
  error: Error,
  context: ErrorContext
): ErrorResult {
  const category = classifyError(error)

  switch (category) {
    case ErrorCategory.TIMEOUT:
    case ErrorCategory.RESOURCE_EXHAUSTED:
    case ErrorCategory.WORKER_UNAVAILABLE:
      // Retryable errors with exponential backoff
      if (context.attempt < context.maxRetries) {
        return {
          shouldRetry: true,
          backoffMs: exponentialBackoff(context.attempt)
        }
      } else {
        return {
          shouldRetry: false,
          fallbackAction: 'notify_admin'
        }
      }

    case ErrorCategory.INVALID_INPUT:
    case ErrorCategory.POLICY_DENIED:
      // Non-retryable errors - log and fail immediately
      return {
        shouldRetry: false
      }

    case ErrorCategory.PARSE_ERROR:
      // Try fallback parser for PE parsing errors
      if (context.tool === 'pe.fingerprint') {
        return {
          shouldRetry: true,
          fallbackAction: 'use_lief_instead_of_pefile'
        }
      } else {
        return {
          shouldRetry: false
        }
      }

    case ErrorCategory.PARTIAL_SUCCESS:
      // Log warning but don't retry
      return {
        shouldRetry: false,
        fallbackAction: 'log_warning'
      }

    case ErrorCategory.NOT_FOUND:
      // Don't retry for not found errors
      return {
        shouldRetry: false
      }

    case ErrorCategory.UNKNOWN:
    default:
      // Unknown errors - don't retry by default
      return {
        shouldRetry: false,
        fallbackAction: 'log_error'
      }
  }
}

/**
 * Create a standardized error message
 */
export function formatErrorMessage(
  category: ErrorCategory,
  originalError: Error,
  context: ErrorContext
): string {
  return `[${category}] ${context.tool} failed for sample ${context.sampleId} (attempt ${context.attempt}/${context.maxRetries}): ${originalError.message}`
}

// Re-export types for convenience
export { ErrorCategory, ErrorContext, ErrorResult } from './types.js'
