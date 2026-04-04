/**
 * Example usage of the error handler module
 * This file demonstrates how to integrate error handling into tools and workers
 */

import {
  handleError,
  classifyError,
  formatErrorMessage,
  ErrorContext,
  ErrorCategory
} from './error-handler.js'

/**
 * Example: Retry logic for a tool with exponential backoff
 */
async function executeToolWithRetry<T>(
  toolName: string,
  sampleId: string,
  operation: () => Promise<T>,
  maxRetries: number = 3
): Promise<T> {
  let lastError: Error | null = null

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await operation()
    } catch (error) {
      lastError = error as Error

      const context: ErrorContext = {
        tool: toolName,
        sampleId,
        attempt,
        maxRetries
      }

      const result = handleError(lastError, context)

      // Log the error with formatted message
      const category = classifyError(lastError)
      const message = formatErrorMessage(category, lastError, context)
      console.error(message)

      if (!result.shouldRetry) {
        // Handle fallback actions
        if (result.fallbackAction === 'use_lief_instead_of_pefile') {
          console.log('Attempting fallback parser...')
          // Implement fallback logic here
        } else if (result.fallbackAction === 'log_warning') {
          console.warn('Partial success, continuing...')
        } else if (result.fallbackAction === 'notify_admin') {
          console.error('Max retries exceeded, admin notification required')
        }

        throw lastError
      }

      // Wait before retrying
      if (result.backoffMs) {
        console.log(`Retrying in ${result.backoffMs}ms...`)
        await sleep(result.backoffMs)
      }
    }
  }

  throw lastError!
}

/**
 * Example: PE fingerprint tool with fallback parser
 */
async function peFingerprint(sampleId: string, useLief: boolean = false) {
  const context: ErrorContext = {
    tool: 'pe.fingerprint',
    sampleId,
    attempt: 0,
    maxRetries: 1
  }

  try {
    if (useLief) {
      // Use LIEF parser
      return await parsePEWithLief(sampleId)
    } else {
      // Use pefile parser
      return await parsePEWithPefile(sampleId)
    }
  } catch (error) {
    const result = handleError(error as Error, context)

    if (result.fallbackAction === 'use_lief_instead_of_pefile') {
      console.log('Primary parser failed, trying LIEF...')
      return await peFingerprint(sampleId, true)
    }

    throw error
  }
}

/**
 * Example: Ghidra analysis with timeout handling
 */
async function ghidraAnalyze(sampleId: string) {
  return executeToolWithRetry(
    'ghidra.analyze',
    sampleId,
    async () => {
      // Simulate Ghidra analysis
      const result = await runGhidraHeadless(sampleId)
      return result
    },
    3 // Max 3 retries for timeout errors
  )
}

/**
 * Example: Policy-denied error (non-retryable)
 */
async function sandboxExecute(sampleId: string, requireApproval: boolean) {
  const context: ErrorContext = {
    tool: 'sandbox.execute',
    sampleId,
    attempt: 0,
    maxRetries: 0 // No retries for policy errors
  }

  try {
    if (!requireApproval) {
      throw new Error('Policy denied: approval required for dynamic execution')
    }

    return await executeSandbox(sampleId)
  } catch (error) {
    const result = handleError(error as Error, context)

    if (!result.shouldRetry) {
      const category = classifyError(error as Error)
      if (category === ErrorCategory.POLICY_DENIED) {
        console.error('Operation denied by policy guard')
        // Log to audit log
      }
    }

    throw error
  }
}

// Helper functions (stubs for demonstration)
async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

async function parsePEWithPefile(_sampleId: string): Promise<any> {
  // Stub implementation
  throw new Error('Parse error: malformed PE header')
}

async function parsePEWithLief(_sampleId: string): Promise<any> {
  // Stub implementation
  return { success: true, parser: 'lief' }
}

async function runGhidraHeadless(_sampleId: string): Promise<any> {
  // Stub implementation
  return { functions: [] }
}

async function executeSandbox(_sampleId: string): Promise<any> {
  // Stub implementation
  return { traces: [] }
}

// Export examples for documentation
export {
  executeToolWithRetry,
  peFingerprint,
  ghidraAnalyze,
  sandboxExecute
}
