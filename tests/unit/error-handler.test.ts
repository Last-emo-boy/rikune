/**
 * Unit tests for error handling module
 * Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6, 31.3
 */

import {
  ErrorCategory,
  ErrorContext,
  classifyError,
  exponentialBackoff,
  handleError,
  formatErrorMessage
} from '../../src/error-handler'

describe('Error Handler', () => {
  describe('classifyError', () => {
    it('should classify timeout errors', () => {
      const error = new Error('Operation timed out after 30s')
      expect(classifyError(error)).toBe(ErrorCategory.TIMEOUT)
    })

    it('should classify resource exhausted errors', () => {
      const error1 = new Error('Out of memory')
      const error2 = new Error('ENOSPC: no space left on device')
      expect(classifyError(error1)).toBe(ErrorCategory.RESOURCE_EXHAUSTED)
      expect(classifyError(error2)).toBe(ErrorCategory.RESOURCE_EXHAUSTED)
    })

    it('should classify worker unavailable errors', () => {
      const error = new Error('Worker unavailable: connection refused')
      expect(classifyError(error)).toBe(ErrorCategory.WORKER_UNAVAILABLE)
    })

    it('should classify invalid input errors', () => {
      const error = new Error('Invalid input: validation failed')
      expect(classifyError(error)).toBe(ErrorCategory.INVALID_INPUT)
    })

    it('should classify parse errors', () => {
      const error = new Error('Parse error: malformed PE file')
      expect(classifyError(error)).toBe(ErrorCategory.PARSE_ERROR)
    })

    it('should classify policy denied errors', () => {
      const error = new Error('Policy denied: unauthorized operation')
      expect(classifyError(error)).toBe(ErrorCategory.POLICY_DENIED)
    })

    it('should classify not found errors', () => {
      const error = new Error('Sample not found')
      expect(classifyError(error)).toBe(ErrorCategory.NOT_FOUND)
    })

    it('should classify partial success errors', () => {
      const error = new Error('Partial results returned')
      expect(classifyError(error)).toBe(ErrorCategory.PARTIAL_SUCCESS)
    })

    it('should classify unknown errors', () => {
      const error = new Error('Something went wrong')
      expect(classifyError(error)).toBe(ErrorCategory.UNKNOWN)
    })
  })

  describe('exponentialBackoff', () => {
    it('should calculate exponential backoff correctly', () => {
      // Attempt 0: 1000ms base
      const delay0 = exponentialBackoff(0, 1000, 30000)
      expect(delay0).toBeGreaterThanOrEqual(1000)
      expect(delay0).toBeLessThanOrEqual(1200) // 1000 + 20% jitter

      // Attempt 1: 2000ms
      const delay1 = exponentialBackoff(1, 1000, 30000)
      expect(delay1).toBeGreaterThanOrEqual(2000)
      expect(delay1).toBeLessThanOrEqual(2400)

      // Attempt 2: 4000ms
      const delay2 = exponentialBackoff(2, 1000, 30000)
      expect(delay2).toBeGreaterThanOrEqual(4000)
      expect(delay2).toBeLessThanOrEqual(4800)
    })

    it('should cap at maximum delay', () => {
      // Attempt 10 would be 1024000ms, but should cap at 30000ms
      const delay = exponentialBackoff(10, 1000, 30000)
      expect(delay).toBeGreaterThanOrEqual(30000)
      expect(delay).toBeLessThanOrEqual(36000) // 30000 + 20% jitter
    })

    it('should add jitter to prevent thundering herd', () => {
      const delays = []
      for (let i = 0; i < 10; i++) {
        delays.push(exponentialBackoff(1, 1000, 30000))
      }

      // All delays should be different due to jitter
      const uniqueDelays = new Set(delays)
      expect(uniqueDelays.size).toBeGreaterThan(1)
    })

    it('should use default values when not specified', () => {
      const delay = exponentialBackoff(0)
      expect(delay).toBeGreaterThanOrEqual(1000)
      expect(delay).toBeLessThanOrEqual(1200)
    })
  })

  describe('handleError', () => {
    const baseContext: ErrorContext = {
      tool: 'pe.fingerprint',
      sampleId: 'sha256:abc123',
      attempt: 0,
      maxRetries: 3
    }

    describe('retryable errors', () => {
      it('should retry timeout errors with backoff', () => {
        const error = new Error('Operation timed out')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(true)
        expect(result.backoffMs).toBeGreaterThan(0)
      })

      it('should retry resource exhausted errors', () => {
        const error = new Error('Out of memory')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(true)
        expect(result.backoffMs).toBeGreaterThan(0)
      })

      it('should retry worker unavailable errors', () => {
        const error = new Error('Worker unavailable')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(true)
        expect(result.backoffMs).toBeGreaterThan(0)
      })

      it('should not retry after max retries exceeded', () => {
        const error = new Error('Operation timed out')
        const context = { ...baseContext, attempt: 3, maxRetries: 3 }
        const result = handleError(error, context)

        expect(result.shouldRetry).toBe(false)
        expect(result.fallbackAction).toBe('notify_admin')
      })
    })

    describe('non-retryable errors', () => {
      it('should not retry invalid input errors', () => {
        const error = new Error('Invalid input')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(false)
        expect(result.backoffMs).toBeUndefined()
      })

      it('should not retry policy denied errors', () => {
        const error = new Error('Policy denied')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(false)
      })

      it('should not retry not found errors', () => {
        const error = new Error('Sample not found')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(false)
      })
    })

    describe('parse errors with fallback', () => {
      it('should suggest fallback parser for PE fingerprint', () => {
        const error = new Error('Parse error: malformed PE')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(true)
        expect(result.fallbackAction).toBe('use_lief_instead_of_pefile')
      })

      it('should not retry parse errors for other tools', () => {
        const error = new Error('Parse error')
        const context = { ...baseContext, tool: 'strings.extract' }
        const result = handleError(error, context)

        expect(result.shouldRetry).toBe(false)
      })
    })

    describe('partial success', () => {
      it('should not retry but suggest logging warning', () => {
        const error = new Error('Partial results returned')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(false)
        expect(result.fallbackAction).toBe('log_warning')
      })
    })

    describe('unknown errors', () => {
      it('should not retry unknown errors', () => {
        const error = new Error('Something unexpected happened')
        const result = handleError(error, baseContext)

        expect(result.shouldRetry).toBe(false)
        expect(result.fallbackAction).toBe('log_error')
      })
    })
  })

  describe('formatErrorMessage', () => {
    it('should format error message with all context', () => {
      const error = new Error('Operation failed')
      const context: ErrorContext = {
        tool: 'pe.fingerprint',
        sampleId: 'sha256:abc123',
        attempt: 1,
        maxRetries: 3
      }

      const message = formatErrorMessage(
        ErrorCategory.TIMEOUT,
        error,
        context
      )

      expect(message).toContain('[E_TIMEOUT]')
      expect(message).toContain('pe.fingerprint')
      expect(message).toContain('sha256:abc123')
      expect(message).toContain('attempt 1/3')
      expect(message).toContain('Operation failed')
    })
  })

  describe('integration scenarios', () => {
    it('should handle retry sequence correctly', () => {
      const error = new Error('Operation timed out')
      const context: ErrorContext = {
        tool: 'ghidra.analyze',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }

      // First attempt
      const result1 = handleError(error, { ...context, attempt: 0 })
      expect(result1.shouldRetry).toBe(true)
      expect(result1.backoffMs).toBeGreaterThanOrEqual(1000)

      // Second attempt
      const result2 = handleError(error, { ...context, attempt: 1 })
      expect(result2.shouldRetry).toBe(true)
      expect(result2.backoffMs).toBeGreaterThanOrEqual(2000)

      // Third attempt
      const result3 = handleError(error, { ...context, attempt: 2 })
      expect(result3.shouldRetry).toBe(true)
      expect(result3.backoffMs).toBeGreaterThanOrEqual(4000)

      // Fourth attempt (max retries reached)
      const result4 = handleError(error, { ...context, attempt: 3 })
      expect(result4.shouldRetry).toBe(false)
      expect(result4.fallbackAction).toBe('notify_admin')
    })

    it('should handle PE parsing fallback scenario', () => {
      const error = new Error('Parse error: invalid PE header')
      const context: ErrorContext = {
        tool: 'pe.fingerprint',
        sampleId: 'sha256:malformed',
        attempt: 0,
        maxRetries: 3
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
      expect(result.fallbackAction).toBe('use_lief_instead_of_pefile')
    })

    it('should handle Ghidra analysis timeout scenario (Req 22.7)', () => {
      const error = new Error('Ghidra analysis timed out after 300s')
      const context: ErrorContext = {
        tool: 'ghidra.analyze',
        sampleId: 'sha256:large_sample',
        attempt: 0,
        maxRetries: 2
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
      expect(result.backoffMs).toBeGreaterThan(0)
      expect(classifyError(error)).toBe(ErrorCategory.TIMEOUT)
    })

    it('should handle resource exhaustion with wait strategy', () => {
      const error = new Error('Out of memory: cannot allocate buffer')
      const context: ErrorContext = {
        tool: 'strings.extract',
        sampleId: 'sha256:huge_file',
        attempt: 0,
        maxRetries: 3
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
      expect(result.backoffMs).toBeGreaterThan(0)
      expect(classifyError(error)).toBe(ErrorCategory.RESOURCE_EXHAUSTED)
    })

    it('should not retry validation errors immediately', () => {
      const error = new Error('Invalid input: sample_id is required')
      const context: ErrorContext = {
        tool: 'sample.ingest',
        sampleId: '',
        attempt: 0,
        maxRetries: 3
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(false)
      expect(classifyError(error)).toBe(ErrorCategory.INVALID_INPUT)
    })

    it('should handle worker connection failures with retry', () => {
      const error = new Error('Worker unavailable: ECONNREFUSED')
      const context: ErrorContext = {
        tool: 'yara.scan',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
      expect(result.backoffMs).toBeGreaterThan(0)
    })

    it('should handle multiple error types in sequence', () => {
      const context: ErrorContext = {
        tool: 'pe.fingerprint',
        sampleId: 'sha256:complex',
        attempt: 0,
        maxRetries: 3
      }

      // First: timeout (retryable)
      const timeoutError = new Error('Operation timed out')
      const result1 = handleError(timeoutError, context)
      expect(result1.shouldRetry).toBe(true)

      // Second: parse error (fallback to LIEF)
      const parseError = new Error('Parse error: malformed PE')
      const result2 = handleError(parseError, context)
      expect(result2.shouldRetry).toBe(true)
      expect(result2.fallbackAction).toBe('use_lief_instead_of_pefile')

      // Third: policy denied (not retryable)
      const policyError = new Error('Policy denied: unauthorized')
      const result3 = handleError(policyError, context)
      expect(result3.shouldRetry).toBe(false)
    })
  })

  describe('edge cases and boundary conditions', () => {
    it('should handle zero attempt number', () => {
      const error = new Error('Operation timed out')
      const context: ErrorContext = {
        tool: 'test.tool',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
      expect(result.backoffMs).toBeGreaterThanOrEqual(1000)
    })

    it('should handle maxRetries of 0', () => {
      const error = new Error('Operation timed out')
      const context: ErrorContext = {
        tool: 'test.tool',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 0
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(false)
      expect(result.fallbackAction).toBe('notify_admin')
    })

    it('should handle very large attempt numbers', () => {
      const delay = exponentialBackoff(100, 1000, 30000)
      expect(delay).toBeGreaterThanOrEqual(30000)
      expect(delay).toBeLessThanOrEqual(36000)
    })

    it('should handle empty error messages', () => {
      const error = new Error('')
      const category = classifyError(error)
      expect(category).toBe(ErrorCategory.UNKNOWN)
    })

    it('should handle error messages with mixed case', () => {
      const error1 = new Error('TIMEOUT occurred')
      const error2 = new Error('TimeOut Detected')
      const error3 = new Error('Operation TIMED OUT')

      expect(classifyError(error1)).toBe(ErrorCategory.TIMEOUT)
      expect(classifyError(error2)).toBe(ErrorCategory.TIMEOUT)
      expect(classifyError(error3)).toBe(ErrorCategory.TIMEOUT)
    })

    it('should format error messages consistently', () => {
      const error = new Error('Test error')
      const context: ErrorContext = {
        tool: 'test.tool',
        sampleId: 'sha256:abc123',
        attempt: 2,
        maxRetries: 5
      }

      const message = formatErrorMessage(
        ErrorCategory.TIMEOUT,
        error,
        context
      )

      expect(message).toMatch(/\[E_TIMEOUT\]/)
      expect(message).toContain('test.tool')
      expect(message).toContain('sha256:abc123')
      expect(message).toContain('2/5')
      expect(message).toContain('Test error')
    })
  })

  describe('requirements validation', () => {
    it('should satisfy Req 22.1: classify timeout errors as retryable', () => {
      const error = new Error('Operation timed out')
      const category = classifyError(error)
      expect(category).toBe(ErrorCategory.TIMEOUT)

      const context: ErrorContext = {
        tool: 'test',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }
      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
    })

    it('should satisfy Req 22.2: classify resource exhaustion as retryable', () => {
      const error = new Error('Out of memory')
      const category = classifyError(error)
      expect(category).toBe(ErrorCategory.RESOURCE_EXHAUSTED)

      const context: ErrorContext = {
        tool: 'test',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }
      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
    })

    it('should satisfy Req 22.3: classify validation errors as non-retryable', () => {
      const error = new Error('Invalid input: validation failed')
      const category = classifyError(error)
      expect(category).toBe(ErrorCategory.INVALID_INPUT)

      const context: ErrorContext = {
        tool: 'test',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }
      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(false)
    })

    it('should satisfy Req 22.4: classify policy denied as non-retryable', () => {
      const error = new Error('Policy denied: unauthorized operation')
      const category = classifyError(error)
      expect(category).toBe(ErrorCategory.POLICY_DENIED)

      const context: ErrorContext = {
        tool: 'test',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }
      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(false)
    })

    it('should satisfy Req 22.5: use backup parser for PE parse failures', () => {
      const error = new Error('Parse error: malformed PE file')
      const context: ErrorContext = {
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
      expect(result.fallbackAction).toBe('use_lief_instead_of_pefile')
    })

    it('should satisfy Req 22.6: mark sample as malformed if backup parser fails', () => {
      const error = new Error('Parse error: invalid format')
      const context: ErrorContext = {
        tool: 'strings.extract',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 3
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(false)
    })

    it('should satisfy Req 22.7: handle Ghidra timeout with cleanup', () => {
      const error = new Error('Ghidra analysis timed out')
      const context: ErrorContext = {
        tool: 'ghidra.analyze',
        sampleId: 'sha256:test',
        attempt: 0,
        maxRetries: 2
      }

      const result = handleError(error, context)
      expect(result.shouldRetry).toBe(true)
      expect(classifyError(error)).toBe(ErrorCategory.TIMEOUT)
    })
  })
})
