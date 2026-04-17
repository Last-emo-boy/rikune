/**
 * Centralized error hierarchy for Rikune.
 *
 * Every public-facing error SHOULD be an instance (or subclass) of
 * `RikuneError` so that callers can rely on a stable shape:
 *   { code, message, recoverable, details? }
 *
 * Error codes use the `E_` prefix followed by a domain-specific tag
 * (e.g. `E_SAMPLE_NOT_FOUND`, `E_JOB_TIMEOUT`).
 */

// ─── Error codes ──────────────────────────────────────────────────────────────

export const ErrorCode = {
  // generic
  E_INTERNAL: 'E_INTERNAL',
  E_INVALID_INPUT: 'E_INVALID_INPUT',
  E_NOT_FOUND: 'E_NOT_FOUND',
  E_UNAUTHORIZED: 'E_UNAUTHORIZED',
  E_RATE_LIMITED: 'E_RATE_LIMITED',

  // sample lifecycle
  E_SAMPLE_NOT_FOUND: 'E_SAMPLE_NOT_FOUND',
  E_SAMPLE_TOO_LARGE: 'E_SAMPLE_TOO_LARGE',
  E_SAMPLE_DUPLICATE: 'E_SAMPLE_DUPLICATE',

  // storage
  E_STORAGE_FULL: 'E_STORAGE_FULL',
  E_STORAGE_IO: 'E_STORAGE_IO',
  E_QUOTA_EXCEEDED: 'E_QUOTA_EXCEEDED',

  // database
  E_DB_CONSTRAINT: 'E_DB_CONSTRAINT',
  E_DB_TRANSACTION: 'E_DB_TRANSACTION',
  E_DB_CONNECTION: 'E_DB_CONNECTION',

  // job / async
  E_JOB_NOT_FOUND: 'E_JOB_NOT_FOUND',
  E_JOB_TIMEOUT: 'E_JOB_TIMEOUT',
  E_JOB_CANCELLED: 'E_JOB_CANCELLED',

  // backend / toolchain
  E_BACKEND_UNAVAILABLE: 'E_BACKEND_UNAVAILABLE',
  E_BACKEND_EXEC: 'E_BACKEND_EXEC',
  E_TIMEOUT: 'E_TIMEOUT',
  E_RESOURCE_EXHAUSTED: 'E_RESOURCE_EXHAUSTED',
  E_WORKER_UNAVAILABLE: 'E_WORKER_UNAVAILABLE',

  // config
  E_CONFIG_INVALID: 'E_CONFIG_INVALID',

  // upload
  E_UPLOAD_EXPIRED: 'E_UPLOAD_EXPIRED',
  E_UPLOAD_INVALID: 'E_UPLOAD_INVALID',

  // cache
  E_CACHE_MISS: 'E_CACHE_MISS',
  E_CACHE_CORRUPT: 'E_CACHE_CORRUPT',
} as const

export type ErrorCodeType = (typeof ErrorCode)[keyof typeof ErrorCode]

// ─── Recovery hints ───────────────────────────────────────────────────────────

const RECOVERY_HINTS: Partial<Record<ErrorCodeType, string>> = {
  E_SAMPLE_NOT_FOUND: 'Re-ingest the sample with sample.ingest, then retry.',
  E_SAMPLE_TOO_LARGE: 'Reduce file size or increase workspace.maxSampleSize in config.',
  E_STORAGE_FULL: 'Run storage.cleanup or increase storage quota.',
  E_QUOTA_EXCEEDED: 'Delete old samples or raise the quota limit.',
  E_JOB_TIMEOUT: 'The job exceeded its timeout.  Consider increasing the timeout or splitting the workload.',
  E_BACKEND_UNAVAILABLE: 'Ensure the required backend is installed and reachable.',
  E_RATE_LIMITED: 'Wait a moment and retry the request.',
  E_CONFIG_INVALID: 'Check the configuration file for syntax or schema errors.',
  E_UPLOAD_EXPIRED: 'Create a new upload session and re-upload.',
  E_TIMEOUT: 'Operation took too long.  Consider increasing the timeout.',
  E_RESOURCE_EXHAUSTED: 'System resources are exhausted.  Wait and retry.',
  E_WORKER_UNAVAILABLE: 'No workers available.  Wait for a worker to become free.',
}

// ─── Base error class ─────────────────────────────────────────────────────────

export class RikuneError extends Error {
  /** Machine-readable error code (`E_*`). */
  readonly code: ErrorCodeType
  /** Whether the caller can meaningfully retry or take corrective action. */
  readonly recoverable: boolean
  /** Arbitrary structured context. */
  readonly details: Record<string, unknown>
  /** Human-readable recovery suggestion (auto-populated from RECOVERY_HINTS). */
  readonly hint: string | undefined

  constructor(
    code: ErrorCodeType,
    message: string,
    options?: {
      recoverable?: boolean
      details?: Record<string, unknown>
      cause?: unknown
      hint?: string
    },
  ) {
    super(message, { cause: options?.cause })
    this.name = 'RikuneError'
    this.code = code
    this.recoverable = options?.recoverable ?? false
    this.details = options?.details ?? {}
    this.hint = options?.hint ?? RECOVERY_HINTS[code]
  }

  /** Serialise to a JSON-safe shape suitable for MCP tool responses. */
  toJSON(): Record<string, unknown> {
    return {
      error: true,
      code: this.code,
      message: this.message,
      recoverable: this.recoverable,
      hint: this.hint,
      details: Object.keys(this.details).length > 0 ? this.details : undefined,
    }
  }
}

// ─── Convenience subclasses ───────────────────────────────────────────────────

export class NotFoundError extends RikuneError {
  constructor(entity: string, id: string, options?: { cause?: unknown }) {
    const code = entity === 'sample' ? ErrorCode.E_SAMPLE_NOT_FOUND
      : entity === 'job' ? ErrorCode.E_JOB_NOT_FOUND
      : ErrorCode.E_NOT_FOUND
    super(code, `${entity} not found: ${id}`, { recoverable: false, ...options })
    this.name = 'NotFoundError'
  }
}

export class ValidationError extends RikuneError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCode.E_INVALID_INPUT, message, { recoverable: true, details })
    this.name = 'ValidationError'
  }
}

export class StorageError extends RikuneError {
  constructor(
    code: ErrorCodeType,
    message: string,
    options?: { recoverable?: boolean; details?: Record<string, unknown>; cause?: unknown },
  ) {
    super(code, message, { recoverable: options?.recoverable ?? false, ...options })
    this.name = 'StorageError'
  }
}

export class BackendError extends RikuneError {
  constructor(
    backend: string,
    message: string,
    options?: { cause?: unknown; details?: Record<string, unknown> },
  ) {
    super(ErrorCode.E_BACKEND_EXEC, `[${backend}] ${message}`, {
      recoverable: false,
      details: { backend, ...options?.details },
      cause: options?.cause,
    })
    this.name = 'BackendError'
  }
}

export class TimeoutError extends RikuneError {
  constructor(operation: string, timeoutMs: number, options?: { cause?: unknown }) {
    super(ErrorCode.E_TIMEOUT, `${operation} timed out after ${timeoutMs}ms`, {
      recoverable: true,
      details: { operation, timeoutMs },
      cause: options?.cause,
    })
    this.name = 'TimeoutError'
  }
}

export class DatabaseError extends RikuneError {
  constructor(
    code: ErrorCodeType,
    message: string,
    options?: { cause?: unknown; details?: Record<string, unknown> },
  ) {
    super(code, message, { recoverable: false, ...options })
    this.name = 'DatabaseError'
  }
}

// ─── Helper: wrap unknown errors ──────────────────────────────────────────────

/**
 * Ensure any thrown value is a `RikuneError`.
 * Unknown errors are wrapped as `E_INTERNAL` with the original as `cause`.
 */
export function toRikuneError(err: unknown): RikuneError {
  if (err instanceof RikuneError) return err
  const message = err instanceof Error ? err.message : String(err)
  return new RikuneError(ErrorCode.E_INTERNAL, message, { cause: err })
}

/**
 * Type-guard to distinguish `RikuneError` from plain errors.
 */
export function isRikuneError(err: unknown): err is RikuneError {
  return err instanceof RikuneError
}
