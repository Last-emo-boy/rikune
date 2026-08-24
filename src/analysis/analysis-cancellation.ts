/**
 * Cooperative cancellation helpers for queued analysis workflows.
 *
 * These helpers deliberately do not race an operation against AbortSignal.
 * Racing would let the queue settle while the abandoned operation can still
 * mutate artifacts or database state. Each workflow instead forwards the
 * signal to interruptible I/O/process boundaries and checks it between
 * bounded synchronous stages.
 */

const CANCELLATION_MESSAGE = 'E_JOB_ABORTED: queued analysis task was cancelled'

export type AbortableHandler<TArgs, TResult> = (
  args: TArgs,
  abortSignal?: AbortSignal
) => Promise<TResult>

export function throwIfAnalysisAborted(abortSignal?: AbortSignal): void {
  if (!abortSignal?.aborted) return

  const error = new Error(CANCELLATION_MESSAGE, {
    cause: abortSignal.reason,
  })
  error.name = 'AbortError'
  throw error
}

/**
 * Invoke a composed workflow stage without abandoning its promise. The
 * callee owns termination of any external process; the post-check prevents a
 * cancelled workflow from entering the next persistence or CPU-only stage.
 */
export async function invokeAbortable<TArgs, TResult>(
  handler: AbortableHandler<TArgs, TResult>,
  args: TArgs,
  abortSignal?: AbortSignal
): Promise<TResult> {
  throwIfAnalysisAborted(abortSignal)
  const result = abortSignal ? await handler(args, abortSignal) : await handler(args)
  throwIfAnalysisAborted(abortSignal)
  return result
}
