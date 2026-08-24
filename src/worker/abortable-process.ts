import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'

export interface AbortableProcessResult {
  exitCode: number | null
  signal: NodeJS.Signals | null
  timedOut: boolean
  stdout: string
  stderr: string
  error: string | null
}

export interface AbortableProcessOptions {
  command: string
  args: string[]
  cwd: string
  env?: NodeJS.ProcessEnv
  stdin?: string
  timeoutMs: number
  abortSignal?: AbortSignal
  terminationWatchdogMs?: number
}

function cancellationError(reason?: unknown): Error {
  const error = new Error('E_JOB_ABORTED: queued analysis child process was cancelled', {
    cause: reason,
  })
  error.name = 'AbortError'
  return error
}

/**
 * Run an external analysis process under close-authoritative tree supervision.
 * Cancellation never races or abandons the child promise: POSIX uses an
 * isolated process group; Windows waits for taskkill /T /F supervision.
 */
export async function runAbortableProcess(
  options: AbortableProcessOptions
): Promise<AbortableProcessResult> {
  if (options.abortSignal?.aborted) {
    throw cancellationError(options.abortSignal.reason)
  }

  return new Promise<AbortableProcessResult>((resolve, reject) => {
    const child = spawn(options.command, options.args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['pipe', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
      windowsHide: true,
    }) as ChildProcessWithoutNullStreams
    const timeoutMs = Math.max(5_000, options.timeoutMs)
    const watchdogMs = Math.max(1_000, options.terminationWatchdogMs ?? 5_000)
    let stdout = ''
    let stderr = ''
    let directCloseObserved = false
    let exitCode: number | null = null
    let exitSignal: NodeJS.Signals | null = null
    let spawnError: string | null = null
    let timedOut = false
    let cancelled = false
    let terminationRequested = false
    let windowsTreeSupervisionFinished = true
    let settled = false
    let timeoutTimer: NodeJS.Timeout | undefined
    let windowsWatchdogTimer: NodeJS.Timeout | undefined
    let onAbort: (() => void) | undefined

    const cleanup = () => {
      if (timeoutTimer) clearTimeout(timeoutTimer)
      if (windowsWatchdogTimer) clearTimeout(windowsWatchdogTimer)
      if (options.abortSignal && onAbort) {
        options.abortSignal.removeEventListener('abort', onAbort)
      }
    }

    const maybeFinalize = () => {
      if (settled || !directCloseObserved || !windowsTreeSupervisionFinished) return
      settled = true
      cleanup()
      if (cancelled) {
        reject(cancellationError(options.abortSignal?.reason))
        return
      }
      resolve({
        exitCode,
        signal: exitSignal,
        timedOut,
        stdout,
        stderr,
        error:
          spawnError ||
          (timedOut
            ? `command timed out after ${timeoutMs}ms`
            : exitCode === 0
              ? null
              : `command failed with exit code ${exitCode ?? 'unknown'}`),
      })
    }

    const killDirect = () => {
      try {
        child.kill('SIGKILL')
      } catch {
        // `close` or a failed spawn remains authoritative.
      }
    }

    const superviseWindowsTree = () => {
      const pid = child.pid
      if (!pid) {
        windowsTreeSupervisionFinished = true
        maybeFinalize()
        return
      }
      windowsTreeSupervisionFinished = false
      let attempts = 0

      const attempt = () => {
        attempts += 1
        const killer = spawn('taskkill', ['/T', '/F', '/PID', String(pid)], {
          stdio: 'ignore',
          windowsHide: true,
        })
        let attemptFinished = false
        const finishAttempt = (failed: boolean) => {
          if (attemptFinished) return
          attemptFinished = true
          if (failed && attempts < 2) {
            attempt()
            return
          }
          if (failed) {
            spawnError = spawnError || 'Windows process-tree termination failed'
            killDirect()
          }
          windowsTreeSupervisionFinished = true
          maybeFinalize()
        }
        killer.once('error', () => finishAttempt(true))
        killer.once('close', (code) => finishAttempt(code !== 0))
      }

      attempt()
      windowsWatchdogTimer = setTimeout(() => {
        spawnError = spawnError || 'Windows process-tree termination watchdog expired'
        killDirect()
        windowsTreeSupervisionFinished = true
        maybeFinalize()
      }, watchdogMs)
      windowsWatchdogTimer.unref()
    }

    const terminateTree = () => {
      if (process.platform === 'win32') {
        superviseWindowsTree()
        return
      }
      const pid = child.pid
      try {
        if (pid) process.kill(-pid, 'SIGKILL')
        else killDirect()
      } catch {
        killDirect()
      }
    }

    const requestTermination = (reason: 'timeout' | 'cancel' | 'error') => {
      if (terminationRequested) return
      terminationRequested = true
      timedOut = reason === 'timeout'
      cancelled = reason === 'cancel'
      terminateTree()
    }

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })
    child.stdin.on('error', () => {
      // The child may close stdin before accepting input; `close` is authoritative.
    })
    child.on('error', (error: NodeJS.ErrnoException) => {
      spawnError = error.message
      if (!child.pid) {
        directCloseObserved = true
        maybeFinalize()
        return
      }
      requestTermination('error')
    })
    child.on('close', (code, signal) => {
      directCloseObserved = true
      exitCode = code ?? null
      exitSignal = signal
      maybeFinalize()
    })

    timeoutTimer = setTimeout(() => requestTermination('timeout'), timeoutMs)
    timeoutTimer.unref()
    if (options.abortSignal) {
      onAbort = () => requestTermination('cancel')
      options.abortSignal.addEventListener('abort', onAbort, { once: true })
    }
    child.stdin.end(options.stdin)
  })
}
