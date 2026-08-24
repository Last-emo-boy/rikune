import { logger } from '../logger.js'
import type { SampleDeletionService } from './sample-deletion.js'
import type { SampleFinalizationService } from './sample-finalization.js'

export interface JournalRecoveryPassResult {
  ingest: { recovered: number; cleaned: number; failed: number }
  deletion: { recovered: number; skipped: number; failed: number }
}

/**
 * Periodically reconciles journals which were live-owned during bootstrap but
 * became claimable later. Passes never overlap and shutdown waits for the
 * current pass before the operation gate/database are closed.
 */
export class JournalRecoveryCoordinator {
  private timer?: NodeJS.Timeout
  private inFlight?: Promise<JournalRecoveryPassResult>
  private stopped = false

  constructor(
    private readonly finalization: SampleFinalizationService,
    private readonly deletion: SampleDeletionService,
    private readonly intervalMs = 5_000
  ) {
    if (!Number.isInteger(intervalMs) || intervalMs < 10 || intervalMs > 60_000) {
      throw new Error('Journal recovery interval must be between 10ms and 60s.')
    }
  }

  start(): void {
    if (this.timer || this.stopped) return
    this.timer = setInterval(() => {
      void this.recoverOnce().catch((error) => {
        logger.error({ err: error }, 'Periodic sample journal recovery pass failed')
      })
    }, this.intervalMs)
    this.timer.unref()
  }

  recoverOnce(): Promise<JournalRecoveryPassResult> {
    if (this.inFlight) return this.inFlight
    this.inFlight = (async () => {
      const ingest = await this.finalization.recoverPendingIngests()
      const deletion = await this.deletion.recoverPendingDeletions()
      if (ingest.failed > 0 || deletion.failed > 0) {
        logger.warn(
          { ingest, deletion },
          'Sample journal recovery retained fail-closed entries for a later pass'
        )
      }
      return { ingest, deletion }
    })().finally(() => {
      this.inFlight = undefined
    })
    return this.inFlight
  }

  async stop(): Promise<void> {
    this.stopped = true
    if (this.timer) clearInterval(this.timer)
    this.timer = undefined
    await this.inFlight
  }
}
