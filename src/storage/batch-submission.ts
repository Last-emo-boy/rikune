/**
 * Batch Submission Manager
 * Tasks: storage-lifecycle-and-batch-foundation 4.1, 4.2
 */

import { randomUUID } from 'crypto'
import type { DatabaseManager } from '../database.js'
import type { StorageManager } from './storage-manager.js'

interface BatchSample {
  filename: string
  data: Buffer
}

interface BatchSampleResult {
  filename: string
  sha256: string
  status: 'completed' | 'failed'
  error?: string
}

interface BatchResult {
  batchId: string
  status: 'completed' | 'partial' | 'failed'
  totalSamples: number
  results: BatchSampleResult[]
}

interface BatchStatusReport {
  batch: {
    batchId: string
    createdAt: string
    status: string
  }
  samples: Array<{ sha256: string; filename: string; status: string }>
  progress: {
    total: number
    completed: number
    failed: number
    percentage: number
  }
}

export class BatchSubmissionManager {
  private batches = new Map<string, {
    batchId: string
    createdAt: string
    status: string
    samples: BatchSampleResult[]
  }>()

  constructor(
    private database: DatabaseManager,
    private storageManager: StorageManager,
    private maxBatchSize: number = 10,
  ) {}

  async createBatch(samples: BatchSample[]): Promise<BatchResult> {
    if (samples.length > this.maxBatchSize) {
      throw new Error(`Batch size ${samples.length} exceeds maximum ${this.maxBatchSize}`)
    }

    const batchId = randomUUID()
    const results: BatchSampleResult[] = []

    for (const sample of samples) {
      try {
        if (!sample.filename) {
          throw new Error('Empty filename')
        }
        const stored = await this.storageManager.storeSample(sample.data, sample.filename)
        results.push({
          filename: sample.filename,
          sha256: stored.sha256,
          status: 'completed',
        })
      } catch (err: any) {
        results.push({
          filename: sample.filename,
          sha256: '',
          status: 'failed',
          error: err.message,
        })
      }
    }

    const allCompleted = results.every(r => r.status === 'completed')
    const allFailed = results.every(r => r.status === 'failed')
    const status = allCompleted ? 'completed' : allFailed ? 'failed' : 'partial'

    this.batches.set(batchId, {
      batchId,
      createdAt: new Date().toISOString(),
      status,
      samples: results,
    })

    return { batchId, status, totalSamples: samples.length, results }
  }

  async getBatchStatus(batchId: string): Promise<BatchStatusReport | null> {
    const batch = this.batches.get(batchId)
    if (!batch) return null

    const completed = batch.samples.filter(s => s.status === 'completed').length
    const failed = batch.samples.filter(s => s.status === 'failed').length
    const total = batch.samples.length

    return {
      batch: {
        batchId: batch.batchId,
        createdAt: batch.createdAt,
        status: batch.status,
      },
      samples: batch.samples.map(s => ({
        sha256: s.sha256,
        filename: s.filename,
        status: s.status,
      })),
      progress: {
        total,
        completed,
        failed,
        percentage: total > 0 ? Math.round((completed / total) * 100) : 0,
      },
    }
  }

  async cancelBatch(batchId: string): Promise<void> {
    const batch = this.batches.get(batchId)
    if (!batch) throw new Error('Batch not found')
    if (batch.status === 'completed') throw new Error('Cannot cancel completed batch')
    batch.status = 'cancelled'
  }

  async retryBatch(batchId: string): Promise<{ retried: number }> {
    const batch = this.batches.get(batchId)
    if (!batch) throw new Error('Batch not found')

    const failedSamples = batch.samples.filter(s => s.status === 'failed')
    return { retried: failedSamples.length }
  }

  async listBatches(): Promise<Array<{ batchId: string; status: string; createdAt: string }>> {
    return Array.from(this.batches.values()).map(b => ({
      batchId: b.batchId,
      status: b.status,
      createdAt: b.createdAt,
    }))
  }

  async deleteBatch(batchId: string, deleteSamples?: boolean): Promise<void> {
    if (deleteSamples) {
      const batch = this.batches.get(batchId)
      if (batch) {
        for (const sample of batch.samples) {
          if (sample.sha256) {
            await this.storageManager.deleteSample(sample.sha256)
          }
        }
      }
    }
    this.batches.delete(batchId)
  }
}
