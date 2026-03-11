/**
 * Unit tests for JobQueue
 * 
 * Tests requirements 21.1 and 21.2:
 * - Task enqueueing with unique job_id
 * - Priority-based task ordering
 * - Job status tracking
 * - Job cancellation
 */

import { JobQueue, JobPriority, type JobResult } from '../../src/job-queue';

describe('JobQueue', () => {
  let queue: JobQueue;

  beforeEach(() => {
    queue = new JobQueue();
  });

  afterEach(() => {
    queue.removeAllListeners();
  });

  describe('enqueue', () => {
    it('should enqueue a job and return a unique job ID', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test123',
        args: { fast: true },
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 1000,
          retryableErrors: []
        }
      });

      expect(jobId).toBeDefined();
      expect(typeof jobId).toBe('string');
      expect(jobId.length).toBeGreaterThan(0);
    });

    it('should generate unique IDs for multiple jobs', () => {
      const jobId1 = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 1000,
          retryableErrors: []
        }
      });

      const jobId2 = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 1000,
          retryableErrors: []
        }
      });

      expect(jobId1).not.toBe(jobId2);
    });

    it('should set initial status to queued', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 1000,
          retryableErrors: []
        }
      });

      const status = queue.getStatus(jobId);
      expect(status).toBeDefined();
      expect(status?.status).toBe('queued');
    });

    it('should emit job:enqueued event', (done) => {
      queue.on('job:enqueued', (jobId) => {
        expect(jobId).toBeDefined();
        done();
      });

      queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 1000,
          retryableErrors: []
        }
      });
    });
  });

  describe('priority queue', () => {
    it('should dequeue jobs in priority order (highest first)', () => {
      // Enqueue jobs with different priorities
      const lowPriorityId = queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.LOW,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const highPriorityId = queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.HIGH,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const normalPriorityId = queue.enqueue({
        type: 'static',
        tool: 'test3',
        sampleId: 'sha256:test3',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      // Dequeue should return highest priority first
      const job1 = queue.dequeue();
      expect(job1?.id).toBe(highPriorityId);

      const job2 = queue.dequeue();
      expect(job2?.id).toBe(normalPriorityId);

      const job3 = queue.dequeue();
      expect(job3?.id).toBe(lowPriorityId);
    });

    it('should use FIFO for jobs with same priority', () => {
      const jobId1 = queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const jobId2 = queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const job1 = queue.dequeue();
      expect(job1?.id).toBe(jobId1);

      const job2 = queue.dequeue();
      expect(job2?.id).toBe(jobId2);
    });
  });

  describe('getStatus', () => {
    it('should return job status', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const status = queue.getStatus(jobId);
      expect(status).toBeDefined();
      expect(status?.id).toBe(jobId);
      expect(status?.status).toBe('queued');
    });

    it('should return undefined for non-existent job', () => {
      const status = queue.getStatus('non-existent-id');
      expect(status).toBeUndefined();
    });

    it('should update status when job is dequeued', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();

      const status = queue.getStatus(jobId);
      expect(status?.status).toBe('running');
      expect(status?.startedAt).toBeDefined();
    });
  });

  describe('cancel', () => {
    it('should cancel a queued job', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const cancelled = queue.cancel(jobId);
      expect(cancelled).toBe(true);

      const status = queue.getStatus(jobId);
      expect(status?.status).toBe('cancelled');
      expect(status?.finishedAt).toBeDefined();
    });

    it('should remove cancelled job from queue', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.cancel(jobId);

      const nextJob = queue.dequeue();
      expect(nextJob).toBeUndefined();
    });

    it('should return false for non-existent job', () => {
      const cancelled = queue.cancel('non-existent-id');
      expect(cancelled).toBe(false);
    });

    it('should return false for already completed job', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: true,
        data: {},
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });

      const cancelled = queue.cancel(jobId);
      expect(cancelled).toBe(false);
    });

    it('should emit job:cancelled event', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.on('job:cancelled', (cancelledJobId) => {
        expect(cancelledJobId).toBe(jobId);
        done();
      });

      queue.cancel(jobId);
    });
  });

  describe('onComplete', () => {
    it('should invoke callback when job completes successfully', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.onComplete(jobId, (result) => {
        expect(result.jobId).toBe(jobId);
        expect(result.ok).toBe(true);
        done();
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: true,
        data: { test: 'data' },
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });
    });

    it('should invoke callback when job fails', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.onComplete(jobId, (result) => {
        expect(result.jobId).toBe(jobId);
        expect(result.ok).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
        done();
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['Test error'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });
    });
  });

  describe('dequeue', () => {
    it('should return undefined when queue is empty', () => {
      const job = queue.dequeue();
      expect(job).toBeUndefined();
    });

    it('should update job status to running', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();

      const status = queue.getStatus(jobId);
      expect(status?.status).toBe('running');
    });

    it('should emit job:started event', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.on('job:started', (startedJobId) => {
        expect(startedJobId).toBe(jobId);
        done();
      });

      queue.dequeue();
    });
  });

  describe('complete', () => {
    it('should mark job as completed on success', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: true,
        data: {},
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });

      const status = queue.getStatus(jobId);
      expect(status?.status).toBe('completed');
      expect(status?.finishedAt).toBeDefined();
    });

    it('should mark job as failed on error', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['Test error'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });

      const status = queue.getStatus(jobId);
      expect(status?.status).toBe('failed');
      expect(status?.error).toBe('Test error');
    });

    it('should emit job:completed event on success', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.on('job:completed', (completedJobId, result) => {
        expect(completedJobId).toBe(jobId);
        expect(result.ok).toBe(true);
        done();
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: true,
        data: {},
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });
    });

    it('should emit job:failed event on error', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.on('job:failed', (failedJobId, result) => {
        expect(failedJobId).toBe(jobId);
        expect(result.ok).toBe(false);
        done();
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['Test error'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });
    });
  });

  describe('updateProgress', () => {
    it('should update job progress', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      queue.updateProgress(jobId, 50);

      const status = queue.getStatus(jobId);
      expect(status?.progress).toBe(50);
    });

    it('should clamp progress to 0-100 range', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      queue.updateProgress(jobId, 150);

      let status = queue.getStatus(jobId);
      expect(status?.progress).toBe(100);

      queue.updateProgress(jobId, -10);
      status = queue.getStatus(jobId);
      expect(status?.progress).toBe(0);
    });

    it('should emit job:progress event', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.on('job:progress', (progressJobId, progress) => {
        expect(progressJobId).toBe(jobId);
        expect(progress).toBe(75);
        done();
      });

      queue.dequeue();
      queue.updateProgress(jobId, 75);
    });
  });

  describe('utility methods', () => {
    it('should return queue length', () => {
      expect(queue.getQueueLength()).toBe(0);

      queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      expect(queue.getQueueLength()).toBe(1);

      queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      expect(queue.getQueueLength()).toBe(2);

      queue.dequeue();
      expect(queue.getQueueLength()).toBe(1);
    });

    it('should get jobs by status', () => {
      const jobId1 = queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const jobId2 = queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue(); // Start first job

      const queuedJobs = queue.getJobsByStatus('queued');
      expect(queuedJobs.length).toBe(1);
      expect(queuedJobs[0].id).toBe(jobId2);

      const runningJobs = queue.getJobsByStatus('running');
      expect(runningJobs.length).toBe(1);
      expect(runningJobs[0].id).toBe(jobId1);
    });

    it('should get job result', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      
      const result: JobResult = {
        jobId,
        ok: true,
        data: { test: 'data' },
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      };
      
      queue.complete(jobId, result);

      const retrievedResult = queue.getResult(jobId);
      expect(retrievedResult).toEqual(result);
    });

    it('should clear old jobs', async () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: true,
        data: {},
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });

      // Wait a bit to ensure the job is old enough
      await new Promise(resolve => setTimeout(resolve, 10));

      // Clear jobs older than 5ms (should clear the completed job)
      const cleared = queue.clearOldJobs(5);
      expect(cleared).toBe(1);

      const status = queue.getStatus(jobId);
      expect(status).toBeUndefined();
    });

    it('should get total jobs count', () => {
      expect(queue.getTotalJobs()).toBe(0);

      queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      expect(queue.getTotalJobs()).toBe(1);

      queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      expect(queue.getTotalJobs()).toBe(2);
    });
  });

  describe('retry mechanism', () => {
    it('should retry a failed job with retryable error', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED']
        }
      });

      queue.on('job:retry-scheduled', (retryJobId, attempts, backoffMs) => {
        expect(retryJobId).toBe(jobId);
        expect(attempts).toBe(1);
        expect(backoffMs).toBe(100); // First retry: 100 * 2^0 = 100
        done();
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['E_TIMEOUT: Operation timed out'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 30000, peakRssMb: 100 }
      });
    });

    it('should not retry a failed job with non-retryable error', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT']
        }
      });

      let retryScheduled = false;
      queue.on('job:retry-scheduled', () => {
        retryScheduled = true;
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['E_INVALID_INPUT: Invalid sample format'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });

      const status = queue.getStatus(jobId);
      expect(status?.status).toBe('failed');
      expect(retryScheduled).toBe(false);
    });

    it('should not retry after max retries exceeded', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 2,
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT']
        }
      });

      // First attempt
      const job1 = queue.dequeue();
      expect(job1?.attempts).toBe(0);
      
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['E_TIMEOUT: Operation timed out'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 30000, peakRssMb: 100 }
      });

      // Wait for retry
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          // Second attempt (retry 1)
          const job2 = queue.dequeue();
          expect(job2?.attempts).toBe(1);
          
          queue.complete(jobId, {
            jobId,
            ok: false,
            errors: ['E_TIMEOUT: Operation timed out'],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 30000, peakRssMb: 100 }
          });

          setTimeout(() => {
            // Third attempt (retry 2 - last retry)
            const job3 = queue.dequeue();
            expect(job3?.attempts).toBe(2);
            
            let retryScheduled = false;
            queue.on('job:retry-scheduled', (_retryJobId, _attempts, _backoffMs) => {
              retryScheduled = true;
            });

            queue.complete(jobId, {
              jobId,
              ok: false,
              errors: ['E_TIMEOUT: Operation timed out'],
              warnings: [],
              artifacts: [],
              metrics: { elapsedMs: 30000, peakRssMb: 100 }
            });

            // Should not retry after max retries
            const status = queue.getStatus(jobId);
            expect(status?.status).toBe('failed');
            expect(retryScheduled).toBe(false);
            resolve();
          }, 250);
        }, 150);
      });
    }, 10000);

    it('should use exponential backoff for retries', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT']
        }
      });

      const backoffDelays: number[] = [];

      queue.on('job:retry-scheduled', (_retryJobId, attempts, backoffMs) => {
        backoffDelays.push(backoffMs);
        
        if (attempts === 3) {
          // Verify exponential backoff: 100, 200, 400
          expect(backoffDelays).toEqual([100, 200, 400]);
          done();
        }
      });

      // First attempt
      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['E_TIMEOUT: Operation timed out'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 30000, peakRssMb: 100 }
      });

      // Wait and retry
      setTimeout(() => {
        queue.dequeue();
        queue.complete(jobId, {
          jobId,
          ok: false,
          errors: ['E_TIMEOUT: Operation timed out'],
          warnings: [],
          artifacts: [],
          metrics: { elapsedMs: 30000, peakRssMb: 100 }
        });

        setTimeout(() => {
          queue.dequeue();
          queue.complete(jobId, {
            jobId,
            ok: false,
            errors: ['E_TIMEOUT: Operation timed out'],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 30000, peakRssMb: 100 }
          });
        }, 250);
      }, 150);
    }, 10000);

    it('should emit job:retry event when job is re-enqueued', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 50,
          retryableErrors: ['E_TIMEOUT']
        }
      });

      queue.on('job:retry', (retryJobId, attempts, backoffMs) => {
        expect(retryJobId).toBe(jobId);
        expect(attempts).toBe(1);
        expect(backoffMs).toBe(50);
        done();
      });

      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['E_TIMEOUT: Operation timed out'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 30000, peakRssMb: 100 }
      });
    }, 5000);

    it('should successfully complete after retry', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 50,
          retryableErrors: ['E_TIMEOUT']
        }
      });

      queue.on('job:completed', (completedJobId) => {
        expect(completedJobId).toBe(jobId);
        const status = queue.getStatus(jobId);
        expect(status?.status).toBe('completed');
        done();
      });

      // First attempt fails
      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['E_TIMEOUT: Operation timed out'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 30000, peakRssMb: 100 }
      });

      // Wait for retry and succeed
      setTimeout(() => {
        queue.dequeue();
        queue.complete(jobId, {
          jobId,
          ok: true,
          data: { test: 'success' },
          errors: [],
          warnings: [],
          artifacts: [],
          metrics: { elapsedMs: 1000, peakRssMb: 100 }
        });
      }, 100);
    }, 5000);

    it('should handle multiple retryable error types', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 50,
          retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED', 'E_WORKER_UNAVAILABLE']
        }
      });

      let retryCount = 0;
      queue.on('job:retry-scheduled', (_retryJobId, _attempts, _backoffMs) => {
        retryCount++;
      });

      // Test different retryable errors
      queue.dequeue();
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['E_RESOURCE_EXHAUSTED: Out of memory'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 4096 }
      });

      setTimeout(() => {
        queue.dequeue();
        queue.complete(jobId, {
          jobId,
          ok: false,
          errors: ['E_WORKER_UNAVAILABLE: No workers available'],
          warnings: [],
          artifacts: [],
          metrics: { elapsedMs: 100, peakRssMb: 50 }
        });

        setTimeout(() => {
          expect(retryCount).toBe(2);
          done();
        }, 100);
      }, 100);
    }, 5000);
  });

  describe('concurrency control', () => {
    it('should track multiple jobs running concurrently', () => {
      // Enqueue multiple jobs
      const jobId1 = queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const jobId2 = queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const jobId3 = queue.enqueue({
        type: 'static',
        tool: 'test3',
        sampleId: 'sha256:test3',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      // Dequeue multiple jobs to simulate concurrent execution
      queue.dequeue();
      queue.dequeue();
      queue.dequeue();

      // All three jobs should be in running state
      const runningJobs = queue.getJobsByStatus('running');
      expect(runningJobs.length).toBe(3);
      expect(runningJobs.map(j => j.id).sort()).toEqual([jobId1, jobId2, jobId3].sort());
    });

    it('should handle concurrent job completions', () => {
      // Enqueue and start multiple jobs
      const jobId1 = queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const jobId2 = queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      queue.dequeue();

      // Complete jobs in different order
      queue.complete(jobId2, {
        jobId: jobId2,
        ok: true,
        data: {},
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });

      queue.complete(jobId1, {
        jobId: jobId1,
        ok: true,
        data: {},
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1500, peakRssMb: 120 }
      });

      // Both should be completed
      const status1 = queue.getStatus(jobId1);
      const status2 = queue.getStatus(jobId2);
      expect(status1?.status).toBe('completed');
      expect(status2?.status).toBe('completed');
    });

    it('should handle mixed concurrent operations (complete, fail, cancel)', () => {
      const jobId1 = queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const jobId2 = queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const jobId3 = queue.enqueue({
        type: 'static',
        tool: 'test3',
        sampleId: 'sha256:test3',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      // Start all jobs
      queue.dequeue();
      queue.dequeue();
      queue.dequeue();

      // Complete first job successfully
      queue.complete(jobId1, {
        jobId: jobId1,
        ok: true,
        data: {},
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });

      // Fail second job
      queue.complete(jobId2, {
        jobId: jobId2,
        ok: false,
        errors: ['Test error'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 500, peakRssMb: 80 }
      });

      // Cancel third job
      queue.cancel(jobId3);

      // Verify final states
      expect(queue.getStatus(jobId1)?.status).toBe('completed');
      expect(queue.getStatus(jobId2)?.status).toBe('failed');
      expect(queue.getStatus(jobId3)?.status).toBe('cancelled');
    });

    it('should correctly report queue length with concurrent jobs', () => {
      // Enqueue 5 jobs
      for (let i = 0; i < 5; i++) {
        queue.enqueue({
          type: 'static',
          tool: `test${i}`,
          sampleId: `sha256:test${i}`,
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 30000,
          retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
        });
      }

      expect(queue.getQueueLength()).toBe(5);
      expect(queue.getTotalJobs()).toBe(5);

      // Dequeue 3 jobs (simulate 3 concurrent workers)
      queue.dequeue();
      queue.dequeue();
      queue.dequeue();

      // Queue length should be 2 (only queued jobs)
      expect(queue.getQueueLength()).toBe(2);
      // Total jobs should still be 5
      expect(queue.getTotalJobs()).toBe(5);

      // Running jobs should be 3
      const runningJobs = queue.getJobsByStatus('running');
      expect(runningJobs.length).toBe(3);
    });

    it('should handle concurrent progress updates', () => {
      const jobId1 = queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const jobId2 = queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      queue.dequeue();
      queue.dequeue();

      // Update progress for both jobs
      queue.updateProgress(jobId1, 25);
      queue.updateProgress(jobId2, 50);

      expect(queue.getStatus(jobId1)?.progress).toBe(25);
      expect(queue.getStatus(jobId2)?.progress).toBe(50);

      // Update again
      queue.updateProgress(jobId1, 75);
      queue.updateProgress(jobId2, 100);

      expect(queue.getStatus(jobId1)?.progress).toBe(75);
      expect(queue.getStatus(jobId2)?.progress).toBe(100);
    });

    it('should maintain priority order when dequeuing with concurrent jobs', () => {
      // Enqueue jobs with different priorities
      const lowId = queue.enqueue({
        type: 'static',
        tool: 'low',
        sampleId: 'sha256:low',
        args: {},
        priority: JobPriority.LOW,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const highId = queue.enqueue({
        type: 'static',
        tool: 'high',
        sampleId: 'sha256:high',
        args: {},
        priority: JobPriority.HIGH,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const normalId = queue.enqueue({
        type: 'static',
        tool: 'normal',
        sampleId: 'sha256:normal',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      // Dequeue should respect priority even with concurrent execution
      const job1 = queue.dequeue();
      expect(job1?.id).toBe(highId);

      const job2 = queue.dequeue();
      expect(job2?.id).toBe(normalId);

      const job3 = queue.dequeue();
      expect(job3?.id).toBe(lowId);

      // All should be running
      expect(queue.getJobsByStatus('running').length).toBe(3);
    });
  });

  describe('requeue', () => {
    it('should re-enqueue a job with updated attempts', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      // Dequeue and fail the job
      const job = queue.dequeue();
      expect(job).toBeDefined();
      expect(job!.attempts).toBe(0);

      // Simulate retry by incrementing attempts
      job!.attempts = 1;

      // Re-enqueue the job
      queue.requeue(job!);

      const status = queue.getStatus(jobId);
      expect(status?.status).toBe('queued');
      expect(queue.getQueueLength()).toBe(1);
    });

    it('should reset job status when re-enqueued', () => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const job = queue.dequeue();
      
      // Complete with failure
      queue.complete(jobId, {
        jobId,
        ok: false,
        errors: ['Test error'],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1000, peakRssMb: 100 }
      });

      let status = queue.getStatus(jobId);
      expect(status?.status).toBe('failed');
      expect(status?.error).toBe('Test error');

      // Re-enqueue
      job!.attempts = 1;
      queue.requeue(job!);

      status = queue.getStatus(jobId);
      expect(status?.status).toBe('queued');
      expect(status?.error).toBeUndefined();
      expect(status?.startedAt).toBeUndefined();
      expect(status?.finishedAt).toBeUndefined();
    });

    it('should emit job:requeued event', (done) => {
      const jobId = queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const job = queue.dequeue();
      job!.attempts = 2;

      queue.on('job:requeued', (requeuedJobId, attempts) => {
        expect(requeuedJobId).toBe(jobId);
        expect(attempts).toBe(2);
        done();
      });

      queue.requeue(job!);
    });

    it('should maintain priority order after requeue', () => {
      // Enqueue low priority job
      queue.enqueue({
        type: 'static',
        tool: 'test1',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.LOW,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      // Enqueue high priority job and fail it
      const highPriorityJobId = queue.enqueue({
        type: 'static',
        tool: 'test2',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.HIGH,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      // Dequeue high priority job (should be first)
      const job = queue.dequeue();
      expect(job?.id).toBe(highPriorityJobId);

      // Re-enqueue it
      job!.attempts = 1;
      queue.requeue(job!);

      // High priority should still be first
      const nextJob = queue.dequeue();
      expect(nextJob?.id).toBe(highPriorityJobId);
    });

    it('should preserve job data when re-enqueued', () => {
      const originalArgs = { fast: true, test: 'data' };
      queue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: originalArgs,
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: { maxRetries: 3, backoffMs: 1000, retryableErrors: [] }
      });

      const job = queue.dequeue();
      job!.attempts = 1;
      queue.requeue(job!);

      const requeuedJob = queue.dequeue();
      expect(requeuedJob?.args).toEqual(originalArgs);
      expect(requeuedJob?.tool).toBe('pe.fingerprint');
      expect(requeuedJob?.sampleId).toBe('sha256:test');
      expect(requeuedJob?.attempts).toBe(1);
    });
  });
});
