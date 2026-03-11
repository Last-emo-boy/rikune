/**
 * Unit tests for Worker Pool
 * 
 * Tests requirements 21.3, 27.2, and operational constraint 4:
 * - Worker process management
 * - Task allocation and status updates
 * - Concurrency control (max 4 Ghidra analyses)
 */

import { jest } from '@jest/globals';
import { WorkerPool, type WorkerPoolConfig } from '../../src/worker-pool';
import { JobQueue, JobPriority } from '../../src/job-queue';

describe('WorkerPool', () => {
  let jobQueue: JobQueue;
  let workerPool: WorkerPool;

  beforeEach(() => {
    jobQueue = new JobQueue();
  });

  afterEach(async () => {
    if (workerPool) {
      await workerPool.stop();
    }
  });

  describe('Initialization', () => {
    test('should create worker pool with default config', () => {
      workerPool = new WorkerPool(jobQueue);
      const stats = workerPool.getStats();

      expect(stats.isRunning).toBe(false);
      expect(stats.workers.static.max).toBe(8);
      expect(stats.workers.decompile.max).toBe(4); // Operational constraint 4
      expect(stats.workers.dotnet.max).toBe(4);
      expect(stats.workers.sandbox.max).toBe(2);
    });

    test('should create worker pool with custom config', () => {
      const config: WorkerPoolConfig = {
        maxStaticWorkers: 4,
        maxDecompileWorkers: 2,
        maxDotNetWorkers: 2,
        maxSandboxWorkers: 1
      };

      workerPool = new WorkerPool(jobQueue, config);
      const stats = workerPool.getStats();

      expect(stats.workers.static.max).toBe(4);
      expect(stats.workers.decompile.max).toBe(2);
      expect(stats.workers.dotnet.max).toBe(2);
      expect(stats.workers.sandbox.max).toBe(1);
    });
  });

  describe('Start and Stop', () => {
    test('should start worker pool', () => {
      workerPool = new WorkerPool(jobQueue);
      
      const startedHandler = jest.fn();
      workerPool.on('pool:started', startedHandler);

      workerPool.start();

      expect(workerPool.getStats().isRunning).toBe(true);
      expect(startedHandler).toHaveBeenCalled();
    });

    test('should not start if already running', () => {
      workerPool = new WorkerPool(jobQueue);
      
      workerPool.start();
      const stats1 = workerPool.getStats();
      
      workerPool.start(); // Try to start again
      const stats2 = workerPool.getStats();

      expect(stats1.isRunning).toBe(true);
      expect(stats2.isRunning).toBe(true);
    });

    test('should stop worker pool', async () => {
      workerPool = new WorkerPool(jobQueue);
      
      const stoppedHandler = jest.fn();
      workerPool.on('pool:stopped', stoppedHandler);

      workerPool.start();
      await workerPool.stop();

      expect(workerPool.getStats().isRunning).toBe(false);
      expect(stoppedHandler).toHaveBeenCalled();
    });

    test('should not fail when stopping if not running', async () => {
      workerPool = new WorkerPool(jobQueue);
      
      await expect(workerPool.stop()).resolves.not.toThrow();
    });
  });

  describe('Job Allocation', () => {
    test('should allocate job when worker pool starts', (done) => {
      workerPool = new WorkerPool(jobQueue);

      // Enqueue a job
      const jobId = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      // Listen for job start
      workerPool.on('worker:job:started', (_workerId, allocatedJobId) => {
        expect(allocatedJobId).toBe(jobId);
        done();
      });

      workerPool.start();
    });

    test('should allocate multiple jobs to different workers', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 3
      });

      const jobIds: string[] = [];
      const startedJobs = new Set<string>();

      // Enqueue multiple jobs
      for (let i = 0; i < 3; i++) {
        const jobId = jobQueue.enqueue({
          type: 'static',
          tool: 'pe.fingerprint',
          sampleId: `sha256:test${i}`,
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 30000
        });
        jobIds.push(jobId);
      }

      // Listen for job starts
      workerPool.on('worker:job:started', (_workerId, jobId) => {
        startedJobs.add(jobId);
        
        if (startedJobs.size === 3) {
          // All jobs started
          expect(startedJobs.size).toBe(3);
          jobIds.forEach(id => expect(startedJobs.has(id)).toBe(true));
          done();
        }
      });

      workerPool.start();
    });

    test('should respect concurrency limits for decompile workers', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxDecompileWorkers: 2
      });

      const jobIds: string[] = [];
      const startedJobs = new Set<string>();

      // Enqueue 4 decompile jobs
      for (let i = 0; i < 4; i++) {
        const jobId = jobQueue.enqueue({
          type: 'decompile',
          tool: 'ghidra.analyze',
          sampleId: `sha256:test${i}`,
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 300000
        });
        jobIds.push(jobId);
      }

      // Listen for job starts
      workerPool.on('worker:job:started', (_workerId, _jobId) => {
        startedJobs.add(_jobId);
      });

      workerPool.start();

      // Check after allocation cycle completes (1 second + buffer)
      setTimeout(() => {
        const stats = workerPool.getStats();
        
        // Should only have 2 busy workers (concurrency limit)
        expect(stats.workers.decompile.busy).toBeLessThanOrEqual(2);
        
        // Should have started exactly 2 jobs
        expect(startedJobs.size).toBe(2);
        
        done();
      }, 1100);
    }, 15000);

    test('should enforce Ghidra concurrency limit of 4', (done) => {
      workerPool = new WorkerPool(jobQueue); // Default has maxDecompileWorkers: 4

      const startedJobs = new Set<string>();

      // Enqueue 8 Ghidra jobs
      for (let i = 0; i < 8; i++) {
        jobQueue.enqueue({
          type: 'decompile',
          tool: 'ghidra.analyze',
          sampleId: `sha256:test${i}`,
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 300000
        });
      }

      // Listen for job starts
      workerPool.on('worker:job:started', (_workerId, jobId) => {
        startedJobs.add(jobId);
      });

      workerPool.start();

      // Check after allocation cycle completes (1 second + buffer)
      setTimeout(() => {
        const stats = workerPool.getStats();
        
        // Should only have 4 busy workers (operational constraint 4)
        expect(stats.workers.decompile.busy).toBeLessThanOrEqual(4);
        
        // Should have started exactly 4 jobs
        expect(startedJobs.size).toBe(4);
        
        done();
      }, 1100);
    }, 15000);

    test('should allocate jobs by priority', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 1 // Only 1 worker to test priority
      });

      const startedOrder: string[] = [];

      // Enqueue jobs with different priorities
      jobQueue.enqueue({
        type: 'static',
        tool: 'strings.extract',
        sampleId: 'sha256:low',
        args: {},
        priority: JobPriority.LOW,
        timeout: 30000
      });

      const highPriorityJob = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:high',
        args: {},
        priority: JobPriority.HIGH,
        timeout: 30000
      });

      jobQueue.enqueue({
        type: 'static',
        tool: 'yara.scan',
        sampleId: 'sha256:normal',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      // Listen for job starts
      workerPool.on('worker:job:started', (_workerId, jobId) => {
        startedOrder.push(jobId);
        
        // Check after first job starts
        if (startedOrder.length === 1) {
          // High priority should be first
          expect(startedOrder[0]).toBe(highPriorityJob);
          done();
        }
      });

      workerPool.start();
    }, 10000);
  });

  describe('Job Completion', () => {
    test('should mark job as completed on success', (done) => {
      workerPool = new WorkerPool(jobQueue);

      const jobId = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      workerPool.on('worker:job:completed', (_workerId, completedJobId, result) => {
        expect(completedJobId).toBe(jobId);
        expect(result.ok).toBe(true);
        
        const status = jobQueue.getStatus(jobId);
        expect(status?.status).toBe('completed');
        
        done();
      });

      workerPool.start();
    });

    test.skip('should allocate next job after completion', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 1 // Only 1 worker
      });

      const completedJobs: string[] = [];

      // Enqueue 2 jobs
      const job1 = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      const job2 = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      workerPool.on('worker:job:completed', (_workerId, jobId) => {
        completedJobs.push(jobId);
        
        if (completedJobs.length === 2) {
          // Both jobs completed
          expect(completedJobs).toContain(job1);
          expect(completedJobs).toContain(job2);
          done();
        }
      });

      workerPool.start();
    }, 20000);
  });

  describe('Worker Management', () => {
    test('should create workers on demand', (done) => {
      workerPool = new WorkerPool(jobQueue);

      const createdWorkers = new Set<string>();

      workerPool.on('worker:created', (workerId, type) => {
        createdWorkers.add(workerId);
        expect(type).toBe('static');
        
        // Check after first worker is created
        expect(createdWorkers.size).toBeGreaterThan(0);
        done();
      });

      // Enqueue a job
      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      workerPool.start();
    }, 10000);

    test('should reuse idle workers', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 2
      });

      let workerCreationCount = 0;

      workerPool.on('worker:created', () => {
        workerCreationCount++;
      });

      // Enqueue first job
      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      workerPool.start();

      // Wait for first job to complete, then enqueue second
      workerPool.on('worker:job:completed', () => {
        // Enqueue second job
        jobQueue.enqueue({
          type: 'static',
          tool: 'pe.fingerprint',
          sampleId: 'sha256:test2',
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 30000
        });

        setTimeout(() => {
          // Should have created only 1 worker (reused for second job)
          expect(workerCreationCount).toBe(1);
          done();
        }, 200);
      });
    });

    test('should track worker heartbeats', () => {
      workerPool = new WorkerPool(jobQueue);
      workerPool.start();

      // Create a worker manually for testing
      const workerId = 'test-worker-123';
      
      // Update heartbeat
      workerPool.updateHeartbeat(workerId);
      
      // Heartbeat update should not throw
      expect(() => workerPool.updateHeartbeat(workerId)).not.toThrow();
    });
  });

  describe('Statistics', () => {
    test('should provide accurate statistics', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 3,
        maxDecompileWorkers: 2
      });

      // Enqueue jobs
      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test1',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      jobQueue.enqueue({
        type: 'decompile',
        tool: 'ghidra.analyze',
        sampleId: 'sha256:test2',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 300000
      });

      workerPool.start();

      // Check after allocation cycle completes
      setTimeout(() => {
        const stats = workerPool.getStats();

        expect(stats.isRunning).toBe(true);
        expect(stats.workers.static.max).toBe(3);
        expect(stats.workers.decompile.max).toBe(2);
        
        // At least one worker should be busy or have been created
        const totalStatic = stats.workers.static.busy + stats.workers.static.idle;
        const totalDecompile = stats.workers.decompile.busy + stats.workers.decompile.idle;
        
        expect(totalStatic).toBeGreaterThan(0);
        expect(totalDecompile).toBeGreaterThan(0);

        done();
      }, 1100);
    }, 15000);

    test('should track queue length', () => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 1
      });

      // Enqueue multiple jobs
      for (let i = 0; i < 5; i++) {
        jobQueue.enqueue({
          type: 'static',
          tool: 'pe.fingerprint',
          sampleId: `sha256:test${i}`,
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 30000
        });
      }

      workerPool.start();

      const stats = workerPool.getStats();
      
      // Should have jobs in queue (1 running, 4 queued)
      expect(stats.queueLength).toBeGreaterThan(0);
    });
  });

  describe('Concurrency Control', () => {
    test('should enforce per-type concurrency limits', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 2,
        maxDecompileWorkers: 1
      });

      // Enqueue mixed job types
      for (let i = 0; i < 3; i++) {
        jobQueue.enqueue({
          type: 'static',
          tool: 'pe.fingerprint',
          sampleId: `sha256:static${i}`,
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 30000
        });
      }

      for (let i = 0; i < 2; i++) {
        jobQueue.enqueue({
          type: 'decompile',
          tool: 'ghidra.analyze',
          sampleId: `sha256:decompile${i}`,
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 300000
        });
      }

      workerPool.start();

      setTimeout(() => {
        const stats = workerPool.getStats();

        // Static workers: max 2 busy
        expect(stats.workers.static.busy).toBeLessThanOrEqual(2);
        
        // Decompile workers: max 1 busy
        expect(stats.workers.decompile.busy).toBeLessThanOrEqual(1);

        done();
      }, 100);
    });

    test('should handle different worker types independently', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 2,
        maxDecompileWorkers: 2,
        maxDotNetWorkers: 2
      });

      // Enqueue jobs of different types
      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:static',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      jobQueue.enqueue({
        type: 'decompile',
        tool: 'ghidra.analyze',
        sampleId: 'sha256:decompile',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 300000
      });

      jobQueue.enqueue({
        type: 'dotnet',
        tool: 'dotnet.types.list',
        sampleId: 'sha256:dotnet',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000
      });

      workerPool.start();

      setTimeout(() => {
        const stats = workerPool.getStats();

        // All types should have workers (busy or idle)
        const totalStatic = stats.workers.static.busy + stats.workers.static.idle;
        const totalDecompile = stats.workers.decompile.busy + stats.workers.decompile.idle;
        const totalDotnet = stats.workers.dotnet.busy + stats.workers.dotnet.idle;
        
        expect(totalStatic).toBeGreaterThan(0);
        expect(totalDecompile).toBeGreaterThan(0);
        expect(totalDotnet).toBeGreaterThan(0);

        done();
      }, 1100);
    }, 15000);
  });

  describe('Retry Mechanism', () => {
    test('should retry failed job with retryable error', (done) => {
      let attemptCount = 0;
      
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          attemptCount++;
          // Fail with retryable error
          throw new Error('E_TIMEOUT: Connection timeout');
        }
      });

      const jobId = jobQueue.enqueue({
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

      let retryCount = 0;

      workerPool.on('worker:job:retrying', (_workerId, retriedJobId, attempt) => {
        expect(retriedJobId).toBe(jobId);
        retryCount++;
        
        // Should retry with incremented attempt
        expect(attempt).toBe(retryCount);
        
        if (retryCount === 1) {
          // First retry detected
          done();
        }
      });

      workerPool.start();
    }, 10000);

    test('should not retry job with non-retryable error', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          // Fail with non-retryable error
          throw new Error('E_INVALID_INPUT: Invalid sample format');
        }
      });

      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT'] // Only timeout is retryable
        }
      });

      let retryAttempted = false;

      workerPool.on('worker:job:retrying', () => {
        retryAttempted = true;
      });

      workerPool.on('worker:job:failed', (_workerId, _failedJobId) => {
        expect(retryAttempted).toBe(false); // Should not have retried
        
        const status = jobQueue.getStatus(_failedJobId);
        expect(status?.status).toBe('failed');
        
        done();
      });

      workerPool.start();
    }, 10000);

    test('should respect max retry limit of 3', (done) => {
      let attemptCount = 0;
      
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          attemptCount++;
          // Always fail with retryable error
          throw new Error('E_TIMEOUT: Connection timeout');
        }
      });

      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 50,
          retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED', 'Worker timeout']
        }
      });

      let retryCount = 0;

      workerPool.on('worker:job:retrying', (_workerId, _retriedJobId, attempt) => {
        retryCount++;
        expect(attempt).toBeLessThanOrEqual(3);
      });

      workerPool.on('worker:job:failed', (_workerId, _failedJobId) => {
        // Should have retried exactly 3 times before failing
        expect(retryCount).toBe(3);
        expect(attemptCount).toBe(4); // Initial attempt + 3 retries
        
        const status = jobQueue.getStatus(_failedJobId);
        expect(status?.status).toBe('failed');
        
        done();
      });

      workerPool.start();
    }, 15000);

    test('should apply exponential backoff on retries', (done) => {
      let attemptCount = 0;
      
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          attemptCount++;
          throw new Error('E_TIMEOUT: Connection timeout');
        }
      });

      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 100, // Base backoff: 100ms
          retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED', 'Worker timeout']
        }
      });

      const retryTimes: number[] = [];

      workerPool.on('worker:job:retrying', () => {
        retryTimes.push(Date.now());
        
        if (retryTimes.length >= 2) {
          // Check exponential backoff between retries
          const delay1 = retryTimes[1] - retryTimes[0];
          
          // First retry: backoffMs * 2^0 = 100ms
          // Second retry: backoffMs * 2^1 = 200ms
          // Allow some tolerance for timing
          expect(delay1).toBeGreaterThanOrEqual(150); // Should be ~200ms
          expect(delay1).toBeLessThan(300);
          
          done();
        }
      });

      workerPool.start();
    }, 15000);

    test('should re-enqueue job after backoff period', (done) => {
      let attemptCount = 0;
      
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          attemptCount++;
          throw new Error('E_TIMEOUT: Connection timeout');
        }
      });

      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 2,
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED', 'Worker timeout']
        }
      });

      let requeueCount = 0;

      jobQueue.on('job:requeued', (_requeuedJobId, attempts) => {
        requeueCount++;
        
        // Attempts should increment
        expect(attempts).toBe(requeueCount);
        
        if (requeueCount === 1) {
          // First requeue detected
          done();
        }
      });

      workerPool.start();
    }, 10000);

    test('should track attempt count across retries', (done) => {
      let attemptCount = 0;
      
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          attemptCount++;
          throw new Error('E_TIMEOUT: Connection timeout');
        }
      });

      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 30000,
        retryPolicy: {
          maxRetries: 3,
          backoffMs: 50,
          retryableErrors: ['E_TIMEOUT', 'E_RESOURCE_EXHAUSTED', 'Worker timeout']
        }
      });

      const attempts: number[] = [];

      workerPool.on('worker:job:retrying', (_workerId, _retriedJobId, attempt) => {
        attempts.push(attempt);
      });

      workerPool.on('worker:job:failed', () => {
        // Verify attempts incremented correctly
        expect(attempts.length).toBe(3);
        
        for (let i = 0; i < attempts.length; i++) {
          expect(attempts[i]).toBe(i + 1);
        }
        
        done();
      });

      workerPool.start();
    }, 15000);
  });

  describe('Timeout Control', () => {
    test('should detect job timeout and terminate worker', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          // Simulate long-running job that exceeds timeout
          await new Promise(resolve => setTimeout(resolve, 2000));
          return {
            jobId: _job.id,
            ok: true,
            data: {},
            errors: [],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 2000, peakRssMb: 0 }
          };
        }
      });

      const jobId = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 500, // 500ms timeout
        retryPolicy: {
          maxRetries: 0, // Don't retry so we can check final status
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT']
        }
      });

      workerPool.on('worker:job:timeout', (_workerId, timedOutJobId, elapsedMs) => {
        expect(timedOutJobId).toBe(jobId);
        expect(elapsedMs).toBeGreaterThanOrEqual(500);
        
        // Wait a bit for job queue to update
        setTimeout(() => {
          const status = jobQueue.getStatus(jobId);
          expect(status?.status).toBe('failed');
          expect(status?.error).toContain('E_TIMEOUT');
          done();
        }, 100);
      });

      workerPool.start();
    }, 10000);

    test('should retry job after timeout if retryable', (done) => {
      let attemptCount = 0;
      
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          attemptCount++;
          // Simulate long-running job
          await new Promise(resolve => setTimeout(resolve, 2000));
          return {
            jobId: _job.id,
            ok: true,
            data: {},
            errors: [],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 2000, peakRssMb: 0 }
          };
        }
      });

      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 500, // 500ms timeout
        retryPolicy: {
          maxRetries: 2,
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT']
        }
      });

      let retryCount = 0;

      workerPool.on('worker:job:retrying', (_workerId, _retriedJobId, attempt) => {
        retryCount++;
        expect(attempt).toBe(retryCount);
        
        if (retryCount === 1) {
          // First retry after timeout
          done();
        }
      });

      workerPool.start();
    }, 15000);

    test('should not timeout if job completes within limit', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          // Fast job that completes quickly
          await new Promise(resolve => setTimeout(resolve, 100));
          return {
            jobId: _job.id,
            ok: true,
            data: {},
            errors: [],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 100, peakRssMb: 0 }
          };
        }
      });

      const jobId = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 5000 // 5 second timeout (plenty of time)
      });

      let timeoutOccurred = false;

      workerPool.on('worker:job:timeout', () => {
        timeoutOccurred = true;
      });

      workerPool.on('worker:job:completed', (_workerId, completedJobId) => {
        expect(completedJobId).toBe(jobId);
        expect(timeoutOccurred).toBe(false);
        
        const status = jobQueue.getStatus(jobId);
        expect(status?.status).toBe('completed');
        
        done();
      });

      workerPool.start();
    }, 10000);

    test('should terminate worker process on timeout', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          // Simulate long-running job
          await new Promise(resolve => setTimeout(resolve, 2000));
          return {
            jobId: _job.id,
            ok: true,
            data: {},
            errors: [],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 2000, peakRssMb: 0 }
          };
        }
      });

      jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 500 // 500ms timeout
      });

      workerPool.on('worker:terminated', (workerId, type) => {
        expect(workerId).toBeDefined();
        expect(type).toBe('static');
        done();
      });

      workerPool.start();
    }, 10000);

    test('should clear timeout timer when job completes', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          // Fast job
          await new Promise(resolve => setTimeout(resolve, 100));
          return {
            jobId: _job.id,
            ok: true,
            data: {},
            errors: [],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 100, peakRssMb: 0 }
          };
        }
      });

      const jobId = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 5000
      });

      let timeoutOccurred = false;

      workerPool.on('worker:job:timeout', () => {
        timeoutOccurred = true;
      });

      workerPool.on('worker:job:completed', (_workerId, completedJobId) => {
        expect(completedJobId).toBe(jobId);
        
        // Wait a bit to ensure timeout doesn't fire
        setTimeout(() => {
          expect(timeoutOccurred).toBe(false);
          done();
        }, 1000);
      });

      workerPool.start();
    }, 10000);

    test('should include timeout value in error message', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        testExecutor: async (_job) => {
          await new Promise(resolve => setTimeout(resolve, 2000));
          return {
            jobId: _job.id,
            ok: true,
            data: {},
            errors: [],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 2000, peakRssMb: 0 }
          };
        }
      });

      const jobId = jobQueue.enqueue({
        type: 'static',
        tool: 'pe.fingerprint',
        sampleId: 'sha256:test',
        args: {},
        priority: JobPriority.NORMAL,
        timeout: 500,
        retryPolicy: {
          maxRetries: 0, // Don't retry
          backoffMs: 100,
          retryableErrors: ['E_TIMEOUT']
        }
      });

      workerPool.on('worker:job:timeout', () => {
        // Wait for job queue to update
        setTimeout(() => {
          const status = jobQueue.getStatus(jobId);
          expect(status?.error).toContain('500ms');
          expect(status?.error).toContain('E_TIMEOUT');
          done();
        }, 100);
      });

      workerPool.start();
    }, 10000);

    test('should handle multiple concurrent timeouts', (done) => {
      workerPool = new WorkerPool(jobQueue, {
        maxStaticWorkers: 3,
        testExecutor: async (_job) => {
          await new Promise(resolve => setTimeout(resolve, 2000));
          return {
            jobId: _job.id,
            ok: true,
            data: {},
            errors: [],
            warnings: [],
            artifacts: [],
            metrics: { elapsedMs: 2000, peakRssMb: 0 }
          };
        }
      });

      const jobIds: string[] = [];
      
      // Enqueue 3 jobs that will all timeout
      for (let i = 0; i < 3; i++) {
        const jobId = jobQueue.enqueue({
          type: 'static',
          tool: 'pe.fingerprint',
          sampleId: `sha256:test${i}`,
          args: {},
          priority: JobPriority.NORMAL,
          timeout: 500
        });
        jobIds.push(jobId);
      }

      const timedOutJobs = new Set<string>();

      workerPool.on('worker:job:timeout', (_workerId, timedOutJobId) => {
        timedOutJobs.add(timedOutJobId);
        
        if (timedOutJobs.size === 3) {
          // All jobs timed out
          jobIds.forEach(id => expect(timedOutJobs.has(id)).toBe(true));
          done();
        }
      });

      workerPool.start();
    }, 15000);
  });
});