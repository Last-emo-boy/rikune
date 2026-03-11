/**
 * Unit tests for logger module
 */

import {
  logger,
  createChildLogger,
  logOperationStart,
  logOperationComplete,
  logOperationError,
  logAudit,
  logMetrics,
  logWarning,
  logDebug,
  logError,
  createTimer,
  withLogging,
  withLoggingSync,
  type OperationContext,
  type PerformanceMetrics,
  type AuditEvent,
} from '../../src/logger.js';

describe('Logger', () => {
  describe('createChildLogger', () => {
    it('should create a child logger with context', () => {
      const childLogger = createChildLogger({ sampleId: 'test-123' });
      expect(childLogger).toBeDefined();
    });
  });

  describe('logOperationStart', () => {
    it('should log operation start', () => {
      const context: OperationContext = {
        operation: 'test-operation',
        sampleId: 'sample-123',
      };

      // Should not throw
      expect(() => logOperationStart(context)).not.toThrow();
    });
  });

  describe('logOperationComplete', () => {
    it('should log operation completion with metrics', () => {
      const context: OperationContext = {
        operation: 'test-operation',
        sampleId: 'sample-123',
      };
      const metrics: PerformanceMetrics = {
        elapsedMs: 100,
        peakRssMb: 50,
      };

      expect(() => logOperationComplete(context, metrics)).not.toThrow();
    });
  });

  describe('logOperationError', () => {
    it('should log operation error with stack trace', () => {
      const context: OperationContext = {
        operation: 'test-operation',
        sampleId: 'sample-123',
      };
      const error = new Error('Test error');
      const metrics: PerformanceMetrics = {
        elapsedMs: 50,
      };

      expect(() => logOperationError(context, error, metrics)).not.toThrow();
    });
  });

  describe('logAudit', () => {
    it('should log audit event', () => {
      const event: AuditEvent = {
        operation: 'sample.ingest',
        user: 'test-user',
        sampleId: 'sample-123',
        decision: 'allow',
        reason: 'Policy check passed',
      };

      expect(() => logAudit(event)).not.toThrow();
    });

    it('should log deny decision', () => {
      const event: AuditEvent = {
        operation: 'sandbox.execute',
        sampleId: 'sample-123',
        decision: 'deny',
        reason: 'Requires approval',
      };

      expect(() => logAudit(event)).not.toThrow();
    });
  });

  describe('logMetrics', () => {
    it('should log performance metrics', () => {
      const metrics: PerformanceMetrics = {
        elapsedMs: 1500,
        peakRssMb: 128,
        cpuPercent: 45.5,
      };

      expect(() => logMetrics('pe.fingerprint', metrics)).not.toThrow();
    });

    it('should log metrics with additional context', () => {
      const metrics: PerformanceMetrics = {
        elapsedMs: 2000,
        peakRssMb: 256,
      };
      const context = {
        sampleId: 'sample-123',
        backend: 'ghidra',
      };

      expect(() => logMetrics('ghidra.analyze', metrics, context)).not.toThrow();
    });
  });

  describe('logWarning', () => {
    it('should log warning message', () => {
      expect(() => logWarning('This is a warning')).not.toThrow();
    });

    it('should log warning with context', () => {
      expect(() =>
        logWarning('Cache miss', { cacheKey: 'test-key' })
      ).not.toThrow();
    });
  });

  describe('logDebug', () => {
    it('should log debug message', () => {
      expect(() => logDebug('Debug information')).not.toThrow();
    });

    it('should log debug with context', () => {
      expect(() =>
        logDebug('Processing sample', { sampleId: 'sample-123' })
      ).not.toThrow();
    });
  });

  describe('logError', () => {
    it('should log error with stack trace', () => {
      const error = new Error('Test error');
      expect(() => logError(error)).not.toThrow();
    });

    it('should log error with context', () => {
      const error = new Error('Database connection failed');
      const context = { database: 'sqlite', path: './test.db' };
      expect(() => logError(error, context)).not.toThrow();
    });
  });

  describe('createTimer', () => {
    it('should create a timer and measure elapsed time', async () => {
      const timer = createTimer();

      // Wait a bit
      await new Promise((resolve) => setTimeout(resolve, 15));

      const metrics = timer.end();

      expect(metrics.elapsedMs).toBeGreaterThanOrEqual(10);
      expect(metrics.peakRssMb).toBeGreaterThan(0);
    });

    it('should measure memory usage', () => {
      const timer = createTimer();
      const metrics = timer.end();

      expect(metrics.peakRssMb).toBeDefined();
      expect(typeof metrics.peakRssMb).toBe('number');
      expect(metrics.peakRssMb).toBeGreaterThan(0);
    });
  });

  describe('withLogging', () => {
    it('should wrap async operation with logging', async () => {
      const context: OperationContext = {
        operation: 'test-async',
        sampleId: 'sample-123',
      };

      const result = await withLogging(context, async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        return 'success';
      });

      expect(result).toBe('success');
    });

    it('should log errors from async operations', async () => {
      const context: OperationContext = {
        operation: 'test-async-error',
        sampleId: 'sample-123',
      };

      await expect(
        withLogging(context, async () => {
          throw new Error('Async operation failed');
        })
      ).rejects.toThrow('Async operation failed');
    });

    it('should measure performance of async operations', async () => {
      const context: OperationContext = {
        operation: 'test-async-perf',
      };

      const result = await withLogging(context, async () => {
        await new Promise((resolve) => setTimeout(resolve, 50));
        return 'done';
      });

      expect(result).toBe('done');
    });
  });

  describe('withLoggingSync', () => {
    it('should wrap sync operation with logging', () => {
      const context: OperationContext = {
        operation: 'test-sync',
        sampleId: 'sample-123',
      };

      const result = withLoggingSync(context, () => {
        return 'success';
      });

      expect(result).toBe('success');
    });

    it('should log errors from sync operations', () => {
      const context: OperationContext = {
        operation: 'test-sync-error',
        sampleId: 'sample-123',
      };

      expect(() =>
        withLoggingSync(context, () => {
          throw new Error('Sync operation failed');
        })
      ).toThrow('Sync operation failed');
    });

    it('should measure performance of sync operations', () => {
      const context: OperationContext = {
        operation: 'test-sync-perf',
      };

      const result = withLoggingSync(context, () => {
        // Simulate some work
        let sum = 0;
        for (let i = 0; i < 1000; i++) {
          sum += i;
        }
        return sum;
      });

      expect(result).toBe(499500);
    });
  });

  describe('Logger instance', () => {
    it('should have standard log methods', () => {
      expect(logger.info).toBeDefined();
      expect(logger.error).toBeDefined();
      expect(logger.warn).toBeDefined();
      expect(logger.debug).toBeDefined();
      expect(logger.trace).toBeDefined();
      expect(logger.fatal).toBeDefined();
    });

    it('should support child logger creation', () => {
      const child = logger.child({ component: 'test' });
      expect(child).toBeDefined();
      expect(child.info).toBeDefined();
    });
  });
});
