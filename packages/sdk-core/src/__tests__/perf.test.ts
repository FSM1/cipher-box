import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

describe('Performance instrumentation', () => {
  let originalNodeEnv: string | undefined;
  let originalPerfFlag: unknown;

  beforeEach(() => {
    originalNodeEnv = process.env.NODE_ENV;
    originalPerfFlag = (globalThis as any).__CIPHERBOX_PERF__;
    // Clear performance entries between tests
    performance.clearMarks();
    performance.clearMeasures();
  });

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
    if (originalPerfFlag === undefined) {
      delete (globalThis as any).__CIPHERBOX_PERF__;
    } else {
      (globalThis as any).__CIPHERBOX_PERF__ = originalPerfFlag;
    }
    vi.resetModules();
  });

  describe('withPerf (enabled)', () => {
    it('calls performance.measure with name starting with "cipherbox:" when enabled', async () => {
      process.env.NODE_ENV = 'test';
      const { markStart, markEnd } = await import('../perf');

      const start = markStart('upload:full');
      const measure = markEnd('upload:full', start);

      expect(measure).not.toBeNull();
      expect(measure!.name).toBe('cipherbox:upload:full');
      expect(measure!.duration).toBeGreaterThanOrEqual(0);
    });

    it('returns the wrapped function return value unchanged', async () => {
      process.env.NODE_ENV = 'test';
      const { withPerf } = await import('../perf');

      const result = await withPerf('test:op', async () => ({ id: 42, data: [1, 2, 3] }));

      expect(result).toEqual({ id: 42, data: [1, 2, 3] });
    });

    it('clears marks after measurement (no mark accumulation)', async () => {
      process.env.NODE_ENV = 'test';
      const { withPerf } = await import('../perf');

      await withPerf('cleanup:test', async () => 'done');

      const startMarks = performance.getEntriesByName('cipherbox:cleanup:test:start');
      const endMarks = performance.getEntriesByName('cipherbox:cleanup:test:end');
      expect(startMarks).toHaveLength(0);
      expect(endMarks).toHaveLength(0);
    });

    it('propagates errors from the wrapped function without swallowing them', async () => {
      process.env.NODE_ENV = 'test';
      const { withPerf } = await import('../perf');

      await expect(
        withPerf('error:test', async () => {
          throw new Error('upload failed');
        })
      ).rejects.toThrow('upload failed');
    });
  });

  describe('withPerf (disabled in production)', () => {
    it('does NOT create marks/measures when NODE_ENV=production and __CIPHERBOX_PERF__ is not set', async () => {
      process.env.NODE_ENV = 'production';
      delete (globalThis as any).__CIPHERBOX_PERF__;
      const { withPerf } = await import('../perf');

      performance.clearMarks();
      performance.clearMeasures();

      const result = await withPerf('prod:test', async () => 'value');

      expect(result).toBe('value');
      const measures = performance.getEntriesByType('measure');
      const cbMeasures = measures.filter((m) => m.name.startsWith('cipherbox:'));
      expect(cbMeasures).toHaveLength(0);
    });
  });

  describe('markStart / markEnd (disabled)', () => {
    it('markStart returns empty string when disabled, markEnd is a no-op when startMark is empty', async () => {
      process.env.NODE_ENV = 'production';
      delete (globalThis as any).__CIPHERBOX_PERF__;
      const { markStart, markEnd } = await import('../perf');

      const start = markStart('noop:test');
      expect(start).toBe('');

      const measure = markEnd('noop:test', start);
      expect(measure).toBeNull();
    });
  });
});
