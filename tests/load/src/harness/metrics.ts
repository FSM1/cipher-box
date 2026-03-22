/**
 * Load Test Metrics Collection
 *
 * Collects per-operation latency, throughput, and error counts.
 * Uses performance.now() for high-resolution timing.
 */

export interface OperationMetrics {
  operation: string;
  count: number;
  errors: number;
  latency: { p50: number; p95: number; p99: number; max: number; min: number; avg: number };
  throughputOpsPerSec: number;
  bytesTransferred?: number;
}

export interface OperationSample {
  operation: string;
  durationMs: number;
  success: boolean;
  bytes?: number;
  timestamp: number;
}

export class MetricsCollector {
  private samples: OperationSample[] = [];
  private startTime = 0;
  private endTime = 0;

  start(): void {
    this.startTime = performance.now();
  }

  stop(): void {
    this.endTime = performance.now();
  }

  /** Override elapsed time for aggregated collectors (set from sample timestamps). */
  setElapsedMs(ms: number): void {
    this.startTime = 0;
    this.endTime = ms;
  }

  record(sample: OperationSample): void {
    this.samples.push(sample);
  }

  /**
   * Wrap an async operation to automatically record metrics.
   */
  async measure<T>(operation: string, fn: () => Promise<T>, bytes?: number): Promise<T> {
    const start = performance.now();
    try {
      const result = await fn();
      this.record({
        operation,
        durationMs: performance.now() - start,
        success: true,
        bytes,
        timestamp: Date.now(),
      });
      return result;
    } catch (err) {
      this.record({
        operation,
        durationMs: performance.now() - start,
        success: false,
        bytes,
        timestamp: Date.now(),
      });
      throw err;
    }
  }

  /**
   * Get aggregated metrics per operation type.
   */
  getMetrics(): OperationMetrics[] {
    const elapsed = (this.endTime || performance.now()) - this.startTime;
    const elapsedSec = elapsed / 1000;

    const grouped = new Map<string, OperationSample[]>();
    for (const s of this.samples) {
      const list = grouped.get(s.operation) ?? [];
      list.push(s);
      grouped.set(s.operation, list);
    }

    const metrics: OperationMetrics[] = [];
    for (const [op, samples] of grouped) {
      const durations = samples.map((s) => s.durationMs).sort((a, b) => a - b);
      const errors = samples.filter((s) => !s.success).length;
      const totalBytes = samples.reduce((sum, s) => sum + (s.bytes ?? 0), 0);

      metrics.push({
        operation: op,
        count: samples.length,
        errors,
        latency: {
          min: durations[0] ?? 0,
          avg: durations.reduce((a, b) => a + b, 0) / durations.length,
          p50: percentile(durations, 0.5),
          p95: percentile(durations, 0.95),
          p99: percentile(durations, 0.99),
          max: durations[durations.length - 1] ?? 0,
        },
        throughputOpsPerSec: elapsedSec > 0 ? samples.length / elapsedSec : 0,
        ...(totalBytes > 0 ? { bytesTransferred: totalBytes } : {}),
      });
    }

    return metrics.sort((a, b) => a.operation.localeCompare(b.operation));
  }

  /** Total samples collected */
  get totalSamples(): number {
    return this.samples.length;
  }

  /** Total errors across all operations */
  get totalErrors(): number {
    return this.samples.filter((s) => !s.success).length;
  }

  /** Raw samples (defensive copy, for JSON export) */
  getRawSamples(): OperationSample[] {
    return [...this.samples];
  }

  /** Read-only access to samples (no copy, for aggregation loops) */
  getReadonlySamples(): readonly OperationSample[] {
    return this.samples;
  }
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil(p * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}
