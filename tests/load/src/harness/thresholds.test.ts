/**
 * Threshold Checking Unit Tests
 *
 * Verifies that checkThresholds correctly identifies pass/fail conditions
 * based on p95 latency and error rate thresholds.
 */

import { describe, it, expect } from 'vitest';
import { checkThresholds, type ThresholdConfig } from './thresholds';
import type { OperationMetrics } from './metrics';

function makeMetrics(
  overrides: Partial<OperationMetrics> & { operation: string }
): OperationMetrics {
  return {
    count: 100,
    errors: 0,
    latency: { p50: 500, p95: 1000, p99: 1500, max: 2000, min: 100, avg: 600 },
    throughputOpsPerSec: 10,
    ...overrides,
  };
}

describe('checkThresholds', () => {
  it('returns passed: true when all metrics are within limits', () => {
    const metrics: OperationMetrics[] = [
      makeMetrics({
        operation: 'uploadFile',
        latency: { p50: 500, p95: 2000, p99: 3000, max: 4000, min: 100, avg: 600 },
      }),
      makeMetrics({
        operation: 'createFolder',
        latency: { p50: 200, p95: 800, p99: 1200, max: 1500, min: 50, avg: 300 },
      }),
    ];

    const thresholds: ThresholdConfig[] = [
      { operation: 'uploadFile', p95MaxMs: 10_000, errorRateMax: 0.05 },
      { operation: 'createFolder', p95MaxMs: 5_000, errorRateMax: 0.1 },
    ];

    const result = checkThresholds(metrics, thresholds);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('returns passed: false when p95 exceeds threshold', () => {
    const metrics: OperationMetrics[] = [
      makeMetrics({
        operation: 'uploadFile',
        latency: { p50: 5000, p95: 12_000, p99: 15_000, max: 20_000, min: 1000, avg: 6000 },
      }),
    ];

    const thresholds: ThresholdConfig[] = [
      { operation: 'uploadFile', p95MaxMs: 10_000, errorRateMax: 0.05 },
    ];

    const result = checkThresholds(metrics, thresholds);
    expect(result.passed).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0]).toContain('p95');
    expect(result.violations[0]).toContain('12000ms');
    expect(result.violations[0]).toContain('10000ms');
  });

  it('returns passed: false when error rate exceeds threshold', () => {
    const metrics: OperationMetrics[] = [
      makeMetrics({
        operation: 'uploadFile',
        count: 100,
        errors: 10, // 10% error rate
        latency: { p50: 500, p95: 2000, p99: 3000, max: 4000, min: 100, avg: 600 },
      }),
    ];

    const thresholds: ThresholdConfig[] = [
      { operation: 'uploadFile', p95MaxMs: 10_000, errorRateMax: 0.05 }, // 5% max
    ];

    const result = checkThresholds(metrics, thresholds);
    expect(result.passed).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0]).toContain('error rate');
    expect(result.violations[0]).toContain('10.0%');
    expect(result.violations[0]).toContain('5.0%');
  });

  it('skips operations not found in metrics (no false violation)', () => {
    const metrics: OperationMetrics[] = [makeMetrics({ operation: 'uploadFile' })];

    const thresholds: ThresholdConfig[] = [
      { operation: 'uploadFile', p95MaxMs: 10_000, errorRateMax: 0.05 },
      { operation: 'createFolder', p95MaxMs: 5_000, errorRateMax: 0.1 }, // not in metrics
      { operation: 'deleteItem', p95MaxMs: 3_000, errorRateMax: 0.05 }, // not in metrics
    ];

    const result = checkThresholds(metrics, thresholds);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('violation message includes operation name, observed value, and threshold value', () => {
    const metrics: OperationMetrics[] = [
      makeMetrics({
        operation: 'createFolder',
        count: 50,
        errors: 10, // 20% error rate
        latency: { p50: 3000, p95: 6000, p99: 8000, max: 10000, min: 500, avg: 4000 },
      }),
    ];

    const thresholds: ThresholdConfig[] = [
      { operation: 'createFolder', p95MaxMs: 5_000, errorRateMax: 0.1 },
    ];

    const result = checkThresholds(metrics, thresholds);
    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(2);

    // p95 violation
    const p95Violation = result.violations.find((v) => v.includes('p95'));
    expect(p95Violation).toBeDefined();
    expect(p95Violation).toContain('createFolder');
    expect(p95Violation).toContain('6000ms');
    expect(p95Violation).toContain('5000ms');

    // error rate violation
    const errorViolation = result.violations.find((v) => v.includes('error rate'));
    expect(errorViolation).toBeDefined();
    expect(errorViolation).toContain('createFolder');
    expect(errorViolation).toContain('20.0%');
    expect(errorViolation).toContain('10.0%');
  });
});
