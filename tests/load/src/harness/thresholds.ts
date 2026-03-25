/**
 * Load Test Threshold Checking
 *
 * Defines pass/fail thresholds for load test scenarios.
 * Compares observed metrics against defined limits and produces
 * actionable violation messages for CI output.
 */

import type { OperationMetrics } from './metrics';

export interface ThresholdConfig {
  /** Operation name to match against OperationMetrics.operation */
  operation: string;
  /** Maximum allowed p95 latency in milliseconds */
  p95MaxMs: number;
  /** Maximum allowed error rate (0.0 to 1.0) */
  errorRateMax: number;
}

export interface ThresholdResult {
  passed: boolean;
  violations: string[];
}

/**
 * Check collected metrics against defined thresholds.
 * Returns pass/fail with descriptive violation messages.
 *
 * Operations in thresholds that are not found in metrics are silently
 * skipped — a scenario may not exercise every operation.
 */
export function checkThresholds(
  metrics: OperationMetrics[],
  thresholds: ThresholdConfig[]
): ThresholdResult {
  const violations: string[] = [];

  for (const t of thresholds) {
    const m = metrics.find((op) => op.operation === t.operation);
    if (!m) continue;

    if (m.latency.p95 > t.p95MaxMs) {
      violations.push(
        `${t.operation} p95 ${Math.round(m.latency.p95)}ms exceeds threshold ${t.p95MaxMs}ms`
      );
    }

    const errorRate = m.count > 0 ? m.errors / m.count : 0;
    if (errorRate > t.errorRateMax) {
      violations.push(
        `${t.operation} error rate ${(errorRate * 100).toFixed(1)}% exceeds threshold ${(t.errorRateMax * 100).toFixed(1)}%`
      );
    }
  }

  return { passed: violations.length === 0, violations };
}
