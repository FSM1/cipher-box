/**
 * Load Test Reporter
 *
 * Formats metrics into console table output and JSON export.
 */

import type { OperationMetrics } from './metrics';

/**
 * Print a formatted summary table to console.
 */
export function printSummary(
  scenarioName: string,
  metrics: OperationMetrics[],
  totalDurationMs: number,
  clientCount: number
): void {
  const totalOps = metrics.reduce((sum, m) => sum + m.count, 0);
  const totalErrors = metrics.reduce((sum, m) => sum + m.errors, 0);
  const totalBytes = metrics.reduce((sum, m) => sum + (m.bytesTransferred ?? 0), 0);

  console.log(`\n${'='.repeat(80)}`);
  console.log(`LOAD TEST: ${scenarioName}`);
  console.log(`${'='.repeat(80)}`);
  console.log(`Clients:     ${clientCount}`);
  console.log(`Duration:    ${(totalDurationMs / 1000).toFixed(1)}s`);
  console.log(`Total ops:   ${totalOps} (${totalErrors} errors)`);
  console.log(`Throughput:  ${(totalOps / (totalDurationMs / 1000)).toFixed(2)} ops/sec`);
  if (totalBytes > 0) {
    console.log(`Data:        ${formatBytes(totalBytes)}`);
  }
  console.log(`${'─'.repeat(80)}`);

  // Table header
  console.log(
    padRight('Operation', 22) +
      padRight('Count', 8) +
      padRight('Errors', 8) +
      padRight('p50', 10) +
      padRight('p95', 10) +
      padRight('p99', 10) +
      padRight('Max', 10)
  );
  console.log('─'.repeat(80));

  for (const m of metrics) {
    console.log(
      padRight(m.operation, 22) +
        padRight(String(m.count), 8) +
        padRight(String(m.errors), 8) +
        padRight(fmtMs(m.latency.p50), 10) +
        padRight(fmtMs(m.latency.p95), 10) +
        padRight(fmtMs(m.latency.p99), 10) +
        padRight(fmtMs(m.latency.max), 10)
    );
  }

  console.log(`${'='.repeat(80)}\n`);
}

/**
 * Export metrics as JSON (for CI artifact upload).
 */
export function toJsonReport(
  scenarioName: string,
  metrics: OperationMetrics[],
  totalDurationMs: number,
  clientCount: number
): string {
  return JSON.stringify(
    {
      scenario: scenarioName,
      clientCount,
      totalDurationMs,
      totalOps: metrics.reduce((sum, m) => sum + m.count, 0),
      totalErrors: metrics.reduce((sum, m) => sum + m.errors, 0),
      operations: metrics,
      timestamp: new Date().toISOString(),
    },
    null,
    2
  );
}

function padRight(str: string, len: number): string {
  return str.padEnd(len);
}

function fmtMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}
