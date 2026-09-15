/**
 * The load harness's JSON report, and the RESULTS.md rows it renders to.
 *
 * The harness owns every number: it measures the shipping API client path, so
 * this module re-computes no percentile and only reshapes what the run wrote.
 */

export interface OperationRow {
  op: string;
  count: number;
  throttled: number;
  failed: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  opsPerSec: number;
}

export interface LoadReport {
  scenario: string;
  breaches: string[];
  operations: OperationRow[];
}

/** The scenarios one baseline covers, in the order RESULTS.md lists them. */
export const BASELINE_SCENARIOS = [
  'content-ingest',
  'gateway-read',
  'name-wave',
  'mixed',
  'byo-advisory',
] as const;

export type BaselineScenario = (typeof BASELINE_SCENARIOS)[number];

export function isBaselineScenario(value: string): value is BaselineScenario {
  return (BASELINE_SCENARIOS as readonly string[]).includes(value);
}

/**
 * Reads one report. A field that is absent or of the wrong type is a refusal,
 * not a zero: a baseline row silently built from a missing number is a false
 * record, and it outlives the run that produced it.
 */
export function parseLoadReport(json: string): LoadReport {
  const value: unknown = JSON.parse(json);
  const report = asRecord(value, 'the report');
  const operations = asArray(report.operations, 'operations').map((entry, index) => {
    const row = asRecord(entry, `operations[${index}]`);
    return {
      op: asString(row.op, `operations[${index}].op`),
      count: asNumber(row.count, `operations[${index}].count`),
      throttled: asNumber(row.throttled, `operations[${index}].throttled`),
      failed: asNumber(row.failed, `operations[${index}].failed`),
      p50Ms: asNumber(row.p50Ms, `operations[${index}].p50Ms`),
      p95Ms: asNumber(row.p95Ms, `operations[${index}].p95Ms`),
      p99Ms: asNumber(row.p99Ms, `operations[${index}].p99Ms`),
      opsPerSec: asNumber(row.opsPerSec, `operations[${index}].opsPerSec`),
    };
  });
  return {
    scenario: asString(report.scenario, 'scenario'),
    breaches: asArray(report.breaches, 'breaches').map((entry, index) =>
      asString(entry, `breaches[${index}]`)
    ),
    operations,
  };
}

/** The RESULTS.md table for one target, one row per operation of every scenario. */
export function renderTable(reports: readonly LoadReport[]): string {
  const header =
    '| Scenario | Operation | n | 429 | err | p50 ms | p95 ms | p99 ms | ops/s |\n' +
    '| --- | --- | --: | --: | --: | --: | --: | --: | --: |';
  const rows = reports.flatMap((report) =>
    report.operations.map(
      (row) =>
        `| \`${report.scenario}\` | \`${row.op}\` | ${row.count} | ${row.throttled} | ` +
        `${row.failed} | ${fixed(row.p50Ms)} | ${fixed(row.p95Ms)} | ${fixed(row.p99Ms)} | ` +
        `${fixed(row.opsPerSec)} |`
    )
  );
  return [header, ...rows].join('\n');
}

/** Every breach the set carries, named by scenario, for the run's own summary. */
export function breachesOf(reports: readonly LoadReport[]): string[] {
  return reports.flatMap((report) =>
    report.breaches.map((breach) => `${report.scenario}: ${breach}`)
  );
}

function fixed(value: number): string {
  return value.toFixed(1);
}

function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${what} is not an object`);
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${what} is not an array`);
  return value;
}

function asString(value: unknown, what: string): string {
  if (typeof value !== 'string') throw new Error(`${what} is not a string`);
  return value;
}

function asNumber(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${what} is not a finite number`);
  }
  return value;
}
