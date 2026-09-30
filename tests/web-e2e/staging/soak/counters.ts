/**
 * The republisher counters on staging, read from Grafana Cloud through the
 * Mimir query endpoint with basic authentication. The read token never enters
 * an error, a record or a log: every refusal here names an env var or an HTTP
 * status, never a value.
 */

import type { Env } from '../../tools/loginSecretExport';
import { keyedLine, withKeyedLine, type Ledger } from './ledger';
import { SoakFailure, type FailureReason } from './reasons';

export const GRAFANA_URL_ENV = 'GRAFANA_PROMETHEUS_URL';
export const GRAFANA_USER_ENV = 'GRAFANA_PROMETHEUS_USERNAME';
export const GRAFANA_TOKEN_ENV = 'STAGING_GRAFANA_READ_TOKEN';

/** Under this API uptime the gauges still read their boot value and the counters skip. */
export const POST_DEPLOY_S = 12 * 3600;

/**
 * `increase` extrapolates to the window edges, so two walks at a 12-hour
 * cadence can read a little below 2.
 */
export const WALK_TOLERANCE = 0.1;

export const UPTIME_QUERY = 'time() - process_start_time_seconds{job="api"}';

export const COUNTER_QUERIES = {
  staleNames: 'increase(republisher_stale_names_total[24h])',
  walksSkipped: 'increase(republisher_walks_skipped_total[24h])',
  resolveFailures: 'increase(republisher_resolve_failures_total[24h])',
  walks: 'increase(republisher_walks_total[24h])',
  lastWalkNames: 'republisher_last_walk_names',
} as const;

export type CounterReadings = Record<keyof typeof COUNTER_QUERIES, number>;

const STALE_BASELINE = 'stale-names-baseline';

export interface GrafanaAccess {
  /** The Prometheus API root: the push URL without its `/push` suffix. */
  readonly base: string;
  readonly authorization: string;
}

export function grafanaAccess(env: Env): GrafanaAccess {
  const value = (name: string): string => {
    const raw = env[name]?.trim();
    if (raw === undefined || raw === '') {
      throw new SoakFailure('counters-unread', `${name} is not set`);
    }
    return raw;
  };
  const push = value(GRAFANA_URL_ENV);
  if (!/^https:\/\/\S+\/push$/.test(push)) {
    throw new SoakFailure('counters-unread', `${GRAFANA_URL_ENV} is not an https URL ending /push`);
  }
  const credentials = `${value(GRAFANA_USER_ENV)}:${value(GRAFANA_TOKEN_ENV)}`;
  return {
    base: push.slice(0, -'/push'.length),
    authorization: `Basic ${Buffer.from(credentials).toString('base64')}`,
  };
}

/** The sample values of an instant-query answer; an empty vector is `[]`. */
export function instantValues(body: unknown): number[] {
  const answer = body as {
    status?: unknown;
    data?: { resultType?: unknown; result?: unknown };
  } | null;
  if (answer?.status !== 'success') throw new Error('the query did not succeed');
  const data = answer.data;
  if (data?.resultType === 'scalar') return [sampleValue((data as { result?: unknown }).result)];
  if (data?.resultType !== 'vector' || !Array.isArray(data.result)) {
    throw new Error('the query answered no vector');
  }
  return data.result.map((series: { value?: unknown }) => sampleValue(series?.value));
}

function sampleValue(sample: unknown): number {
  const value = Array.isArray(sample) && sample.length === 2 ? Number(sample[1]) : Number.NaN;
  if (!Number.isFinite(value)) throw new Error('the query answered a sample that is not a number');
  return value;
}

/** One instant query. A refusal names the query and the HTTP status, never the URL or the token. */
export async function query(
  access: GrafanaAccess,
  promql: string,
  timeoutMs: number
): Promise<number[]> {
  const url = `${access.base}/api/v1/query?query=${encodeURIComponent(promql)}`;
  let response: Response;
  try {
    response = await fetch(url, {
      headers: { authorization: access.authorization },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    const name = error instanceof Error ? error.name : 'an error';
    throw new SoakFailure('counters-unread', `${promql}: the request failed with ${name}`);
  }
  if (!response.ok) {
    throw new SoakFailure('counters-unread', `${promql}: HTTP ${response.status}`);
  }
  try {
    return instantValues(await response.json());
  } catch (error) {
    throw new SoakFailure('counters-unread', `${promql}: ${(error as Error).message}`);
  }
}

/** The one series a counter query names. */
export function oneSeries(promql: string, values: readonly number[]): number {
  if (values.length !== 1) {
    throw new SoakFailure('counters-unread', `${promql} answered ${values.length} series`);
  }
  return values[0]!;
}

/** The youngest API process: one restart is enough to open the window. */
export function uptimeSeconds(values: readonly number[]): number {
  if (values.length === 0) throw new SoakFailure('counters-unread', 'no API uptime series');
  return Math.min(...values);
}

export function inPostDeployWindow(uptimeS: number): boolean {
  return uptimeS <= POST_DEPLOY_S;
}

export function uptimeLine(uptimeS: number): string {
  return `the API is up ${(uptimeS / 3600).toFixed(1)} hours`;
}

export interface CounterCheck {
  readonly check: string;
  readonly reason: FailureReason;
  /** The failed detail, or `null` for a pass. */
  readonly verdict: (readings: CounterReadings, staleBaseline: number) => string | null;
}

/**
 * An `increase` of a count that did not move can read a fraction above a whole
 * number, so the counts compare rounded.
 */
function grew(value: number, limit: number, what: string): string | null {
  return Math.round(value) > limit
    ? `${what} grew by ${value.toFixed(2)} in 24 hours, limit ${limit}`
    : null;
}

export const COUNTER_CHECKS: readonly CounterCheck[] = [
  {
    check: 'stale names in 24 hours',
    reason: 'stale-names-grew',
    verdict: (r, baseline) => grew(r.staleNames, baseline, 'stale names'),
  },
  {
    check: 'skipped walks in 24 hours',
    reason: 'walks-skipped-grew',
    verdict: (r) => grew(r.walksSkipped, 0, 'skipped walks'),
  },
  {
    check: 'resolve failures in 24 hours',
    reason: 'resolve-failures-grew',
    verdict: (r) => grew(r.resolveFailures, 0, 'resolve failures'),
  },
  {
    check: 'walks in 24 hours',
    reason: 'no-walk-in-window',
    verdict: (r) =>
      r.walks < 2 - WALK_TOLERANCE ? `${r.walks.toFixed(2)} walks in 24 hours, want 2` : null,
  },
  {
    check: 'names in the last walk',
    reason: 'last-walk-empty',
    verdict: (r) => (r.lastWalkNames > 0 ? null : 'the last walk found 0 names'),
  },
];

const COUNTERS = Object.keys(COUNTER_QUERIES) as (keyof CounterReadings)[];

export async function readCounters(
  access: GrafanaAccess,
  timeoutMs: number
): Promise<CounterReadings> {
  const values = await Promise.all(
    COUNTERS.map(async (key) => {
      const promql = COUNTER_QUERIES[key];
      return oneSeries(promql, await query(access, promql, timeoutMs));
    })
  );
  return Object.fromEntries(COUNTERS.map((key, index) => [key, values[index]])) as CounterReadings;
}

export function countersLine(readings: CounterReadings): string {
  return COUNTERS.map((key) => `${key} ${readings[key].toFixed(2)}`).join('; ');
}

/** The stale-names baseline the ledger holds, or `null` before the first reading. */
export function staleBaseline(ledger: Ledger): number | null {
  const fields = keyedLine(ledger, STALE_BASELINE);
  if (fields === null) return null;
  if (fields.length !== 1 || !/^(0|[1-9]\d*)$/.test(fields[0]!)) {
    throw new SoakFailure('ledger-unparsable', `the ${STALE_BASELINE} line is bad`);
  }
  return Number(fields[0]);
}

/** Records the first reading, rounded, as the baseline. */
export function withStaleBaseline(ledger: Ledger, staleNames: number): Ledger {
  return withKeyedLine(ledger, STALE_BASELINE, [String(Math.max(Math.round(staleNames), 0))]);
}
