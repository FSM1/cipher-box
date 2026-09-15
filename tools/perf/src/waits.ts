/**
 * The cross-client convergence latency: what the harness's settled waits cost.
 *
 * A sample is one wait that a second host's read satisfied, so the elapsed time
 * is the time a write took to reach that host, rounded up to the poll interval
 * the CI timing profile sets. The rows are therefore read as poll cycles first
 * and as milliseconds second.
 */

export interface WaitSample {
  what: string;
  elapsedMs: number;
  attempts: number;
}

export interface WaitGroup {
  what: string;
  count: number;
  p50Ms: number;
  p95Ms: number;
  maxMs: number;
  maxAttempts: number;
}

/** Reads the JSONL a run appended. A malformed line is a refusal, not a skip. */
export function parseSamples(jsonl: string): WaitSample[] {
  return jsonl
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      const value: unknown = JSON.parse(line);
      if (typeof value !== 'object' || value === null) {
        throw new Error(`sample ${index + 1} is not an object`);
      }
      const sample = value as Record<string, unknown>;
      if (
        typeof sample.what !== 'string' ||
        typeof sample.elapsedMs !== 'number' ||
        typeof sample.attempts !== 'number'
      ) {
        throw new Error(`sample ${index + 1} is not a wait sample`);
      }
      return { what: sample.what, elapsedMs: sample.elapsedMs, attempts: sample.attempts };
    });
}

/**
 * One row per distinct wait, worst first.
 *
 * The waits are grouped by `what` verbatim: the harness writes that string, and
 * two waits that read the same signal on the same host share it.
 */
export function group(samples: readonly WaitSample[]): WaitGroup[] {
  const byWhat = new Map<string, WaitSample[]>();
  for (const sample of samples) {
    const bucket = byWhat.get(sample.what);
    if (bucket) bucket.push(sample);
    else byWhat.set(sample.what, [sample]);
  }
  const groups = [...byWhat.entries()].map(([what, bucket]) => {
    const elapsed = bucket.map((sample) => sample.elapsedMs).sort((a, b) => a - b);
    return {
      what,
      count: bucket.length,
      p50Ms: percentile(elapsed, 50),
      p95Ms: percentile(elapsed, 95),
      maxMs: elapsed[elapsed.length - 1],
      maxAttempts: Math.max(...bucket.map((sample) => sample.attempts)),
    };
  });
  return groups.sort((a, b) => b.maxMs - a.maxMs);
}

/** The nearest-rank percentile of an already-sorted series, as the load harness takes it. */
export function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) throw new Error('a percentile of no samples');
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(Math.max(rank, 1), sorted.length) - 1];
}

export function renderWaits(groups: readonly WaitGroup[]): string {
  const header =
    '| Wait | n | p50 ms | p95 ms | max ms | max reads |\n| --- | --: | --: | --: | --: | --: |';
  const rows = groups.map(
    (row) =>
      `| ${row.what} | ${row.count} | ${row.p50Ms} | ${row.p95Ms} | ${row.maxMs} | ` +
      `${row.maxAttempts} |`
  );
  return [header, ...rows].join('\n');
}
