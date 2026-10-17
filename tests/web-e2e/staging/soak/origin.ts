/**
 * Whether the staging origin stopped or restarted inside a soak run, read from
 * the Alloy metrics in Grafana Cloud. Grafana Cloud is outside the VPS, so it
 * also answers while the VPS is off. The staging deploy holds the same
 * concurrency group as the soak, so an API restart inside the run is an origin
 * event, not a deploy.
 */

import type { Env } from '../../tools/loginSecretExport';
import { grafanaAccess, query, type GrafanaAccess } from './counters';

/** Alloy scrapes every 30 seconds; no `up` sample for longer than this is a gap. */
export const SILENT_AFTER_S = 180;

const QUERY_TIMEOUT_MS = 15_000;

export const STARTED_ENV = 'SOAK_STARTED';
export const GITHUB_TOKEN_ENV = 'SOAK_GITHUB_TOKEN';

/** The soak legs, also under the `<caller> / ` prefix of a called workflow. */
const LEG_JOB = /(^|\/ )Soak: (Web Vault|Web Shares|Desktop \((macos|linux|windows)\))( \/|$)/;

export interface RunWindow {
  readonly startS: number;
  readonly endS: number;
  /** `guard` when the job times could not be read. */
  readonly source: 'jobs' | 'guard';
}

export interface OriginReadings {
  /** The newest `up{job="api"}` sample of any value in the window, or `null` for none. */
  readonly anySampleS: number | null;
  /** The newest `up{job="api"} == 1` sample in the window, or `null` for none. */
  readonly lastUpS: number | null;
  /** The newest API process start in the window, or `null` for none. */
  readonly latestStartS: number | null;
  /** A gap of more than `SILENT_AFTER_S` with no `up` sample before the restart. */
  readonly gapBeforeStart: boolean;
}

export interface Job {
  readonly name: string;
  readonly conclusion: string | null;
  readonly started_at: string | null;
  readonly completed_at: string | null;
}

const INFRA = 'Treat this failure as infra and run it again.';
const READ_LOGS = 'read the API logs before a re-run.';

function utc(seconds: number): string {
  return `${new Date(seconds * 1000).toISOString().slice(0, 19)}Z`;
}

/** The line the soak issue carries about the origin in the run window. */
export function originLine(readings: OriginReadings, window: RunWindow): string {
  const note = window.source === 'guard' ? '; window from the guard; job times not read' : '';
  const span = `${utc(window.startS)} to ${utc(window.endS)}${note}`;
  const { anySampleS, lastUpS, latestStartS, gapBeforeStart } = readings;
  if (anySampleS === null) {
    return `Origin boot history: not read (no api series in the run window, ${span})`;
  }
  if (lastUpS === null) {
    return `Origin: the staging API was never up in the run window (${span}); ${READ_LOGS}`;
  }
  if (window.endS - anySampleS > SILENT_AFTER_S) {
    return `Origin stop: the staging origin sent no metric after ${utc(anySampleS)}, inside the run window (${span}). ${INFRA}`;
  }
  if (window.endS - lastUpS > SILENT_AFTER_S) {
    return `Origin: the staging API was down after ${utc(lastUpS)} while the VPS sent metrics, inside the run window (${span}); ${READ_LOGS}`;
  }
  if (latestStartS !== null && latestStartS >= window.startS) {
    return gapBeforeStart
      ? `Origin restart: the staging API process started at ${utc(latestStartS)} after a metric gap, inside the run window (${span}). ${INFRA}`
      : `Origin: the API process started at ${utc(latestStartS)} inside the run window (${span}), with no metric gap; ${READ_LOGS}`;
  }
  return `Origin boot history: no API restart and no metric gap at the end of the run window (${span}).`;
}

/** At most one value: the queries aggregate, and an empty vector is `null`. */
function single(values: readonly number[]): number | null {
  if (values.length > 1) throw new Error(`the query answered ${values.length} series`);
  return values[0] ?? null;
}

function range(fromS: number, toS: number): string {
  return `${Math.max(Math.ceil(toS - fromS), 60)}s`;
}

export async function readOrigin(
  access: GrafanaAccess,
  window: RunWindow
): Promise<OriginReadings> {
  const r = range(window.startS, window.endS);
  const at = (promql: string, timeS: number): Promise<number | null> =>
    query(access, promql, QUERY_TIMEOUT_MS, timeS).then(single);
  // `timestamp()` gives the sample time only for a bare selector, so `== 1` goes through `and`.
  const [anySampleS, lastUpS, latestStartS] = await Promise.all([
    at(`max(max_over_time(timestamp(up{job="api"})[${r}:30s]))`, window.endS),
    at(
      `max(max_over_time((timestamp(up{job="api"}) and up{job="api"} == 1)[${r}:30s]))`,
      window.endS
    ),
    at(`max(max_over_time(process_start_time_seconds{job="api"}[${r}]))`, window.endS),
  ]);
  let gapBeforeStart = false;
  if (latestStartS !== null && latestStartS >= window.startS) {
    // The fewest `up` samples in any SILENT_AFTER_S span from the run start to the restart.
    const fewest = await at(
      `min_over_time((sum(count_over_time(up{job="api"}[${SILENT_AFTER_S}s])) or vector(0))[${range(window.startS, latestStartS)}:30s])`,
      latestStartS
    );
    gapBeforeStart = fewest === 0;
  }
  return { anySampleS, lastUpS, latestStartS, gapBeforeStart };
}

/** The span of the soak legs that ran: the earliest start to the latest end. */
export function legWindow(jobs: readonly Job[]): { startS: number; endS: number } {
  const legs = jobs.filter(
    (job) =>
      LEG_JOB.test(job.name) &&
      job.conclusion !== 'skipped' &&
      job.started_at !== null &&
      job.completed_at !== null
  );
  if (legs.length === 0) throw new Error('no soak leg ran');
  const seconds = (iso: string | null): number => Date.parse(iso!) / 1000;
  const startS = Math.min(...legs.map((job) => seconds(job.started_at)));
  const endS = Math.max(...legs.map((job) => seconds(job.completed_at)));
  if (!Number.isFinite(startS) || !Number.isFinite(endS) || endS <= startS) {
    throw new Error('the leg job times are not valid');
  }
  return { startS, endS };
}

/**
 * The newest attempt of each job of this run. A job that a re-run of failed
 * jobs did not run again keeps the times of the attempt that ran it.
 */
async function readJobs(env: Env): Promise<Job[]> {
  const token = env[GITHUB_TOKEN_ENV]?.trim();
  const api = env.GITHUB_API_URL ?? 'https://api.github.com';
  if (!token || !env.GITHUB_REPOSITORY || !env.GITHUB_RUN_ID) throw new Error('no run');
  const jobs: Job[] = [];
  for (let page = 1; ; page += 1) {
    const url = `${api}/repos/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}/jobs?filter=latest&per_page=100&page=${page}`;
    const response = await fetch(url, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json' },
      signal: AbortSignal.timeout(QUERY_TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = (await response.json()) as { total_count: number; jobs: Job[] };
    jobs.push(...body.jobs);
    if (body.jobs.length === 0 || jobs.length >= body.total_count) return jobs;
  }
}

/** The leg span from the job times, or the guard start to `nowS` when they cannot be read. */
export async function runWindow(env: Env, nowS: number): Promise<RunWindow> {
  try {
    return { ...legWindow(await readJobs(env)), source: 'jobs' };
  } catch {
    const startS = Number(env[STARTED_ENV]?.trim() || Number.NaN);
    if (!Number.isInteger(startS) || startS <= 0 || startS > nowS) {
      throw new Error('the run start time is not set');
    }
    return { startS, endS: nowS, source: 'guard' };
  }
}

/**
 * The origin line of the run. It never throws: a source that cannot be read
 * gives a "not read" line, so the check never fails the report.
 */
export async function originReport(env: Env, nowS: number): Promise<string> {
  try {
    const window = await runWindow(env, nowS);
    return originLine(await readOrigin(grafanaAccess(env), window), window);
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'an unknown error';
    return `Origin boot history: not read (${reason})`;
  }
}
