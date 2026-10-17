/**
 * Whether the staging origin stopped or restarted inside a soak run, read from
 * the Alloy metrics in Grafana Cloud. Grafana Cloud is outside the VPS, so it
 * also answers while the VPS is off. The staging deploy holds the same
 * concurrency group as the soak, so an API restart inside the run is an origin
 * event, not a deploy.
 */

import type { Env } from '../../tools/loginSecretExport';
import { grafanaAccess, query, type GrafanaAccess } from './counters';

/** Alloy scrapes every 30 seconds; a last sample older than this is a stopped origin. */
export const SILENT_AFTER_S = 180;

const QUERY_TIMEOUT_MS = 15_000;

export interface RunWindow {
  readonly startS: number;
  readonly endS: number;
}

export interface OriginReadings {
  /** The time of the newest `up{job="api"}` sample in the window, or `null` for none. */
  readonly lastSampleS: number | null;
  /** The newest API process start in the window, or `null` for none. */
  readonly latestStartS: number | null;
}

const INFRA = 'Treat this failure as infra and run it again.';

function utc(seconds: number): string {
  return `${new Date(seconds * 1000).toISOString().slice(0, 19)}Z`;
}

/** The line the soak issue carries about the origin in the run window. */
export function originLine(readings: OriginReadings, window: RunWindow): string {
  const span = `${utc(window.startS)} to ${utc(window.endS)}`;
  const { lastSampleS, latestStartS } = readings;
  if (lastSampleS === null) {
    return `Origin stop: Grafana Cloud holds no staging API metric in the run window (${span}). ${INFRA}`;
  }
  if (window.endS - lastSampleS > SILENT_AFTER_S) {
    return `Origin stop: the staging origin sent no metric after ${utc(lastSampleS)}, inside the run window (${span}). ${INFRA}`;
  }
  if (latestStartS !== null && latestStartS >= window.startS) {
    return `Origin restart: the staging API process started at ${utc(latestStartS)}, inside the run window (${span}). ${INFRA}`;
  }
  return `Origin boot history: no API restart and no metric gap at the end of the run window (${span}).`;
}

/** At most one value: the queries aggregate with `max`, and an empty vector is `null`. */
function single(values: readonly number[]): number | null {
  if (values.length > 1) throw new Error(`the query answered ${values.length} series`);
  return values[0] ?? null;
}

export async function readOrigin(
  access: GrafanaAccess,
  window: RunWindow
): Promise<OriginReadings> {
  const range = `${Math.max(Math.ceil(window.endS - window.startS), 60)}s`;
  const [lastSample, latestStart] = await Promise.all([
    query(access, `max(max_over_time(timestamp(up{job="api"})[${range}:30s]))`, QUERY_TIMEOUT_MS),
    query(
      access,
      `max(max_over_time(process_start_time_seconds{job="api"}[${range}]))`,
      QUERY_TIMEOUT_MS
    ),
  ]);
  return { lastSampleS: single(lastSample), latestStartS: single(latestStart) };
}

/**
 * The origin line for a run that started at `startedRaw` (Unix seconds) and
 * ends now. It never throws: a source that cannot be read gives a "not read"
 * line, so the check never fails the report.
 */
export async function originReport(
  env: Env,
  startedRaw: string | undefined,
  nowS: number,
  read: typeof readOrigin = readOrigin
): Promise<string> {
  try {
    const startS = Number(startedRaw?.trim() || Number.NaN);
    if (!Number.isInteger(startS) || startS <= 0 || startS > nowS) {
      throw new Error('the run start time is not set');
    }
    const window = { startS, endS: nowS };
    return originLine(await read(grafanaAccess(env), window), window);
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'an unknown error';
    return `Origin boot history: not read (${reason})`;
  }
}
