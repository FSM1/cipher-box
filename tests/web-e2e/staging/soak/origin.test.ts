import { afterEach, describe, expect, it, vi } from 'vitest';
import { GRAFANA_TOKEN_ENV, GRAFANA_URL_ENV, GRAFANA_USER_ENV } from './counters';
import {
  GITHUB_TOKEN_ENV,
  legWindow,
  originLine,
  originReport,
  readOrigin,
  runWindow,
  SILENT_AFTER_S,
  STARTED_ENV,
  type Job,
  type OriginReadings,
  type RunWindow,
} from './origin';

const TOKEN = 'glc_not-a-real-token';
const GRAFANA = {
  [GRAFANA_URL_ENV]: 'https://metrics.example.test/api/prom/push',
  [GRAFANA_USER_ENV]: '123456',
  [GRAFANA_TOKEN_ENV]: TOKEN,
};
const RUN = {
  [GITHUB_TOKEN_ENV]: 'ghs_not-a-real-token',
  GITHUB_API_URL: 'https://api.example.test',
  GITHUB_REPOSITORY: 'owner/repo',
  GITHUB_RUN_ID: '39022710259',
};

const at = (iso: string): number => Date.parse(iso) / 1000;

// The soak run of 2026-10-17: the VPS stopped at 10:20:45Z and booted at 10:53:16Z.
const OUTAGE_RUN: RunWindow = {
  startS: at('2026-10-17T09:53:02Z'),
  endS: at('2026-10-17T10:33:25Z'),
  source: 'jobs',
};

const UP: OriginReadings = {
  anySampleS: OUTAGE_RUN.endS - 20,
  lastUpS: OUTAGE_RUN.endS - 20,
  latestStartS: at('2026-10-16T12:00:00Z'),
  gapBeforeStart: false,
};

function job(name: string, start: string, end: string, conclusion = 'success'): Job {
  return { name, conclusion, started_at: start, completed_at: end };
}

// The leg jobs of nightly run 39022710259, attempt 2, as `filter=latest` answers:
// the web legs keep their attempt 1 times, the desktop legs ran again.
const NIGHT_JOBS: Job[] = [
  job('Resolve The Staging Tag', '2026-10-17T09:51:35Z', '2026-10-17T09:52:38Z'),
  job('Staging Soak / Soak: Check The Inputs', '2026-10-17T09:52:41Z', '2026-10-17T09:52:58Z'),
  job('Staging Soak / Soak: Web Vault', '2026-10-17T09:53:02Z', '2026-10-17T10:02:36Z'),
  job('Staging Soak / Soak: Web Shares', '2026-10-17T10:02:39Z', '2026-10-17T10:17:30Z'),
  job(
    'Staging Soak / Soak: Desktop (macos) / Desktop Leg',
    '2026-10-17T15:54:47Z',
    '2026-10-17T16:04:41Z'
  ),
  job(
    'Staging Soak / Soak: Desktop (linux) / Desktop Leg',
    '2026-10-17T16:04:46Z',
    '2026-10-17T16:12:10Z'
  ),
  job(
    'Staging Soak / Soak: Desktop (windows) / Desktop Leg',
    '2026-10-17T16:12:14Z',
    '2026-10-17T16:22:01Z'
  ),
  job('Staging Soak / Soak: Report', '2026-10-17T16:22:03Z', '2026-10-17T16:22:25Z'),
  job(
    'Full-Matrix Flake Surveillance / Desktop E2E / Mount Cadence (macos)',
    '2026-10-17T15:54:43Z',
    '2026-10-17T09:51:37Z',
    'skipped'
  ),
];

// The same legs in attempt 1, when the VPS stopped under the desktop legs.
const OUTAGE_JOBS: Job[] = [
  job('Staging Soak / Soak: Web Vault', '2026-10-17T09:53:02Z', '2026-10-17T10:02:36Z'),
  job('Staging Soak / Soak: Web Shares', '2026-10-17T10:02:39Z', '2026-10-17T10:17:30Z'),
  job(
    'Staging Soak / Soak: Desktop (macos) / Desktop Leg',
    '2026-10-17T10:17:38Z',
    '2026-10-17T10:24:19Z',
    'failure'
  ),
  job(
    'Staging Soak / Soak: Desktop (linux) / Desktop Leg',
    '2026-10-17T10:24:22Z',
    '2026-10-17T10:28:17Z',
    'failure'
  ),
  job(
    'Staging Soak / Soak: Desktop (windows) / Desktop Leg',
    '2026-10-17T10:28:20Z',
    '2026-10-17T10:33:25Z',
    'failure'
  ),
];

/** `NIGHT_JOBS` with the conclusion of each named leg changed. */
function withConclusions(conclusions: Record<string, string>): Job[] {
  return NIGHT_JOBS.map((j) => {
    const os = /Desktop \((\w+)\)/.exec(j.name)?.[1];
    return os && conclusions[os] ? { ...j, conclusion: conclusions[os] } : j;
  });
}

function vector(...values: number[]): unknown {
  return {
    status: 'success',
    data: { resultType: 'vector', result: values.map((v) => ({ metric: {}, value: [0, `${v}`] })) },
  };
}

function jobsAnswer(jobs: readonly Job[]): unknown {
  return { total_count: jobs.length, jobs };
}

/** A fetch that answers the jobs API with `jobs` and each PromQL query by its text. */
function stubFetch(jobs: readonly Job[] | null, promql: (query: string) => number[]) {
  const fetched = vi.fn(async (url: string) => {
    if (url.startsWith(RUN.GITHUB_API_URL)) {
      return jobs === null ? new Response('no', { status: 403 }) : Response.json(jobsAnswer(jobs));
    }
    const params = new URL(url).searchParams;
    return Response.json(vector(...promql(params.get('query') ?? '')));
  });
  vi.stubGlobal('fetch', fetched);
  return fetched;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the run window', () => {
  it('spans every leg that ran when all legs passed', () => {
    expect(legWindow(NIGHT_JOBS)).toEqual({
      startS: at('2026-10-17T09:53:02Z'),
      endS: at('2026-10-17T16:22:01Z'),
    });
  });

  it('spans only the legs that did not pass, not the time between two attempts', () => {
    expect(legWindow(withConclusions({ windows: 'failure' }))).toEqual({
      startS: at('2026-10-17T16:12:14Z'),
      endS: at('2026-10-17T16:22:01Z'),
    });
    expect(legWindow(withConclusions({ macos: 'cancelled', linux: 'timed_out' }))).toEqual({
      startS: at('2026-10-17T15:54:47Z'),
      endS: at('2026-10-17T16:12:10Z'),
    });
    expect(legWindow(OUTAGE_JOBS)).toEqual({
      startS: at('2026-10-17T10:17:38Z'),
      endS: at('2026-10-17T10:33:25Z'),
    });
  });

  it('gives the same window on a retry of the report job alone', async () => {
    const retried = [
      ...NIGHT_JOBS,
      job('Staging Soak / Soak: Report', '2026-10-18T08:00:00Z', '2026-10-18T08:00:30Z'),
    ];
    stubFetch(NIGHT_JOBS, () => []);
    const first = await runWindow({ ...RUN, [STARTED_ENV]: '1' }, at('2026-10-17T16:22:10Z'));
    stubFetch(retried, () => []);
    const second = await runWindow({ ...RUN, [STARTED_ENV]: '1' }, at('2026-10-18T08:00:10Z'));
    expect(second).toEqual(first);
    expect(first.source).toBe('jobs');
  });

  it('falls back to the guard start and the report time when the jobs are not read', async () => {
    stubFetch(null, () => []);
    const nowS = at('2026-10-17T16:22:10Z');
    const window = await runWindow({ ...RUN, [STARTED_ENV]: String(OUTAGE_RUN.startS) }, nowS);
    expect(window).toEqual({ startS: OUTAGE_RUN.startS, endS: nowS, source: 'guard' });
    expect(originLine(UP, window)).toContain('window from the guard; job times not read');
  });
});

describe('the origin line', () => {
  it('names a stop when the origin sent no metric at the end of the run', () => {
    const last = at('2026-10-17T10:20:30Z');
    const line = originLine({ ...UP, anySampleS: last, lastUpS: last }, OUTAGE_RUN);
    expect(line).toBe(
      'Origin stop: the staging origin sent no metric after 2026-10-17T10:20:30Z, inside the run ' +
        'window (2026-10-17T09:53:02Z to 2026-10-17T10:33:25Z). Treat this failure as infra and run it again.'
    );
  });

  it('names a restart after a metric gap as infra', () => {
    const line = originLine(
      { ...UP, latestStartS: at('2026-10-17T10:25:40Z'), gapBeforeStart: true },
      OUTAGE_RUN
    );
    expect(line).toMatch(
      /^Origin restart: the staging API process started at 2026-10-17T10:25:40Z after a metric gap/
    );
    expect(line).toContain('Treat this failure as infra and run it again.');
  });

  it('names a restart with no metric gap neutrally, not as infra', () => {
    const line = originLine({ ...UP, latestStartS: at('2026-10-17T10:25:40Z') }, OUTAGE_RUN);
    expect(line).toMatch(/^Origin: the API process started at 2026-10-17T10:25:40Z inside the run/);
    expect(line).toContain('with no metric gap; read the API logs before a re-run.');
    expect(line).not.toContain('infra');
  });

  it('does not count an `up` of 0 as a live API', () => {
    const line = originLine({ ...UP, lastUpS: at('2026-10-17T10:00:00Z') }, OUTAGE_RUN);
    expect(line).toMatch(/^Origin: the staging API was down after 2026-10-17T10:00:00Z/);
    expect(line).not.toContain('no API restart');
    expect(originLine({ ...UP, lastUpS: null }, OUTAGE_RUN)).toMatch(
      /^Origin: the staging API was never up/
    );
  });

  it('says not read for an empty answer, not a stop', () => {
    const line = originLine(
      { anySampleS: null, lastUpS: null, latestStartS: null, gapBeforeStart: false },
      OUTAGE_RUN
    );
    expect(line).toMatch(/^Origin boot history: not read \(no api series in the run window/);
  });

  it('names no infra event for a quiet origin', () => {
    const quiet = OUTAGE_RUN.endS - SILENT_AFTER_S;
    const line = originLine(
      { ...UP, anySampleS: quiet, lastUpS: quiet, latestStartS: OUTAGE_RUN.startS - 1 },
      OUTAGE_RUN
    );
    expect(line).toMatch(/^Origin boot history: no API restart and no metric gap/);
    expect(line).not.toContain('infra');
  });
});

describe('the origin report', () => {
  it('reads the queries at the window end, and the gap at the restart', async () => {
    const restart = at('2026-10-17T10:25:40Z');
    const fetched = stubFetch(null, (q) => {
      if (q.includes('process_start_time_seconds')) return [restart];
      if (q.includes('count_over_time')) return [0];
      if (q.includes('== 1')) return [OUTAGE_RUN.endS - 50];
      return [OUTAGE_RUN.endS - 20];
    });
    const readings = await readOrigin(
      { base: 'https://metrics.example.test/api/prom', authorization: 'Basic x' },
      OUTAGE_RUN
    );
    expect(readings).toEqual({
      anySampleS: OUTAGE_RUN.endS - 20,
      lastUpS: OUTAGE_RUN.endS - 50,
      latestStartS: restart,
      gapBeforeStart: true,
    });
    const calls = fetched.mock.calls.map(([url]) => new URL(url).searchParams);
    const timeOf = (part: string): string | null =>
      calls.find((p) => p.get('query')!.includes(part))!.get('time');
    expect(timeOf('up{job="api"} == 1')).toBe(String(OUTAGE_RUN.endS));
    expect(timeOf('count_over_time(up{job="api"}[180s])')).toBe(String(restart));
  });

  it('gives the stop line for the outage run, over the leg job window', async () => {
    const last = at('2026-10-17T10:20:30Z');
    stubFetch(OUTAGE_JOBS, (q) =>
      q.includes('process_start_time_seconds') ? [at('2026-10-16T12:00:00Z')] : [last]
    );
    const line = await originReport({ ...GRAFANA, ...RUN }, at('2026-10-17T10:40:00Z'));
    expect(line).toBe(
      'Origin stop: the staging origin sent no metric after 2026-10-17T10:20:30Z, inside the run ' +
        'window (2026-10-17T10:17:38Z to 2026-10-17T10:33:25Z). Treat this failure as infra and run it again.'
    );
  });

  it('says not read, and never throws, when a source is missing or refuses', async () => {
    stubFetch(null, () => []);
    expect(await originReport(GRAFANA, OUTAGE_RUN.endS)).toBe(
      'Origin boot history: not read (the run start time is not set)'
    );
    expect(await originReport({ ...RUN, [STARTED_ENV]: '1' }, OUTAGE_RUN.endS)).toMatch(
      /^Origin boot history: not read \(.*GRAFANA_PROMETHEUS_URL is not set\)$/
    );
    vi.stubGlobal('fetch', async () => new Response(`bad token ${TOKEN}`, { status: 401 }));
    const refused = await originReport({ ...GRAFANA, [STARTED_ENV]: '1' }, OUTAGE_RUN.endS);
    expect(refused).toMatch(/^Origin boot history: not read \(.*HTTP 401\)$/);
    expect(refused).not.toContain(TOKEN);
  });
});
