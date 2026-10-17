import { afterEach, describe, expect, it, vi } from 'vitest';
import { GRAFANA_TOKEN_ENV, GRAFANA_URL_ENV, GRAFANA_USER_ENV } from './counters';
import { originLine, originReport, readOrigin, SILENT_AFTER_S, type RunWindow } from './origin';

const TOKEN = 'glc_not-a-real-token';
const ENV = {
  [GRAFANA_URL_ENV]: 'https://metrics.example.test/api/prom/push',
  [GRAFANA_USER_ENV]: '123456',
  [GRAFANA_TOKEN_ENV]: TOKEN,
};

const at = (iso: string): number => Date.parse(iso) / 1000;

// The soak run of 2026-10-17: the VPS stopped at 10:20:45Z and booted at 10:53:16Z.
const OUTAGE_RUN: RunWindow = {
  startS: at('2026-10-17T06:05:00Z'),
  endS: at('2026-10-17T10:35:00Z'),
};

function vector(...values: number[]): unknown {
  return {
    status: 'success',
    data: { resultType: 'vector', result: values.map((v) => ({ metric: {}, value: [0, `${v}`] })) },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the origin line', () => {
  it('names a stop when the origin sent no metric at the end of the run', () => {
    const line = originLine(
      { lastSampleS: at('2026-10-17T10:20:30Z'), latestStartS: at('2026-10-16T12:00:00Z') },
      OUTAGE_RUN
    );
    expect(line).toBe(
      'Origin stop: the staging origin sent no metric after 2026-10-17T10:20:30Z, inside the run ' +
        'window (2026-10-17T06:05:00Z to 2026-10-17T10:35:00Z). Treat this failure as infra and run it again.'
    );
  });

  it('names a restart when the API process started inside the run', () => {
    const line = originLine(
      { lastSampleS: OUTAGE_RUN.endS - 20, latestStartS: at('2026-10-17T08:24:40Z') },
      OUTAGE_RUN
    );
    expect(line).toMatch(
      /^Origin restart: the staging API process started at 2026-10-17T08:24:40Z/
    );
    expect(line).toContain('Treat this failure as infra');
  });

  it('names a stop when the window holds no metric at all', () => {
    expect(originLine({ lastSampleS: null, latestStartS: null }, OUTAGE_RUN)).toMatch(
      /^Origin stop: Grafana Cloud holds no staging API metric in the run window/
    );
  });

  it('names no infra event for a quiet origin', () => {
    const line = originLine(
      { lastSampleS: OUTAGE_RUN.endS - SILENT_AFTER_S, latestStartS: OUTAGE_RUN.startS - 1 },
      OUTAGE_RUN
    );
    expect(line).toMatch(/^Origin boot history: no API restart and no metric gap/);
    expect(line).not.toContain('infra');
  });
});

describe('the origin report', () => {
  it('reads both queries over the run window', async () => {
    const fetched = vi.fn(async (url: string) =>
      Response.json(
        decodeURIComponent(url).includes('timestamp(up')
          ? vector(at('2026-10-17T10:20:30Z'))
          : vector()
      )
    );
    vi.stubGlobal('fetch', fetched);
    const readings = await readOrigin(
      { base: 'https://metrics.example.test/api/prom', authorization: 'Basic x' },
      OUTAGE_RUN
    );
    expect(readings).toEqual({ lastSampleS: at('2026-10-17T10:20:30Z'), latestStartS: null });
    const queries = fetched.mock.calls.map(([url]) => decodeURIComponent(url));
    expect(queries).toEqual(
      expect.arrayContaining([
        expect.stringContaining('max(max_over_time(timestamp(up{job="api"})[16200s:30s]))'),
        expect.stringContaining(
          'max(max_over_time(process_start_time_seconds{job="api"}[16200s]))'
        ),
      ])
    );
  });

  it('gives the stop line for the outage run', async () => {
    vi.stubGlobal('fetch', async (url: string) =>
      Response.json(
        decodeURIComponent(url).includes('timestamp(up')
          ? vector(at('2026-10-17T10:20:30Z'))
          : vector(at('2026-10-16T12:00:00Z'))
      )
    );
    const line = await originReport(ENV, String(OUTAGE_RUN.startS), OUTAGE_RUN.endS);
    expect(line).toMatch(
      /^Origin stop: the staging origin sent no metric after 2026-10-17T10:20:30Z/
    );
  });

  it('says not read, and never throws, when a source is missing or refuses', async () => {
    expect(await originReport(ENV, undefined, OUTAGE_RUN.endS)).toBe(
      'Origin boot history: not read (the run start time is not set)'
    );
    expect(await originReport({}, String(OUTAGE_RUN.startS), OUTAGE_RUN.endS)).toMatch(
      /^Origin boot history: not read \(.*GRAFANA_PROMETHEUS_URL is not set\)$/
    );
    vi.stubGlobal('fetch', async () => new Response(`bad token ${TOKEN}`, { status: 401 }));
    const refused = await originReport(ENV, String(OUTAGE_RUN.startS), OUTAGE_RUN.endS);
    expect(refused).toMatch(/^Origin boot history: not read \(.*HTTP 401\)$/);
    expect(refused).not.toContain(TOKEN);
  });
});
