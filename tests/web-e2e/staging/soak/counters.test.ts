import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  COUNTER_CHECKS,
  countersLine,
  grafanaAccess,
  GRAFANA_TOKEN_ENV,
  GRAFANA_URL_ENV,
  GRAFANA_USER_ENV,
  inPostDeployWindow,
  instantValues,
  oneSeries,
  query,
  staleBaseline,
  uptimeLine,
  uptimeSeconds,
  withStaleBaseline,
  type CounterReadings,
} from './counters';
import { emptyLedger, formatLedger, LEDGER_HEADER, parseLedger } from './ledger';
import { SoakFailure } from './reasons';

const TOKEN = 'glc_not-a-real-token';
const ENV = {
  [GRAFANA_URL_ENV]: 'https://metrics.example.test/api/prom/push',
  [GRAFANA_USER_ENV]: '123456',
  [GRAFANA_TOKEN_ENV]: TOKEN,
};

const HEALTHY: CounterReadings = {
  staleNames: 2,
  walksSkipped: 0,
  resolveFailures: 0,
  walks: 2,
  lastWalkNames: 40,
};

function failureOf(act: () => unknown): SoakFailure {
  try {
    act();
  } catch (error) {
    if (error instanceof SoakFailure) return error;
    throw error;
  }
  throw new Error('expected a SoakFailure');
}

describe('the Grafana access', () => {
  it('queries the push URL without its /push suffix, with basic authentication', () => {
    const access = grafanaAccess(ENV);
    expect(access.base).toBe('https://metrics.example.test/api/prom');
    expect(access.authorization).toBe(`Basic ${Buffer.from(`123456:${TOKEN}`).toString('base64')}`);
  });

  it.each([GRAFANA_URL_ENV, GRAFANA_USER_ENV, GRAFANA_TOKEN_ENV])(
    'fails as counters-unread when %s is not set, and names no value',
    (name) => {
      const failure = failureOf(() => grafanaAccess({ ...ENV, [name]: ' ' }));
      expect(failure.reason).toBe('counters-unread');
      expect(failure.message).toContain(name);
      expect(failure.message).not.toContain(TOKEN);
    }
  );

  it('refuses a URL that is not an https push URL', () => {
    const failure = failureOf(() =>
      grafanaAccess({ ...ENV, [GRAFANA_URL_ENV]: 'http://metrics.example.test/api/prom/push' })
    );
    expect(failure.reason).toBe('counters-unread');
    expect(failure.message).not.toContain('metrics.example.test');
  });
});

describe('an instant-query answer', () => {
  it('reads the value of each series', () => {
    const body = {
      status: 'success',
      data: {
        resultType: 'vector',
        result: [{ metric: {}, value: [1_790_000_000, '1.98'] }],
      },
    };
    expect(instantValues(body)).toEqual([1.98]);
  });

  it('reads an empty vector as no series', () => {
    expect(
      instantValues({ status: 'success', data: { resultType: 'vector', result: [] } })
    ).toEqual([]);
  });

  it.each([
    ['an error answer', { status: 'error' }],
    ['a matrix', { status: 'success', data: { resultType: 'matrix', result: [] } }],
    [
      'a sample that is no number',
      { status: 'success', data: { resultType: 'vector', result: [{ value: [1, 'NaN'] }] } },
    ],
  ])('refuses %s', (_label, body) => {
    expect(() => instantValues(body)).toThrow();
  });

  it('wants exactly one series of a counter', () => {
    expect(oneSeries('q', [3])).toBe(3);
    expect(failureOf(() => oneSeries('q', [])).reason).toBe('counters-unread');
    expect(failureOf(() => oneSeries('q', [1, 2])).reason).toBe('counters-unread');
  });
});

describe('a counter query', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('asks the query endpoint with the authorization header', async () => {
    const fetched = vi.fn(async () =>
      Response.json({ status: 'success', data: { resultType: 'vector', result: [] } })
    );
    vi.stubGlobal('fetch', fetched);
    const access = grafanaAccess(ENV);
    expect(await query(access, 'up{job="api"}', 1_000)).toEqual([]);
    const [url, init] = fetched.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(
      `https://metrics.example.test/api/prom/api/v1/query?query=${encodeURIComponent('up{job="api"}')}`
    );
    expect(init.headers).toEqual({ authorization: access.authorization });
  });

  it('fails a refused query as counters-unread, naming neither the URL nor the token', async () => {
    vi.stubGlobal('fetch', async () => new Response(`bad token ${TOKEN}`, { status: 401 }));
    const failure = await query(grafanaAccess(ENV), 'up', 1_000).then(
      () => null,
      (error: unknown) => error
    );
    expect(failure).toBeInstanceOf(SoakFailure);
    expect((failure as SoakFailure).reason).toBe('counters-unread');
    expect((failure as SoakFailure).message).toBe('[counters-unread] up: HTTP 401');
  });
});

describe('the post-deploy window', () => {
  it('takes the youngest API process', () => {
    expect(uptimeSeconds([50_000, 3_600])).toBe(3_600);
    expect(failureOf(() => uptimeSeconds([])).reason).toBe('counters-unread');
  });

  it('skips the counters up to 12 hours of uptime', () => {
    expect(inPostDeployWindow(3 * 3600)).toBe(true);
    expect(inPostDeployWindow(12 * 3600)).toBe(true);
    expect(inPostDeployWindow(12 * 3600 + 1)).toBe(false);
    expect(uptimeLine(3 * 3600)).toBe('the API is up 3.0 hours');
  });
});

describe('the counter checks', () => {
  const failed = (readings: CounterReadings, baseline = 2) =>
    COUNTER_CHECKS.filter((entry) => entry.verdict(readings, baseline) !== null).map(
      (entry) => entry.reason
    );

  it('pass a healthy night', () => {
    expect(failed(HEALTHY)).toEqual([]);
  });

  it('let two walks read a little below 2', () => {
    expect(failed({ ...HEALTHY, walks: 1.95 })).toEqual([]);
    expect(failed({ ...HEALTHY, walks: 1.5 })).toEqual(['no-walk-in-window']);
  });

  it('fail each counter that grew, with its own reason', () => {
    expect(failed({ ...HEALTHY, staleNames: 3.2 })).toEqual(['stale-names-grew']);
    expect(failed({ ...HEALTHY, staleNames: 2.3 })).toEqual([]);
    expect(failed({ ...HEALTHY, walksSkipped: 1 })).toEqual(['walks-skipped-grew']);
    expect(failed({ ...HEALTHY, resolveFailures: 0.8 })).toEqual(['resolve-failures-grew']);
    expect(failed({ ...HEALTHY, lastWalkNames: 0 })).toEqual(['last-walk-empty']);
  });

  it('name each value in the summary line', () => {
    expect(countersLine(HEALTHY)).toBe(
      'staleNames 2.00; walksSkipped 0.00; resolveFailures 0.00; walks 2.00; lastWalkNames 40.00'
    );
  });
});

describe('the stale-names baseline', () => {
  it('is absent until the first reading, then reads back rounded', () => {
    expect(staleBaseline(emptyLedger())).toBeNull();
    const ledger = withStaleBaseline(emptyLedger(), 2.4);
    expect(staleBaseline(parseLedger(formatLedger(ledger)))).toBe(2);
  });

  it('refuses a bad line as ledger-unparsable', () => {
    const ledger = parseLedger(`${LEDGER_HEADER}\nstale-names-baseline two\n`);
    expect(failureOf(() => staleBaseline(ledger)).reason).toBe('ledger-unparsable');
  });
});
