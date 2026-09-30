import { describe, expect, it } from 'vitest';
import {
  emptyLedger,
  formatLedger,
  parseLedger,
  type Ledger,
} from '../../../web-e2e/staging/soak/ledger';
import { SoakFailure } from '../../../web-e2e/staging/soak/reasons';
import { CI_PROFILE, PRODUCTION_PROFILE } from '../profile';
import {
  LOGIN_SECRET_ENV,
  ledgerLine,
  ledgerPath,
  legDeadlines,
  legMarkers,
  legOf,
  loginSecret,
  markerDate,
  markerPath,
  markersToRead,
  readBudget,
  readLine,
  recordMarker,
  remoteStack,
  soakBudgets,
} from './plan';

/** A made-up secret: 32 bytes of `0xab`, which no account signs in with. */
const SECRET = 'ab'.repeat(32);

function ledgerOf(...lines: string[]): Ledger {
  return parseLedger(['cipherbox-soak-ledger 1', ...lines].join('\n') + '\n');
}

describe('the leg of a platform', () => {
  it('names the three desktop platforms and refuses any other', () => {
    expect(legOf('darwin')).toBe('macos');
    expect(legOf('linux')).toBe('linux');
    expect(legOf('win32')).toBe('windows');
    expect(() => legOf('freebsd')).toThrow('no desktop soak leg runs on freebsd');
  });
});

describe('the marker paths', () => {
  it('put a marker in the folder of its leg, under the grantee ledger folder', () => {
    expect(markerPath({ leg: 'linux', date: '2026-09-30' })).toEqual([
      'soak',
      'desktop',
      'linux',
      'marker-2026-09-30.txt',
    ]);
    expect(ledgerPath()).toEqual(['soak', 'desktop', 'ledger.txt']);
  });

  it('read a marker day back from its file name only', () => {
    expect(markerDate('marker-2026-09-30.txt')).toBe('2026-09-30');
    expect(markerDate('marker-2026-02-30.txt')).toBeNull();
    expect(markerDate('marker-2026-09-30.txt.tmp')).toBeNull();
    expect(markerDate('ledger.txt')).toBeNull();
  });
});

describe('the grantee ledger lines', () => {
  it('survive a write and a read through the web ledger format', () => {
    const written = recordMarker(emptyLedger(), { leg: 'windows', date: '2026-09-30' });
    const text = formatLedger(written);
    expect(text).toBe('cipherbox-soak-ledger 1\nmarker windows 2026-09-30\n');
    expect(legMarkers(parseLedger(text))).toEqual([{ leg: 'windows', date: '2026-09-30' }]);
  });

  it('add the line of a day once, so a rerun leaves the ledger as it is', () => {
    const once = recordMarker(emptyLedger(), { leg: 'macos', date: '2026-09-30' });
    expect(recordMarker(once, { leg: 'macos', date: '2026-09-30' })).toBe(once);
    expect(recordMarker(once, { leg: 'linux', date: '2026-09-30' }).lines).toHaveLength(2);
  });

  it('carry every line of another shape through a rewrite', () => {
    const ledger = ledgerOf('2026-09-29 k51abc 3', 'binned 2026-06-01 2026-09-01');
    const next = recordMarker(ledger, { leg: 'macos', date: '2026-09-30' });
    expect(formatLedger(next)).toBe(
      'cipherbox-soak-ledger 1\n2026-09-29 k51abc 3\nbinned 2026-06-01 2026-09-01\n' +
        'marker macos 2026-09-30\n'
    );
  });

  it('refuse a marker line of a leg or a day this soak does not know', () => {
    for (const line of ['marker android 2026-09-30', 'marker macos 2026-13-01', 'marker macos']) {
      expect(() => legMarkers(ledgerOf(line))).toThrow(
        expect.objectContaining({ name: 'SoakFailure', reason: 'ledger-unparsable' })
      );
    }
    expect(() => ledgerLine({ leg: 'macos', date: '2026-9-30' })).toThrow(SoakFailure);
  });
});

describe('the markers a leg reads', () => {
  it('take the other legs from the ledger and the listings both, and skip its own', () => {
    const ledger = ledgerOf(
      'marker linux 2026-09-28',
      'marker macos 2026-09-28',
      'marker windows 2026-09-29'
    );
    const read = markersToRead(
      ledger,
      {
        linux: ['marker-2026-09-28.txt', 'marker-2026-09-29.txt', 'notes.txt'],
        macos: ['marker-2026-09-29.txt'],
        web: ['marker-2026-09-29.txt'],
      },
      'macos'
    );
    expect(read).toEqual([
      { leg: 'linux', date: '2026-09-28' },
      { leg: 'linux', date: '2026-09-29' },
      { leg: 'windows', date: '2026-09-29' },
      { leg: 'web', date: '2026-09-29' },
    ]);
    expect(readLine(read)).toBe('linux 2, windows 1, web 1');
  });

  it('is none on the first night', () => {
    expect(markersToRead(emptyLedger(), {}, 'linux')).toEqual([]);
    expect(readLine([])).toBe('no marker of another leg yet');
  });
});

describe('the step budgets', () => {
  it('derive from the poll cadence, so the production cadence gets production budgets', () => {
    const production = soakBudgets(PRODUCTION_PROFILE);
    const ci = soakBudgets(CI_PROFILE);
    const ratio = PRODUCTION_PROFILE.pollCadenceMs / CI_PROFILE.pollCadenceMs;
    expect(production.signInMs).toBe(ci.signInMs * ratio);
    expect(production.publishMs).toBe(ci.publishMs * ratio);
    expect(soakBudgets()).toEqual(production);
  });

  it('give every step many poll ticks, so one slow tick fails no step', () => {
    const budgets = soakBudgets(PRODUCTION_PROFILE);
    const tick = PRODUCTION_PROFILE.pollCadenceMs;
    for (const value of [
      budgets.signInMs,
      budgets.ledgerMs,
      budgets.readBaseMs,
      budgets.writeMs,
      budgets.publishMs,
    ]) {
      expect(value).toBeGreaterThanOrEqual(10 * tick);
    }
  });

  it('grow the read budget with the markers to read', () => {
    const budgets = soakBudgets(PRODUCTION_PROFILE);
    expect(readBudget(budgets, 0)).toBe(budgets.readBaseMs);
    expect(readBudget(budgets, 100)).toBe(budgets.readBaseMs + 100 * budgets.readPerMarkerMs);
  });

  it('fit each start wait of an instance inside the sign-in budget', () => {
    const budgets = soakBudgets(PRODUCTION_PROFILE);
    const waits = legDeadlines(budgets, PRODUCTION_PROFILE);
    expect(waits.apiReadyMs).toBe(budgets.signInMs);
    expect(waits.controlFileMs).toBe(budgets.signInMs);
    expect(waits.mountMs).toBe(budgets.signInMs);
    expect(waits.readIntervalMs).toBe(PRODUCTION_PROFILE.pollCadenceMs);
  });
});

describe('the login secret', () => {
  it('reads 32 bytes of hex as the 64 lowercase characters the host takes', () => {
    expect(loginSecret({ [LOGIN_SECRET_ENV]: SECRET })).toBe(SECRET);
    expect(loginSecret({ [LOGIN_SECRET_ENV]: ` 0x${SECRET.toUpperCase()}\n` })).toBe(SECRET);
  });

  it('refuses an absent or malformed secret, and never repeats the value', () => {
    expect(() => loginSecret({})).toThrow(`${LOGIN_SECRET_ENV} is not set`);
    expect(() => loginSecret({ [LOGIN_SECRET_ENV]: '  ' })).toThrow('is not set');
    const short = SECRET.slice(2);
    let message = '';
    try {
      loginSecret({ [LOGIN_SECRET_ENV]: short });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toBe(`${LOGIN_SECRET_ENV} is not 32 bytes of hex`);
    expect(message.includes(short)).toBe(false);
  });
});

describe('the remote stack', () => {
  const env = {
    VITE_API_URL: 'https://api.example.test',
    VITE_ROUTING_ENDPOINTS: 'https://routing-a.example.test, https://routing-b.example.test,',
  };

  it('reads the API and the routing endpoints the host was built with', () => {
    expect(remoteStack(env)).toEqual({
      apiUrl: 'https://api.example.test',
      routingEndpoints: ['https://routing-a.example.test', 'https://routing-b.example.test'],
    });
  });

  it('takes plain http on a loopback host only', () => {
    expect(
      remoteStack({
        VITE_API_URL: 'http://localhost:3000',
        VITE_ROUTING_ENDPOINTS: 'http://127.0.0.1:3001',
      }).apiUrl
    ).toBe('http://localhost:3000');
    expect(() => remoteStack({ ...env, VITE_API_URL: 'http://api.example.test' })).toThrow(
      'VITE_API_URL must be an https URL'
    );
  });

  it('refuses a missing API or an empty routing list', () => {
    expect(() => remoteStack({ ...env, VITE_API_URL: undefined })).toThrow(
      'VITE_API_URL is not set'
    );
    expect(() => remoteStack({ ...env, VITE_ROUTING_ENDPOINTS: ' , ' })).toThrow(
      'VITE_ROUTING_ENDPOINTS must list at least one routing endpoint'
    );
    expect(() => remoteStack({ ...env, VITE_ROUTING_ENDPOINTS: 'not a url' })).toThrow(
      'VITE_ROUTING_ENDPOINTS holds a value that is not a URL'
    );
  });
});
