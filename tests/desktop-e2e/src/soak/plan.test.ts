import { describe, expect, it } from 'vitest';
import { CI_PROFILE, PRODUCTION_PROFILE } from '../profile';
import {
  LOGIN_SECRET_ENV,
  legDeadlines,
  legOf,
  loginSecret,
  readBudget,
  remoteStack,
  soakBudgets,
  withoutSoakVars,
} from './plan';

/** A made-up secret: 32 bytes of `0xab`, which no account signs in with. */
const SECRET = 'ab'.repeat(32);

describe('the leg of a platform', () => {
  it('names the three desktop platforms and refuses any other', () => {
    expect(legOf('darwin')).toBe('macos');
    expect(legOf('linux')).toBe('linux');
    expect(legOf('win32')).toBe('windows');
    expect(() => legOf('freebsd')).toThrow('no desktop soak leg runs on freebsd');
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

  it('fit every wait of a sign-in, one after the other, inside the sign-in budget', () => {
    const budgets = soakBudgets(PRODUCTION_PROFILE);
    const waits = legDeadlines(budgets, PRODUCTION_PROFILE);
    const signIn = waits.apiReadyMs + 2 * waits.controlFileMs + 2 * waits.mountMs + waits.refreshMs;
    expect(signIn).toBeLessThanOrEqual(budgets.signInMs);
    expect(waits.readIntervalMs).toBe(PRODUCTION_PROFILE.pollCadenceMs);
  });

  it('fit the waits of the marker write, a status and a refresh, inside its budget', () => {
    const budgets = soakBudgets(PRODUCTION_PROFILE);
    const waits = legDeadlines(budgets, PRODUCTION_PROFILE);
    // Both control calls are bounded by `refreshMs`; the rest of the budget is the file work.
    expect(2 * waits.refreshMs).toBeLessThan(budgets.writeMs);
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

describe('the environment a host inherits', () => {
  it('drops every soak variable and keeps the rest', () => {
    expect(
      withoutSoakVars({
        [LOGIN_SECRET_ENV]: SECRET,
        SOAK_OWNER_WALLET_KEY: SECRET,
        VITE_API_URL: 'https://api.example.test',
        PATH: '/usr/bin',
      })
    ).toEqual({ VITE_API_URL: 'https://api.example.test', PATH: '/usr/bin' });
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
