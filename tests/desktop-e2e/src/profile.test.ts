import { describe, expect, it } from 'vitest';
import { CI_PROFILE, PRODUCTION_PROFILE, deadlines, type Deadlines } from './profile';

const NAMES = [
  'intervalMs',
  'apiReadyMs',
  'controlFileMs',
  'mountMs',
  'publishMs',
  'refreshMs',
  'offlineMs',
  'shutdownMs',
] as const satisfies readonly (keyof Deadlines)[];

describe('deadlines', () => {
  it('gives every wait a positive finite budget', () => {
    const ci = deadlines(CI_PROFILE);
    for (const name of NAMES) {
      expect(Number.isFinite(ci[name]), name).toBe(true);
      expect(ci[name], name).toBeGreaterThan(0);
    }
  });

  it('defaults to the CI profile, because only an e2e-hook build runs the suite', () => {
    expect(deadlines()).toEqual(deadlines(CI_PROFILE));
  });

  it('derives from the profile rather than from fixed numbers', () => {
    const ci = deadlines(CI_PROFILE);
    const production = deadlines(PRODUCTION_PROFILE);
    for (const name of NAMES) {
      if (name === 'intervalMs') continue;
      expect(production[name], name).toBeGreaterThan(ci[name]);
    }
  });

  it('clears the staleness threshold before it waits for the offline rung', () => {
    for (const profile of [CI_PROFILE, PRODUCTION_PROFILE]) {
      expect(deadlines(profile).offlineMs).toBeGreaterThan(profile.staleAfterMs);
    }
  });

  it('outlasts a published record before it calls a publish late', () => {
    for (const profile of [CI_PROFILE, PRODUCTION_PROFILE]) {
      expect(deadlines(profile).publishMs).toBeGreaterThan(profile.recordTtlMs);
    }
  });

  it('reads a signal more often than the engine ticks, so no read misses a state', () => {
    for (const profile of [CI_PROFILE, PRODUCTION_PROFILE]) {
      expect(deadlines(profile).intervalMs).toBeLessThan(profile.pollCadenceMs);
    }
  });

  it('holds the read interval inside a range that neither spins nor crawls', () => {
    for (const profile of [CI_PROFILE, PRODUCTION_PROFILE]) {
      const interval = deadlines(profile).intervalMs;
      expect(interval).toBeGreaterThanOrEqual(50);
      expect(interval).toBeLessThanOrEqual(500);
    }
  });

  it('keeps the CI record TTL small but nonzero, as blueprint/testing.md fixes it', () => {
    expect(CI_PROFILE.recordTtlMs).toBeGreaterThanOrEqual(1_000);
    expect(CI_PROFILE.recordTtlMs).toBeLessThanOrEqual(5_000);
  });
});
