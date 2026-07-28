import { describe, expect, it } from 'vitest';

import { storageHeadroomBytes } from './storageHeadroom.js';

describe('storageHeadroomBytes', () => {
  it('reports quota minus usage when the estimate is complete', () => {
    expect(storageHeadroomBytes({ quota: 1_000, usage: 400 })).toBe(600);
  });

  it('reports a genuine zero when the origin is full', () => {
    expect(storageHeadroomBytes({ quota: 1_000, usage: 1_000 })).toBe(0);
  });

  it('never reports negative headroom when usage exceeds quota', () => {
    expect(storageHeadroomBytes({ quota: 1_000, usage: 1_500 })).toBe(0);
  });

  it('stays unmeasured when usage is missing rather than assuming an empty origin', () => {
    // The whole point: `usage ?? 0` would hand back 1000 as free space and the
    // engine would build a measured policy on a number nothing measured.
    expect(storageHeadroomBytes({ quota: 1_000 })).toBeUndefined();
  });

  it('stays unmeasured when quota is missing', () => {
    expect(storageHeadroomBytes({ usage: 400 })).toBeUndefined();
  });

  it('stays unmeasured when the environment reports no estimate at all', () => {
    expect(storageHeadroomBytes(undefined)).toBeUndefined();
    expect(storageHeadroomBytes({})).toBeUndefined();
  });

  it('distinguishes an unmeasurable origin from a measured zero', () => {
    // Both admit no upload; only one of them means the origin is full.
    expect(storageHeadroomBytes({ quota: 0, usage: 0 })).toBe(0);
    expect(storageHeadroomBytes(undefined)).toBeUndefined();
  });
});
