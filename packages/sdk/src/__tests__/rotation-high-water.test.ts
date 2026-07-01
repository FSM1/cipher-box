/**
 * Tests for state/rotation-high-water.ts
 *
 * TDD RED phase — tests written before implementation (68-01 Task 1).
 *
 * SC#1 / ROT-07: durable monotonic-max generation + seq floors over an
 * injected HighWaterStore seam, proven at the logic tier without a browser.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createRotationHighWater, type HighWaterStore } from '../state/rotation-high-water';

/** Simple Map-backed HighWaterStore fake for injection. */
function createMapStore(): HighWaterStore & { map: Map<string, number> } {
  const map = new Map<string, number>();
  return {
    map,
    async get(nodeId: string) {
      return map.get(nodeId);
    },
    async put(nodeId: string, value: number) {
      map.set(nodeId, value);
    },
  };
}

describe('createRotationHighWater — generation floor (monotonic-max)', () => {
  let generationStore: ReturnType<typeof createMapStore>;
  let seqStore: ReturnType<typeof createMapStore>;

  beforeEach(() => {
    generationStore = createMapStore();
    seqStore = createMapStore();
  });

  it('bumpGeneration then getGenerationFloor returns the bumped value', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 5);
    expect(await hw.getGenerationFloor('node-a')).toBe(5);
  });

  it('bumping to a lower generation leaves the floor at the higher value (monotonic-max)', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 5);
    await hw.bumpGeneration('node-a', 4);
    expect(await hw.getGenerationFloor('node-a')).toBe(5);
  });

  it('getGenerationFloor returns undefined for an unseen nodeId', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    expect(await hw.getGenerationFloor('unseen-node')).toBeUndefined();
  });
});

describe('createRotationHighWater — seq floor (monotonic-max)', () => {
  let generationStore: ReturnType<typeof createMapStore>;
  let seqStore: ReturnType<typeof createMapStore>;

  beforeEach(() => {
    generationStore = createMapStore();
    seqStore = createMapStore();
  });

  it('bumpSeq then getSeqFloor returns the bumped value', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpSeq('node-a', 10);
    expect(await hw.getSeqFloor('node-a')).toBe(10);
  });

  it('bumping to a lower seq leaves the floor at the higher value (monotonic-max)', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpSeq('node-a', 10);
    await hw.bumpSeq('node-a', 3);
    expect(await hw.getSeqFloor('node-a')).toBe(10);
  });
});

describe('createRotationHighWater — seedFromGrant (owner-vouched first-contact seed)', () => {
  let generationStore: ReturnType<typeof createMapStore>;
  let seqStore: ReturnType<typeof createMapStore>;

  beforeEach(() => {
    generationStore = createMapStore();
    seqStore = createMapStore();
  });

  it('seeds the generation floor to rootGeneration when no floor exists yet', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.seedFromGrant('node-a', 7);
    expect(await hw.getGenerationFloor('node-a')).toBe(7);
  });

  it('raises the generation floor only when rootGeneration is higher than the current floor', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 9);
    await hw.seedFromGrant('node-a', 3); // lower than current floor -- must not lower it
    expect(await hw.getGenerationFloor('node-a')).toBe(9);
  });

  it('raises the generation floor when rootGeneration is higher than the current floor', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 3);
    await hw.seedFromGrant('node-a', 9);
    expect(await hw.getGenerationFloor('node-a')).toBe(9);
  });
});

describe('createRotationHighWater — restart/persistence (SC#1 logic tier)', () => {
  it('a fresh state machine over the SAME backing stores observes previously-written floors and rejects a downgrade', async () => {
    const generationStore = createMapStore();
    const seqStore = createMapStore();

    const first = createRotationHighWater(generationStore, seqStore);
    await first.bumpGeneration('node-a', 6);
    await first.bumpSeq('node-a', 42);

    // Simulate a restart: a FRESH state machine constructed over the SAME
    // backing stores (no in-instance cache is allowed to hide the store).
    const second = createRotationHighWater(generationStore, seqStore);
    expect(await second.getGenerationFloor('node-a')).toBe(6);
    expect(await second.getSeqFloor('node-a')).toBe(42);

    // The fresh instance must reject a downgrade attempt too.
    await second.bumpGeneration('node-a', 2);
    expect(await second.getGenerationFloor('node-a')).toBe(6);
  });
});

describe('createRotationHighWater — malformed stored value treated as absent (V5 fail-closed)', () => {
  it('a negative stored value is treated as absent, not coerced to a low floor', async () => {
    const generationStore = createMapStore();
    const seqStore = createMapStore();
    generationStore.map.set('node-a', -1);

    const hw = createRotationHighWater(generationStore, seqStore);
    expect(await hw.getGenerationFloor('node-a')).toBeUndefined();
  });

  it('a non-integer (fractional) stored value is treated as absent', async () => {
    const generationStore = createMapStore();
    const seqStore = createMapStore();
    generationStore.map.set('node-a', 3.5);

    const hw = createRotationHighWater(generationStore, seqStore);
    expect(await hw.getGenerationFloor('node-a')).toBeUndefined();
  });

  it('a NaN stored value is treated as absent', async () => {
    const generationStore = createMapStore();
    const seqStore = createMapStore();
    generationStore.map.set('node-a', NaN);

    const hw = createRotationHighWater(generationStore, seqStore);
    expect(await hw.getGenerationFloor('node-a')).toBeUndefined();
  });

  it('a non-numeric stored value is treated as absent', async () => {
    const generationStore = createMapStore();
    const seqStore = createMapStore();
    // Force a malformed value through the store's untyped `get` seam.
    (generationStore.map as Map<string, unknown>).set('node-a', 'not-a-number');

    const hw = createRotationHighWater(generationStore, seqStore);
    expect(await hw.getGenerationFloor('node-a')).toBeUndefined();
  });

  it('a malformed stored value does not get coerced to a low floor -- a subsequent bump still wins', async () => {
    const generationStore = createMapStore();
    const seqStore = createMapStore();
    generationStore.map.set('node-a', -5);

    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 1);
    expect(await hw.getGenerationFloor('node-a')).toBe(1);
  });
});
