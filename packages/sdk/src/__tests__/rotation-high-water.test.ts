/**
 * Tests for state/rotation-high-water.ts
 *
 * TDD RED phase — tests written before implementation (68-01 Task 1/2).
 *
 * SC#1 / ROT-07: durable monotonic-max generation + seq floors over an
 * injected HighWaterStore seam, proven at the logic tier without a browser.
 * SC#4 / D-05: enforceResolved fail-closed regression gate. §7.3 test 13
 * (within-generation seq rollback) and test 14 (cold-device first-contact).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  createRotationHighWater,
  GenerationRegressionError,
  SequenceRegressionError,
  type HighWaterStore,
} from '../state/rotation-high-water';

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

describe('enforceResolved — fail-closed regression gate (SC#4 / D-05 / §7.3 test 13/14)', () => {
  let generationStore: ReturnType<typeof createMapStore>;
  let seqStore: ReturnType<typeof createMapStore>;

  beforeEach(() => {
    generationStore = createMapStore();
    seqStore = createMapStore();
  });

  it('§7.3 test 13: a seq below the stored seq floor throws SequenceRegressionError and does not bump', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 1);
    await hw.bumpSeq('node-a', 10);

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 5, generation: 1, versionFloor: 0 })
    ).rejects.toThrow(SequenceRegressionError);

    // Must NOT bump on rejection.
    expect(await hw.getSeqFloor('node-a')).toBe(10);
  });

  it('a generation below the stored generation floor throws GenerationRegressionError and does not bump', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 5);
    await hw.bumpSeq('node-a', 10);

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 20, generation: 2, versionFloor: 0 })
    ).rejects.toThrow(GenerationRegressionError);

    // Must NOT bump generation OR seq on rejection.
    expect(await hw.getGenerationFloor('node-a')).toBe(5);
    expect(await hw.getSeqFloor('node-a')).toBe(10);
  });

  it('non-regressing values bump both floors monotonic-max and resolve normally', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 1);
    await hw.bumpSeq('node-a', 10);

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 15, generation: 2, versionFloor: 0 })
    ).resolves.not.toThrow();

    expect(await hw.getGenerationFloor('node-a')).toBe(2);
    expect(await hw.getSeqFloor('node-a')).toBe(15);
  });

  it('§7.3 test 14 cold-device: first contact (no local seq floor) with seq below versionFloor throws SequenceRegressionError', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    // No prior bumpSeq/bumpGeneration call -- this is a cold device.

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 3, generation: 1, versionFloor: 10 })
    ).rejects.toThrow(SequenceRegressionError);

    // Must not seed a floor from the rejected first-contact attempt.
    expect(await hw.getSeqFloor('node-a')).toBeUndefined();
  });

  it('cold-device first contact at or above versionFloor seeds and passes', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 10, generation: 1, versionFloor: 10 })
    ).resolves.not.toThrow();

    expect(await hw.getSeqFloor('node-a')).toBe(10);
    expect(await hw.getGenerationFloor('node-a')).toBe(1);
  });

  it('a NaN live generation is rejected fail-closed, not silently passed', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 5);
    await hw.bumpSeq('node-a', 10);

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 20, generation: NaN, versionFloor: 0 })
    ).rejects.toThrow(GenerationRegressionError);

    // Must NOT bump either floor on rejection.
    expect(await hw.getGenerationFloor('node-a')).toBe(5);
    expect(await hw.getSeqFloor('node-a')).toBe(10);
  });

  it('a NaN live seq is rejected fail-closed, not silently passed', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 5);
    await hw.bumpSeq('node-a', 10);

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: NaN, generation: 6, versionFloor: 0 })
    ).rejects.toThrow(SequenceRegressionError);

    expect(await hw.getGenerationFloor('node-a')).toBe(5);
    expect(await hw.getSeqFloor('node-a')).toBe(10);
  });

  it('negative or fractional live values are rejected fail-closed', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 1, generation: -1, versionFloor: 0 })
    ).rejects.toThrow(GenerationRegressionError);
    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 1.5, generation: 1, versionFloor: 0 })
    ).rejects.toThrow(SequenceRegressionError);

    // Nothing may be seeded by a rejected attempt.
    expect(await hw.getGenerationFloor('node-a')).toBeUndefined();
    expect(await hw.getSeqFloor('node-a')).toBeUndefined();
  });

  it('cold-device first contact with a malformed versionFloor is rejected, not treated as "no gate"', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);

    await expect(
      hw.enforceResolved({ nodeId: 'node-a', seq: 3, generation: 1, versionFloor: NaN })
    ).rejects.toThrow(SequenceRegressionError);

    expect(await hw.getSeqFloor('node-a')).toBeUndefined();
  });

  it('bumpGeneration/bumpSeq never persist a malformed live candidate', async () => {
    const hw = createRotationHighWater(generationStore, seqStore);
    await hw.bumpGeneration('node-a', 5);

    await hw.bumpGeneration('node-a', NaN);
    await hw.bumpSeq('node-a', NaN);

    expect(await hw.getGenerationFloor('node-a')).toBe(5);
    expect(await hw.getSeqFloor('node-a')).toBeUndefined();
    // The raw backing stores must not have been polluted either.
    expect(generationStore.map.get('node-a')).toBe(5);
    expect(seqStore.map.has('node-a')).toBe(false);
  });

  it('GenerationRegressionError and SequenceRegressionError are instanceof-distinguishable with stable names', () => {
    const genErr = new GenerationRegressionError('node-a', 1, 2);
    const seqErr = new SequenceRegressionError('node-a', 1, 2);

    expect(genErr).toBeInstanceOf(Error);
    expect(genErr).toBeInstanceOf(GenerationRegressionError);
    expect(genErr).not.toBeInstanceOf(SequenceRegressionError);
    expect(genErr.name).toBe('GenerationRegressionError');

    expect(seqErr).toBeInstanceOf(Error);
    expect(seqErr).toBeInstanceOf(SequenceRegressionError);
    expect(seqErr).not.toBeInstanceOf(GenerationRegressionError);
    expect(seqErr.name).toBe('SequenceRegressionError');
  });
});
