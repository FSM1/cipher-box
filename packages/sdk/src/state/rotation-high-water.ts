/**
 * @cipherbox/sdk - Durable rotation high-water state machine
 *
 * Hoists the durable anti-rollback CORE LOGIC (ROT-07) into the SDK so it is
 * unit-tested with Vitest -- apps/web supplies only a thin, untested
 * IndexedDB-backed HighWaterStore adapter (68-06) and calls enforceResolved
 * from resolveIpnsRecord.
 *
 * Maintains two independent monotonic-max floors per nodeId:
 *   - generation: the M1 cross-generation rollback defense (design §4.3)
 *   - seq: the within-generation sequence rollback defense (design §6.5)
 *
 * Both floors are read through an injected HighWaterStore seam on every
 * access -- there is NO in-instance cache -- so a fresh state machine
 * constructed over the SAME backing store observes previously-written
 * floors (the restart/persistence semantics proven at the logic tier).
 *
 * enforceResolved is a pure pass/throw pre-unseal gate -- it never returns
 * or computes any AAD/unseal parameter. The AAD generation is sourced from
 * the parent mirror in the unrelated unseal path.
 */

/** A durable key-value seam for a single high-water floor (generation or seq). */
export interface HighWaterStore {
  get(nodeId: string): Promise<number | undefined>;
  put(nodeId: string, value: number): Promise<void>;
}

/** Parameters supplied to enforceResolved for a freshly-resolved IPNS record. */
export interface EnforceResolvedParams {
  nodeId: string;
  seq: number;
  generation: number;
  /** Owner-vouched cold-device floor applied only on first contact (no local seq floor yet). */
  versionFloor: number;
}

/** Thrown when a resolved generation regresses below the durable generation floor. */
export class GenerationRegressionError extends Error {
  constructor(nodeId: string, floor: number, attempted: number) {
    super(
      `Generation regression rejected for node ${nodeId}: floor=${floor}, attempted=${attempted}`
    );
    this.name = 'GenerationRegressionError';
  }
}

/** Thrown when a resolved seq regresses below the durable seq floor (or cold-device versionFloor). */
export class SequenceRegressionError extends Error {
  constructor(nodeId: string, floor: number, attempted: number) {
    super(
      `Sequence regression rejected for node ${nodeId}: floor=${floor}, attempted=${attempted}`
    );
    this.name = 'SequenceRegressionError';
  }
}

/**
 * Validates a value read back from a HighWaterStore. Fail-closed (V5):
 * anything that is not a non-negative safe integer is treated as absent
 * rather than coerced to a low floor.
 */
function isValidFloorValue(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

/**
 * Reads a floor from the store, applying V5 fail-closed validation.
 * A malformed stored value (negative, fractional, NaN, non-numeric) is
 * treated as absent -- never coerced to a low floor.
 */
async function readFloor(store: HighWaterStore, nodeId: string): Promise<number | undefined> {
  const raw = await store.get(nodeId);
  return isValidFloorValue(raw) ? raw : undefined;
}

/**
 * Conditionally raises a floor to `candidate` only if it is higher than the
 * current stored value (monotonic-max). Returns the resulting floor.
 */
async function bumpFloor(
  store: HighWaterStore,
  nodeId: string,
  candidate: number
): Promise<number> {
  const current = await readFloor(store, nodeId);
  // V5 applies to writes too: never persist a malformed candidate (NaN,
  // negative, fractional) -- the floor stays where it is.
  if (!isValidFloorValue(candidate)) {
    return current ?? 0;
  }
  if (current === undefined || candidate > current) {
    await store.put(nodeId, candidate);
    return candidate;
  }
  return current;
}

/** The durable rotation high-water state machine returned by createRotationHighWater. */
export interface RotationHighWater {
  getGenerationFloor(nodeId: string): Promise<number | undefined>;
  bumpGeneration(nodeId: string, generation: number): Promise<void>;
  /** Owner-vouched first-contact seed -- raises the generation floor only if higher (never lowers it). */
  seedFromGrant(nodeId: string, rootGeneration: number): Promise<void>;
  getSeqFloor(nodeId: string): Promise<number | undefined>;
  bumpSeq(nodeId: string, seq: number): Promise<void>;
  /**
   * Fail-closed pre-unseal gate: compares a freshly-resolved seq/generation
   * against the stored floors. Throws a distinguishable regression error on
   * any regression; on first contact (no local seq floor) applies the
   * cold-device versionFloor gate; otherwise bumps both floors monotonic-max.
   *
   * This is a pure pass/throw decision -- it never returns or computes any
   * AAD/unseal parameter.
   */
  enforceResolved(params: EnforceResolvedParams): Promise<void>;
}

/**
 * Creates a durable rotation high-water state machine over two injected
 * HighWaterStore seams -- one for the generation floor, one for the seq
 * floor. Holds no in-instance cache: every read/write goes through the
 * injected stores.
 */
export function createRotationHighWater(
  generationStore: HighWaterStore,
  seqStore: HighWaterStore
): RotationHighWater {
  return {
    async getGenerationFloor(nodeId) {
      return readFloor(generationStore, nodeId);
    },

    async bumpGeneration(nodeId, generation) {
      await bumpFloor(generationStore, nodeId, generation);
    },

    async seedFromGrant(nodeId, rootGeneration) {
      await bumpFloor(generationStore, nodeId, rootGeneration);
    },

    async getSeqFloor(nodeId) {
      return readFloor(seqStore, nodeId);
    },

    async bumpSeq(nodeId, seq) {
      await bumpFloor(seqStore, nodeId, seq);
    },

    async enforceResolved({ nodeId, seq, generation, versionFloor }) {
      // Fail-closed on the LIVE inputs too, not just stored values: NaN
      // compares false against everything in JS, so a malformed generation/
      // seq would otherwise sail past both `<` regression checks below.
      // floor=-1 marks "input itself invalid" (no valid floor was consulted).
      if (!isValidFloorValue(generation)) {
        throw new GenerationRegressionError(nodeId, -1, generation);
      }
      if (!isValidFloorValue(seq)) {
        throw new SequenceRegressionError(nodeId, -1, seq);
      }

      const generationFloor = await readFloor(generationStore, nodeId);
      if (generationFloor !== undefined && generation < generationFloor) {
        throw new GenerationRegressionError(nodeId, generationFloor, generation);
      }

      const seqFloor = await readFloor(seqStore, nodeId);
      if (seqFloor === undefined) {
        // Cold-device / first-contact: apply the owner-vouched versionFloor
        // gate. A malformed versionFloor is rejected rather than treated as
        // "no gate" -- first contact is exactly when the gate matters most.
        if (!isValidFloorValue(versionFloor) || seq < versionFloor) {
          throw new SequenceRegressionError(nodeId, versionFloor, seq);
        }
      } else if (seq < seqFloor) {
        throw new SequenceRegressionError(nodeId, seqFloor, seq);
      }

      await bumpFloor(generationStore, nodeId, generation);
      await bumpFloor(seqStore, nodeId, seq);
    },
  };
}
