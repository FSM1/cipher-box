/**
 * @cipherbox/sdk - Durable rotation high-water state machine
 *
 * Hoists the durable anti-rollback CORE LOGIC (ROT-07) into the SDK so it is
 * unit-tested with Vitest -- apps/web supplies only a thin, untested
 * IndexedDB-backed HighWaterStore adapter (68-06) and calls enforceResolved
 * (added in a follow-up task) from resolveIpnsRecord.
 *
 * Maintains two independent monotonic-max floors per nodeId:
 *   - generation: the M1 cross-generation rollback defense (design §4.3)
 *   - seq: the within-generation sequence rollback defense (design §6.5)
 *
 * Both floors are read through an injected HighWaterStore seam on every
 * access -- there is NO in-instance cache -- so a fresh state machine
 * constructed over the SAME backing store observes previously-written
 * floors (the restart/persistence semantics proven at the logic tier).
 */

/** A durable key-value seam for a single high-water floor (generation or seq). */
export interface HighWaterStore {
  get(nodeId: string): Promise<number | undefined>;
  put(nodeId: string, value: number): Promise<void>;
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
  };
}
