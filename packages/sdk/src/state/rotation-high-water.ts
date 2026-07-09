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
 * Both floors -- plus the optional SC#3 ECIES wrapped-key checkpoint -- are
 * read through a SINGLE injected `HighWaterStore` seam on every access --
 * there is NO in-instance cache -- so a fresh state machine constructed over
 * the SAME backing store observes previously-written floors (the
 * restart/persistence semantics proven at the logic tier).
 *
 * enforceResolved is a pure pass/throw pre-unseal gate -- it never returns
 * or computes any AAD/unseal parameter. The AAD generation is sourced from
 * the parent mirror in the unrelated unseal path.
 *
 * TS/Rust behavioral-equivalence contract (SC#5, T-70-03/T-70-04): this
 * orchestration layer's field-bump helper is a non-atomic read-then-put,
 * exactly like the Rust twin's `bump_floor` (`crates/sdk/src/rotation/high_water.rs`).
 * Atomicity is NOT this layer's job -- it is owned by the concrete
 * `HighWaterStore` adapter: the browser's `idbPutFloors`/`idbPersistWrappedKey`
 * (`apps/web/src/services/rotation-state.service.ts`) already read the
 * existing COMBINED record back INSIDE the same IndexedDB `readwrite`
 * transaction and write `Math.max(existing, value)` per numeric field, so a
 * concurrent tab's higher write can never be clobbered by a lower one --
 * matching the Rust store's `tokio::sync::Mutex`-guarded, max-preserving
 * `JsonSidecarFloorStore::put`.
 *
 * SC#4/D-06 (CLOSED, 70.1-02): `enforceResolved`'s cross-store sequencing --
 * formerly `bumpFloor(generationStore)` THEN `bumpFloor(seqStore)`, two
 * separate non-atomic writes to two separate IndexedDB object stores -- was
 * a DOC-ONLY residual flagged by Phase 70
 * (`.planning/todos/pending/2026-07-02-rotation-hardening-followups-from-pr-review.md`
 * item 1). This phase collapses BOTH floors into ONE combined per-nodeId
 * record (`CombinedFloorRecord`) written via a SINGLE `store.put` call --
 * the cross-store sequencing window no longer exists because there is only
 * one store. D-07 additionally folds the SC#3 wrapped-key checkpoint
 * ciphertext into this SAME combined record (see
 * `apps/web/src/services/rotation-state.service.ts`'s
 * `persistWrappedKey`/`getWrappedKey`/`deleteWrappedKey`).
 */

/**
 * Persisted combined per-nodeId record (SC#4/D-06, SC#3/D-07): both
 * anti-rollback floors PLUS the optional ECIES wrapped-key checkpoint
 * ciphertext, all in ONE record so a single store write is atomic across
 * all three fields. `wrappedKeyCheckpoint` is a ciphertext blob -- it is
 * never numerically compared/maxed, only overwritten or cleared.
 */
export interface CombinedFloorRecord {
  generation?: number;
  seq?: number;
  wrappedKeyCheckpoint?: string;
}

/**
 * A durable key-value seam for the COMBINED per-nodeId floor record. Replaces
 * the prior two-store (`generationStore`/`seqStore`) seam: one get/put pair
 * now carries generation, seq, AND the optional wrapped-key checkpoint in a
 * single record, so `enforceResolved` writes both floors atomically.
 */
export interface HighWaterStore {
  get(nodeId: string): Promise<CombinedFloorRecord | undefined>;
  /**
   * Writes the FULL combined record for `nodeId`. Concrete adapters (e.g.
   * the browser's IndexedDB-backed store) MUST max-preserve `generation`/
   * `seq` against any existing record inside the SAME write transaction --
   * this orchestration layer already computes the candidate max before
   * calling `put`, but a concurrent writer (another tab) may have raised the
   * floor since this layer's own read, so the concrete store's own
   * max-preserving write is the real safety net.
   */
  put(nodeId: string, record: CombinedFloorRecord): Promise<void>;
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
 * Reads the combined record from the store, applying V5 fail-closed
 * validation independently to `generation` and `seq` -- a malformed value in
 * ONE field never poisons the other, and never poisons the ciphertext blob.
 */
async function readCombined(store: HighWaterStore, nodeId: string): Promise<CombinedFloorRecord> {
  const raw = await store.get(nodeId);
  return {
    generation: isValidFloorValue(raw?.generation) ? raw?.generation : undefined,
    seq: isValidFloorValue(raw?.seq) ? raw?.seq : undefined,
    wrappedKeyCheckpoint:
      typeof raw?.wrappedKeyCheckpoint === 'string' ? raw.wrappedKeyCheckpoint : undefined,
  };
}

/**
 * Conditionally raises ONE field of the combined record to `candidate`, only
 * if it is higher than the current stored value (monotonic-max) -- writing
 * the FULL combined record back (preserving the other field and the
 * wrapped-key checkpoint untouched) via a single `store.put` call.
 */
async function bumpField(
  store: HighWaterStore,
  nodeId: string,
  field: 'generation' | 'seq',
  candidate: number
): Promise<void> {
  // V5 applies to writes too: never persist a malformed candidate (NaN,
  // negative, fractional) -- the floor stays where it is.
  if (!isValidFloorValue(candidate)) {
    return;
  }
  const current = await readCombined(store, nodeId);
  const currentValue = current[field];
  if (currentValue === undefined || candidate > currentValue) {
    await store.put(nodeId, { ...current, [field]: candidate });
  }
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
   * cold-device versionFloor gate; otherwise bumps both floors monotonic-max
   * in ONE combined-record write (SC#4/D-06 -- no cross-store sequencing
   * window).
   *
   * This is a pure pass/throw decision -- it never returns or computes any
   * AAD/unseal parameter.
   */
  enforceResolved(params: EnforceResolvedParams): Promise<void>;
}

/**
 * Creates a durable rotation high-water state machine over a SINGLE injected
 * combined `HighWaterStore` seam (SC#4/D-06). Holds no in-instance cache:
 * every read/write goes through the injected store.
 */
export function createRotationHighWater(store: HighWaterStore): RotationHighWater {
  return {
    async getGenerationFloor(nodeId) {
      return (await readCombined(store, nodeId)).generation;
    },

    async bumpGeneration(nodeId, generation) {
      await bumpField(store, nodeId, 'generation', generation);
    },

    async seedFromGrant(nodeId, rootGeneration) {
      await bumpField(store, nodeId, 'generation', rootGeneration);
    },

    async getSeqFloor(nodeId) {
      return (await readCombined(store, nodeId)).seq;
    },

    async bumpSeq(nodeId, seq) {
      await bumpField(store, nodeId, 'seq', seq);
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

      const current = await readCombined(store, nodeId);

      if (current.generation !== undefined && generation < current.generation) {
        throw new GenerationRegressionError(nodeId, current.generation, generation);
      }

      if (current.seq === undefined) {
        // Cold-device / first-contact: apply the owner-vouched versionFloor
        // gate. A malformed versionFloor is rejected rather than treated as
        // "no gate" -- first contact is exactly when the gate matters most.
        if (!isValidFloorValue(versionFloor) || seq < versionFloor) {
          throw new SequenceRegressionError(nodeId, versionFloor, seq);
        }
      } else if (seq < current.seq) {
        throw new SequenceRegressionError(nodeId, current.seq, seq);
      }

      // SC#4/D-06: bump BOTH floors in ONE combined-record write -- CLOSED,
      // no cross-store sequencing window remains (see module doc above).
      const nextGeneration =
        current.generation === undefined || generation > current.generation
          ? generation
          : current.generation;
      const nextSeq = current.seq === undefined || seq > current.seq ? seq : current.seq;
      await store.put(nodeId, { ...current, generation: nextGeneration, seq: nextSeq });
    },
  };
}
