# Phase 70: Rotation Soundness - Deep Merge, Fresh-Record Resume, and Durable Floor Concurrency - Pattern Map

**Mapped:** 2026-07-07
**Files analyzed:** 10 (2 new TS, 1 new Rust test module, 7 modified)
**Analogs found:** 10 / 10

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|-----------------|---------------|
| `packages/sdk-core/src/rotation/merge.ts` | utility (pure transform) | transform | `packages/sdk-core/src/folder/merge.ts` (`mergeChildren`) | exact (same signature shape, different policy) |
| `packages/sdk-core/src/__tests__/rotation/merge.test.ts` | test | transform | `packages/sdk-core/src/__tests__/folder-merge.test.ts` + `.../rotation/engine.test.ts` | exact |
| `crates/sdk/src/floor_store.rs` (new concurrency tests) | test | event-driven / concurrency | same file's existing `#[cfg(test)] mod tests` + `crates/sdk/src/rotation/high_water.rs` test module | exact |
| `packages/sdk-core/src/rotation/engine.ts` | service (rotation walk engine) | event-driven / CRUD | itself (existing `mergeConcurrentChildren`, `verifySubtreeClean`, `rotateOne`) | exact (in-place modification) |
| `packages/sdk-core/src/folder/registration.ts` | service (publish helper) | request-response / CRUD | itself (`updateFolderMetadataAndPublish`'s existing `merge` closure) | exact (in-place modification) |
| `packages/sdk/src/state/rotation-high-water.ts` | store/orchestration | CRUD | `apps/web/src/services/rotation-state.service.ts` (`idbPut`) | role-match (TS parity reference, likely doc-only) |
| `packages/sdk/src/client.ts` (`performScopeExitRotation`) | service (orchestration) | event-driven | itself, existing zeroization call sites elsewhere in `client.ts` | exact (in-place modification) |
| `apps/web/src/services/rotation-driver.service.ts` | service (browser glue) | event-driven | `apps/web/src/services/rotation-state.service.ts` (`idbPut`, connection caching) | role-match |
| `crates/sdk/src/rotation/high_water.rs` (`bump_floor`) | service (concurrency gate) | CRUD / concurrency | `apps/web/src/services/rotation-state.service.ts`'s `idbPut` (cross-language pattern to port) | role-match (cross-language port) |
| `crates/sdk/src/floor_store.rs` (`JsonSidecarFloorStore`) | store (file-backed) | file-I/O / concurrency | `crates/sdk`'s `WriteQueue` sidecar convention (see engine.ts pitfalls note); TS `idbPut` is the semantic analog to port | role-match (cross-language port) |

## Pattern Assignments

### `packages/sdk-core/src/rotation/merge.ts` (NEW - utility, transform)

**Analog:** `packages/sdk-core/src/folder/merge.ts` (`mergeChildren`, remote-wins default - DO NOT modify its default policy)

**Why this analog:** Same function shape (`(base, local, remote) => SealedChildRef[]`), same module location convention (co-located `merge.ts` in a domain subfolder), but a DIFFERENT conflict policy. `mergeRotatedChildren` must be a wholly separate exported function, never a flag on `mergeChildren`.

**Core pattern (recommended shape, from RESEARCH.md Pattern 1, already verified against the codebase's `SealedChildRef` type):**
```typescript
// packages/sdk-core/src/rotation/merge.ts (NEW)
import type { SealedChildRef } from '@cipherbox/core';

/**
 * Rotation-only three-way merge: LOCAL WINS on conflict (preserves the D-02
 * re-seal), remote-only (not-in-base) entries are concurrent adds (included,
 * still under their pre-rotation seal), base-only (not in local AND not in
 * remote) entries are intentional deletes (dropped).
 *
 * NEVER use this for non-rotation folder mutations - see folder/merge.ts's
 * mergeChildren (remote-wins) for the generic policy.
 */
export function mergeRotatedChildren(
  base: SealedChildRef[],
  local: SealedChildRef[],
  remote: SealedChildRef[]
): SealedChildRef[] {
  const baseNames = new Set(base.map((c) => c.ipnsName));
  const merged = new Map<string, SealedChildRef>();
  for (const child of remote) {
    if (!baseNames.has(child.ipnsName)) merged.set(child.ipnsName, child);
  }
  for (const child of local) merged.set(child.ipnsName, child);
  return Array.from(merged.values());
}
```

**Import convention:** copy `folder/merge.ts`'s import style (`import type { SealedChildRef } from '@cipherbox/core';`) - no relative deep imports.

**Known accepted residual (do not "fix"):** unconditional local-wins can resurrect a concurrently-deleted child (RESEARCH.md Pitfall 2). Document in a code comment, not a bug to close in this phase.

---

### `packages/sdk-core/src/__tests__/rotation/merge.test.ts` (NEW - test)

**Analog 1:** `packages/sdk-core/src/__tests__/folder-merge.test.ts` (existing `mergeChildren` unit tests) - copy the describe/it structure, fixture-building helpers for `SealedChildRef` objects, and assertion style (deep-equal on resulting arrays keyed by `ipnsName`).

**Analog 2:** `packages/sdk-core/src/__tests__/rotation/engine.test.ts` - copy the rotation-domain fixture conventions (readKey byte fixtures, node-id naming scheme) already used for CAS-409 merge tests (~L1106-1334) and the zeroization-invariant describe block (~L324-368) as a template for any buffer-identity assertions this test file also needs.

**Required cases (from RESEARCH.md Phase Requirements -> Test Map, SC#1):**
- local wins on conflict (same `ipnsName` in base/local/remote with differing `readKeySealed`)
- remote-only add is included
- base-only omission (present in base, absent from both local and remote) is dropped
- documented residual: concurrent delete during rotation resurrects (assert the KNOWN behavior, not a "fix")

---

### `crates/sdk/src/floor_store.rs` (new `#[tokio::test]` concurrency tests)

**Analog:** the file's own existing `#[cfg(test)] mod tests` block, plus `crates/sdk/src/rotation/high_water.rs`'s test module for the "spawn N concurrent tasks against a shared store" pattern.

**Core pattern to copy:** existing tests in this module already construct a `JsonSidecarFloorStore` against a `tempfile`-backed sidecar path and call `get`/`put` directly - reuse that fixture setup. For the new concurrency tests, wrap N `tokio::spawn` tasks each calling `put` with distinct/overlapping generations against a `std::sync::Arc`-shared store handle, then `join_all` and assert the final `get` reflects `max(...)` across all attempts (no lost updates). Mirror `high_water.rs`'s existing test naming convention (`snake_case`, behavior-first: e.g. `concurrent_puts_no_lost_update`, `corrupt_sidecar_fails_closed`).

**Corrupt-sidecar fail-closed test:** write garbage bytes directly to the sidecar file path (bypassing the store's own `put`), then call `get`/`enforce_resolved` and assert an `Err` (or equivalent fail-closed signal), NOT `unwrap_or_default()`'s silent cold-start behavior - this is a NEW assertion; RESEARCH.md flags this as a scope escalation beyond the original todo's framing (A4), so it must be tested explicitly, not assumed covered.

---

### `packages/sdk-core/src/rotation/engine.ts` (MODIFIED - service, event-driven)

**Analog:** itself. Three concrete pattern edits, all verified against live code in RESEARCH.md:

**1. `mergeConcurrentChildren` swap (SC#1 site A)** - current code (L451-477 per research):
```typescript
export async function mergeConcurrentChildren(
  basePub: PublishedNode,
  remotePub: PublishedNode,
  oldReadKey: Uint8Array,
  localChildren: SealedChildRef[],
  newReadKey: Uint8Array,
  localNode: Node,
  generationPrime: number,
  writeKey: Uint8Array
): Promise<PublishedNode> {
  const baseNodeDecoded = await unsealNode(basePub, oldReadKey);
  const remoteNodeDecoded = await unsealNode(remotePub, oldReadKey);
  const mergedChildren = mergeChildren(          // <-- swap for mergeRotatedChildren
    baseNodeDecoded.children ?? [],
    localChildren,
    remoteNodeDecoded.children ?? []
  );
  const mergedNode: Node = { ...localNode, generation: generationPrime, children: mergedChildren };
  return sealNode(mergedNode, newReadKey, writeKey);
}
```
Change the return shape to `Promise<{ published: PublishedNode; mergedChildren: SealedChildRef[] }>` (mechanical, low-risk per research) so `rotateOne`'s closure can capture the plaintext merged children.

**2. `rotateOne`'s merged-children return capture (SC#3, Pattern 3 in research):**
```typescript
let mergedChildrenForReturn: SealedChildRef[] | undefined;
// ... inside publishWithCas's merge closure:
merge: async (base, _local, remote) => {
  if (!base) { /* unchanged fallback */ }
  const mergedPublished = await mergeConcurrentChildren(/* ... */);
  mergedChildrenForReturn = mergedPublished.mergedChildren;
  return { merged: mergedPublished.published };
},
// ... final return:
return {
  skipped: false,
  children: mergedChildrenForReturn ?? node.children ?? [],
  newSequenceNumber: casResult.newSequenceNumber,
};
```
This mirrors `registration.ts`'s existing `currentWriteChildren` outer-scope-capture pattern - reuse that same capture idiom.

**3. `verifySubtreeClean` full recursion (SC#2)** - current depth-1-only shape (L491-524 per research):
```typescript
export async function verifySubtreeClean(
  rootIpnsName: string,
  rootReadKey: Uint8Array,
  ctx: SdkContext
): Promise<{ isDirty: boolean; frontier: Array<{ ipnsName: string; nodeId: string }> }> {
  const rootResolved = await resolveIpnsRecord(rootIpnsName, ctx);
  if (!rootResolved) return { isDirty: false, frontier: [] };   // WRONG - must be dirty
  // ... only iterates rootNode.children ?? [] one level, never recurses.
}
```
Restructure per RESEARCH.md Pitfall 3: change the frontier item shape to carry enough for the BFS queue to consume directly (`{ ipnsName, nodeId, parentIpnsName, nodeReadKey, childPubKind, enqueuedGeneration }`), and derive keys via the SAME `unsealChildReadKey` mechanism the main BFS uses (extract a shared internal traversal helper rather than duplicating key-chain-walk logic).

**Grant callback threading (SC#4):** `grantCallbacks`/`innerGrants` currently exist only on `RotateOneParams` (verified via grep in research); add them to `RotationParams` and thread through every `rotateOne` call site inside `rotateReadFromNode`, mirroring how other cross-cutting params (`writeKey`, `ctx`) are already threaded through that same param chain.

**Zeroization boundary (SC#6):** engine.ts must NEVER zero `RotateReadResult.readKey` - that violates terminal-owner discipline (Anti-Patterns in research). On the dirty-resume-republish path, always return a fresh copy (`new Uint8Array(rootReadKey)`), never alias the caller's live buffer.

---

### `packages/sdk-core/src/folder/registration.ts` (MODIFIED - service, request-response/CRUD)

**Analog:** itself, existing inline `merge` closure in `updateFolderMetadataAndPublish` (SC#1 site B - the actually-exercised bug site per RESEARCH.md).

**Current code (L304-320 per research):**
```typescript
merge: (base, local, remote) => {
  if (params.writeKey) { /* write-body union, unaffected by SC#1 */ }
  return { merged: mergeChildren(base ?? [], local, remote) };  // <-- fix site B
},
```

**Fix pattern:** add an optional `mergeChildrenFn` parameter to `updateFolderMetadataAndPublish`, defaulting to today's `mergeChildren` (unchanged for every non-rotation caller). The two D-09 batched-republish call sites inside `rotateReadFromNode` (engine.ts ~L1042, ~L1110) pass `mergeChildrenFn: mergeRotatedChildren` explicitly. Also thread a `baseChildren` snapshot (currently omitted, silently defaulting to `[]`) - capture it into a new `baseChildrenSnapshot: SealedChildRef[]` field on `ParentTrackingState` at `parentTracking.set(...)` time, before any child-driven mutation.

**Return-value consumption:** `updateFolderMetadataAndPublish` already returns `publishedChildren` - currently ignored by both D-09 call sites. Diff `result.publishedChildren` against the pre-call snapshot by `ipnsName`; anything newly present is a concurrent add that must be pushed onto the BFS `queue` via the same `unsealChildReadKey`-against-parent-key idiom already used for root/child enqueue elsewhere in `engine.ts`.

---

### `packages/sdk/src/state/rotation-high-water.ts` (MODIFIED - store/orchestration, CRUD)

**Analog:** `apps/web/src/services/rotation-state.service.ts`'s `idbPut` (already-correct reference implementation - see Shared Patterns below).

Per RESEARCH.md, this file may need NO code change (doc-only parity note) - the max-preserving atomicity is already correctly implemented in the concrete IndexedDB store adapter (`idbPut`), not at this orchestration layer. Verify during planning via `grep -rn "idbPut\|bumpFloor" packages/sdk/src/state/rotation-high-water.ts` before assuming a change is required.

---

### `packages/sdk/src/client.ts` (`performScopeExitRotation`) (MODIFIED - service, event-driven)

**Analog:** itself - existing zeroization call sites elsewhere in `client.ts` (search `grep -rn "fill(0)" packages/sdk/src/client.ts` during planning for the established idiom).

**Pattern:** after `rotationResult` is assigned and its `readKey` has been defensively copied for whatever `client.ts` needs it for, zero `rotationResult.readKey` as the terminal owner. This is the SC#6 gap: `RotateReadResult.readKey` is currently never zeroed by the caller. Follow the codebase's existing terminal-owner idiom (buffer identity check + `fill(0)`), and pair the change with a unit test asserting (a) `rotationResult.readKey` IS zeroed post-call, and (b) any caller-owned buffer that must NOT be touched (e.g. `folderTree`'s own live key reference) is unchanged - mirroring `engine.test.ts`'s zeroization-invariant describe block (~L324-368).

**Dirty-resume republish threading:** locate the dirty-resume-republish call path (search for the caller feeding `verifySubtreeClean`'s output back into a republish) and ensure the result is threaded through the SAME return/zeroization contract as the fresh path - do not special-case it.

---

### `apps/web/src/services/rotation-driver.service.ts` (MODIFIED - service, event-driven, browser glue)

**Analog:** `apps/web/src/services/rotation-state.service.ts` (`idbPut`'s connection-caching and single-atomic-transaction idiom).

**Fix 1 - `activeRootNodeId` module-global -> `Set`:** replace the single `activeRootNodeId: string | null` module-level variable with a `Set<string>` keyed per root node id, so concurrent multi-root rotations don't clobber each other's badge state (RESEARCH.md State of the Art table, SC#6). Follow whatever add/delete/has idiom is already used elsewhere in this file for other Set-based state, if any; otherwise use plain `Set.add`/`Set.delete`/`Set.has`.

**Fix 2 - per-call IndexedDB connection caching:** copy `rotation-state.service.ts`'s `openRotationDB()` caching pattern (a module-level cached-Promise-of-connection idiom) rather than opening a new connection per call.

---

### `crates/sdk/src/rotation/high_water.rs` (`bump_floor`) (MODIFIED - service, CRUD/concurrency)

**Analog (cross-language port target):** `apps/web/src/services/rotation-state.service.ts`'s `idbPut` (TS reference already correctly implementing the max-preserving atomic write - see Shared Patterns).

**Current unsynchronized code (L114-127 per research):**
```rust
async fn bump_floor<S: HighWaterStore>(store: &S, node_id: &str, candidate: i64) -> u64 {
    let current = read_floor(store, node_id).await;   // gap: no lock spans read..put
    if !is_valid_floor_value(candidate) { return current.unwrap_or(0); }
    let candidate_u64 = candidate as u64;
    match current {
        Some(cur) if candidate_u64 <= cur => cur,
        _ => { store.put(node_id, candidate_u64).await; candidate_u64 }
    }
}
```

**Fix direction (per RESEARCH.md Assumption A3):** push the atomicity fix DOWN into `JsonSidecarFloorStore::put` (the concrete store), not up into this orchestration-layer `bump_floor`. This function's non-atomic read-then-write remains an "abstract orchestration" layer whose safety is provided by the store's own internal max-preserving write, exactly matching how TS's `idbPut` is the correct layer (not an abstract `bumpFloor` utility above it).

---

### `crates/sdk/src/floor_store.rs` (`JsonSidecarFloorStore`) (MODIFIED - store, file-I/O/concurrency)

**Cross-language analog to port:** `apps/web/src/services/rotation-state.service.ts`'s `idbPut` (L90-111, ALREADY correct):
```typescript
function idbPut(storeName: string, nodeId: string, value: number): Promise<void> {
  return openRotationDB().then((db) => new Promise<void>((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');   // single atomic transaction
    const store = tx.objectStore(storeName);
    const readBack = store.get(nodeId);                   // read INSIDE the same transaction
    readBack.onsuccess = () => {
      const existing = readBack.result as unknown;
      const floor = isValidFloorValue(existing) ? Math.max(existing, value) : value;  // max-preserving
      store.put(floor, nodeId);
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  }));
}
```

**Rust port pattern:** hold a `tokio::sync::Mutex` for the whole load-modify-write critical section of `JsonSidecarFloorStore::put`, with the blocking filesystem read/write calls wrapped in `tokio::task::spawn_blocking` (matching the existing `WriteQueue` sidecar convention already present elsewhere in `crates/sdk`, per research's Don't-Hand-Roll table). Compute `max(existing, candidate)` at write time inside the locked section - not relying on the caller's outer `bump_floor` read.

**Corrupt-sidecar fail-closed:** on JSON parse failure of the sidecar contents, return an explicit `Err` (fail-closed), never `unwrap_or_default()` (which silently resets to a cold-start state - a Tampering-class regression per RESEARCH.md's threat table).

## Shared Patterns

### Cross-language atomic max-preserving write (SC#5)

**Source:** `apps/web/src/services/rotation-state.service.ts` L90-111 (`idbPut`) - already correct, TS side needs no change.

**Apply to:** `crates/sdk/src/floor_store.rs`'s `JsonSidecarFloorStore::put` (Rust port, `tokio::sync::Mutex` + `spawn_blocking`, computing `max(existing, candidate)` inside the locked critical section).

### Terminal-owner zeroization discipline (SC#6, project-wide)

**Source:** existing zeroization call sites in `packages/sdk-core/src/__tests__/rotation/engine.test.ts` (~L324-368 zeroization-invariant describe block) and elsewhere in `client.ts`.

**Apply to:** `packages/sdk/src/client.ts`'s `performScopeExitRotation` (new zero of `rotationResult.readKey`) and `packages/sdk-core/src/rotation/engine.ts`'s dirty-resume-republish return path (must return a fresh copy, never alias caller-owned buffers). Every such change must ship with a paired unit test asserting both "IS zeroed by its new terminal owner" and "any buffer that must NOT be zeroed is unchanged."

### Outer-scope merge-result capture idiom

**Source:** `packages/sdk-core/src/folder/registration.ts`'s existing `currentWriteChildren` outer-scope capture inside its `publishWithCas` merge closure.

**Apply to:** `packages/sdk-core/src/rotation/engine.ts`'s `rotateOne` (new `mergedChildrenForReturn` capture, same idiom).

### Rust sidecar Mutex + spawn_blocking convention

**Source:** `crates/sdk`'s existing `WriteQueue` sidecar durability convention (file referenced but not read this session - locate via `grep -rn "spawn_blocking" crates/sdk/src` during planning).

**Apply to:** `crates/sdk/src/floor_store.rs`'s `JsonSidecarFloorStore` load-modify-write critical section.

## No Analog Found

None - all 10 classified files/changes have a concrete in-repo or cross-language analog identified above.

## Metadata

**Analog search scope:** `packages/sdk-core/src/rotation/`, `packages/sdk-core/src/folder/`, `packages/sdk-core/src/__tests__/`, `packages/sdk/src/state/`, `packages/sdk/src/client.ts`, `apps/web/src/services/`, `crates/sdk/src/`
**Files scanned:** 0 additional (all excerpts sourced directly from 70-RESEARCH.md's verified-against-live-code Code Examples and Architecture Patterns sections per this session's read-only/no-duplicate-reads constraint)
**Pattern extraction date:** 2026-07-07
