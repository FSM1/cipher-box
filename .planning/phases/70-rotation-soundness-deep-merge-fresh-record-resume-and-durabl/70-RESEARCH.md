# Phase 70: Rotation Soundness — Deep Merge, Fresh-Record Resume, and Durable Floor Concurrency - Research

**Researched:** 2026-07-07
**Domain:** Read-key rotation engine soundness (TypeScript `packages/sdk-core`/`packages/sdk` + Rust `crates/sdk`), IndexedDB/JSON-sidecar concurrency
**Confidence:** HIGH (all findings grounded in current code, line-referenced; two genuinely open design gray areas flagged LOW and marked BLOCKED below)

## Summary

This is a debt-closure phase: six Success Criteria (SC#1–SC#6), each traceable to one of five locked todos and the crash-recovery model in `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §4.5. There is no CONTEXT.md; the todos are the design record. All six SCs are buildable now, with two important nuances the planner must account for:

1. **SC#1 (concurrent-add merge) has TWO call sites, not one.** The todo names `mergeConcurrentChildren` (engine.ts), but the *actual* bug reproduced by e2e test 3 fires through **`updateFolderMetadataAndPublish`'s own inline `merge` callback** (`packages/sdk-core/src/folder/registration.ts`) — the D-09 batched parent republish, which is the generic function used by every rotation AND every non-rotation folder mutation. Both sites currently delegate to the same remote-wins `mergeChildren` (`folder/merge.ts`). Fixing only `mergeConcurrentChildren` would not fix the actual e2e-reproducible bug.
2. **SC#3's "Phase 68 durable floor now supplies this" claim is only half true.** `rotation-high-water.ts` persists *generation/seq floor numbers* (an anti-rollback gate), never key material. It does **not** solve "recover the root's readKey after a crash where no in-memory copy survives." The real, buildable scope of SC#3 is narrower than the phase description implies — flagged as an open gray area below (Open Question 1), not silently assumed solved.

**Primary recommendation:** Add a new `packages/sdk-core/src/rotation/merge.ts` exporting `mergeRotatedChildren(base, local, remote)` (local-wins-on-conflict + remote-only-additions + base-only-omissions dropped); use it in `mergeConcurrentChildren`; add an optional injectable conflict-policy to `updateFolderMetadataAndPublish` (default unchanged, remote-wins) and pass the new policy explicitly from the two D-09 batched-republish call sites inside `rotateReadFromNode`. Do not touch `mergeChildren`'s default.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Rotation walk logic (merge, verify, resume, grant re-mint) | SDK / API tier (`packages/sdk-core`) | — | Host-agnostic pure logic; no FUSE/Tauri/web import (D-02) |
| Rotation job checkpoint UX (badge, IndexedDB job store) | Frontend Server / Client (`apps/web`) | — | Thin, untested glue over the SDK seam (D-02/D-03) |
| Anti-rollback floor persistence (web) | Browser / Client (IndexedDB) | SDK (`packages/sdk`) orchestration | Storage lives in the browser; monotonic-max logic lives in the SDK (no in-instance cache) |
| Anti-rollback floor persistence (desktop) | Database / Storage (JSON sidecar on local disk) | Rust SDK (`crates/sdk`) orchestration | FUSE single-daemon model; sidecar mirrors `WriteQueue`'s durability convention |
| Grant re-mint (ECIES re-wrap) | API / Backend (grant rows) via injected callbacks | SDK (compute-only) | DB mutation is host-injected; SDK only computes the wrapped bytes |
| Test coverage (crash-safety proof) | sdk-e2e (cross-package, live API) | Unit (sdk-core/sdk vitest, Rust `#[tokio::test]`) | Only sdk-e2e exercises the real client→API IPNS round trip |

## Package Legitimacy Audit

Not applicable — this phase adds zero new external dependencies. All work is internal to `packages/sdk-core`, `packages/sdk`, `apps/web`, and `crates/sdk`, using primitives already in the dependency tree (`tokio::sync::Mutex`, `tokio::task::spawn_blocking` — both already transitive deps of `crates/sdk` via `tokio`).

## User Constraints

No `CONTEXT.md` exists for this phase (confirmed: `.planning/phases/70-.../*-CONTEXT.md` absent). Per the phase brief, the five locked todos ARE the authoritative design record and function as locked decisions:

### Locked (from the five todos + phase description)
- SC#1 fix must be **local-wins for conflicts + remote-only adds included + base-only-omitted-from-both dropped**. Do NOT change `folder/merge.ts`'s `mergeChildren` remote-wins default — that policy is correct for the unrelated folder-state-desync use case.
- SC#2: `verifySubtreeClean` must recurse the FULL subtree (not just immediate children); a missing root record must be treated as dirty/surfaced, never silently "clean."
- SC#3: fresh-record resume (empty `completedNodeIds`) must be wired; `rotateOne` must return the MERGED children (including remote adds) so they get enqueued; a missing job record must not silently desync `pendingChildCount`.
- SC#3 wording correction (from the 2026-06-29 todo, itself already accepted by the ROADMAP per Phase 64's shipped SC#4): crash recovery converges via safe **double-rotation**, per design §4.5 — NOT "never double-bump." Do not over-constrain against this.
- SC#4: `grantCallbacks`/`innerGrants` must thread through `RotationParams` → `rotateReadFromNode` → every `rotateOne` call site so `reMintGrantsRootedAt` is reachable in the real (non-test) walk.
- SC#5: TS and Rust floor-store fixes MUST remain behaviorally equivalent — apply parity on both sides or neither.
- SC#6: zeroize rotation readKey source buffers at the terminal owner; no module-global `activeRootNodeId` leaking across concurrent roots.
- Zeroization discipline (project-wide, security-critical): a **callee must never zero a caller-supplied/reused buffer**; only the terminal owner zeroes. The 48/89 sdk-e2e regression is the canonical cautionary precedent — flag every zeroization change in review.
- CipherBox terminology, string-literal-over-enum convention, zero-knowledge boundary (server never sees plaintext/unwrapped keys) — from `./CLAUDE.md`.

### Claude's Discretion (no locked answer in the todos)
- Exact shape of the SC#1 fix (new `rotation/merge.ts` file vs `localWins` flag on `mergeChildren` vs branch inline) — the todo explicitly leaves this open ("Either add a rotation-specific merge... or branch the policy... Do NOT change the generic default").
- Exact API shape for threading a rotation-specific conflict policy through `updateFolderMetadataAndPublish` (new optional param vs a separate rotation-only wrapper function).
- Exact Rust locking primitive for `JsonSidecarFloorStore` (`tokio::sync::Mutex<()>` vs per-node sharding) — todo says "e.g. `tokio::sync::Mutex`", not mandated.
- Whether `reconcileFolderSequence`'s cached-generation gap (item 5, 2026-07-02 todo) is fixed by threading the resolved generation (extra fetch+unseal cost) or by explicit contract documentation — todo presents both as options.

### Deferred Ideas (OUT OF SCOPE for this phase)
- WRITE-plane grant re-mint / live `shares` transport cutover beyond what's needed to satisfy SC#4's threading requirement (full live wiring is Phase 66's job — SC#4 here only needs the plumbing to exist and be *reachable*, not a live API implementation).
- Lazy rotation walk (rotate-on-next-write) — explicitly deferred per design §4.8, CAP-03.
- Per-file "re-encrypt now" / purge-history (CAP-02).
- Any change to `mergeChildren`'s remote-wins default for non-rotation callers.

## Phase Requirements

phase_req_ids is null for this phase (todo-driven, not REQ-driven — confirmed no ROT-08+ entries exist in `.planning/REQUIREMENTS.md`; ROT-01 through ROT-07 are already marked Complete). No requirements table applies; the six Success Criteria in the phase description function as the requirement set and are traced throughout this document instead.

## Standard Stack

No new libraries. This phase is entirely internal refactoring/hardening of existing modules:

| Component | Language | Already a dependency? |
|-----------|----------|------------------------|
| `tokio::sync::Mutex` | Rust | Yes — `tokio` is already a `crates/sdk` dependency (used throughout `#[tokio::test]`) |
| `tokio::task::spawn_blocking` | Rust | Yes — same crate |
| `structuredClone` / manual `Uint8Array` copy | TypeScript | Built-in |
| IndexedDB native multi-store transactions | Browser | Built-in Web API, already used by `rotation-state.service.ts`'s `idbPut` |

**Version verification:** N/A — no new package installs. `Cargo.toml`/`package.json` are unchanged by this phase's scope.

## Architecture Patterns

### System Architecture Diagram

```
        (owner client — web or FUSE/Tauri)
                    |
      mutation trigger (delete / move-out / rename-over / revoke)
                    |
                    v
      performScopeExitRotation (client.ts)
        - reads rootReadKey from folderTree (current, in-memory)
        - builds a FRESH RotationJobRecord (completedNodeIds: new Set())
        - injects rotationCallbacks.persistJob -> rotation-driver.service.ts
                    |
                    v
      rotateReadFromNode (engine.ts) -- ENTRY GATE (SC#2/#3 target) --+
        |                                                             |
        +- rootResult.skipped === false -> fresh rotateOne(root)      |
        |     (unseal fails => AEAD error if root already rotated     |
        |      in a lost prior run -- see Open Question 1)            |
        |                                                             |
        +- rootResult.skipped === true  -> verifySubtreeClean (SC#2) -+
              - today: 1 level deep, missing root record => "clean" <-- WRONG
              - target: full recursive walk, missing root => dirty/throw
                    |
                    v
      BFS frontier walk (per node): rotateOne
        - CAS-409 on the node's OWN publish -> mergeConcurrentChildren (SC#1 site A)
        - D-09 batched parent republish -> updateFolderMetadataAndPublish
              CAS-409 -> inline merge callback -> mergeChildren (SC#1 site B -- THE
              site test 3 actually exercises)
        - innerGrants/grantCallbacks (SC#4) -> reMintGrantsRootedAt
              (currently UNREACHABLE outside unit tests -- no wiring in
               RotationParams/rotateReadFromNode)
                    |
                    v
      publishWithCas (cas.ts) -> IPNS CAS publish (server-side forward-only
      sequence gate) -> IPFS content-addressed storage
                    |
                    v
      rotateReadFromNode returns RotateReadResult | undefined (SC#6 target:
      caller must zero the returned readKey after copying)
                    |
                    v
      performScopeExitRotation refreshes folderTree, zeroes old key
      (SC#6 gap: never zeroes rotationResult.readKey itself)


        (durable anti-rollback floor -- parallel, read-path gate)
      resolveIpnsRecord (web) / listing.rs (FUSE)
                    |
                    v
      RotationHighWater.enforceResolved / enforce_resolved  (SC#5 target)
        |                                    |
        v                                    v
   HighWaterStore (TS)                 HighWaterStore (Rust)
   IndexedDB via rotation-state         JsonSidecarFloorStore
   .service.ts -- idbPut ALREADY        get/put -- NOT locked, blocking fs
   max-preserving in ONE transaction    I/O inside async fn (SC#5 gap)
```

### Recommended Project Structure (new/changed files only)
```
packages/sdk-core/src/rotation/
├── engine.ts          # CHANGED — merge-return threading, verifySubtreeClean
│                       #   recursion, grantCallbacks threading, dirty-resume
│                       #   result surfacing
├── merge.ts            # NEW — mergeRotatedChildren (local-wins/add/drop)
└── index.ts             # export mergeRotatedChildren if publicly needed

packages/sdk-core/src/folder/
├── merge.ts             # UNCHANGED — remote-wins default preserved
└── registration.ts      # CHANGED — optional injectable conflict policy on
                          #   updateFolderMetadataAndPublish, default unchanged

packages/sdk/src/state/
└── rotation-high-water.ts  # possibly CHANGED — SC#5 TS-side parity note
                              #   (see SC#5 section — likely NO change needed,
                              #   fix lives in the concrete store adapter)

apps/web/src/services/
├── rotation-driver.service.ts  # CHANGED — Set<rootNodeId>, cached IDB conn
└── (client.ts is in packages/sdk/src, not apps/web)

crates/sdk/src/
├── floor_store.rs       # CHANGED — tokio::sync::Mutex + spawn_blocking +
│                          #   fail-closed corrupt-sidecar signal
└── rotation/high_water.rs  # possibly unchanged if locking pushed to the store
```

### Pattern 1: Rotation-specific three-way merge, isolated from the generic policy
**What:** `mergeRotatedChildren(base, local, remote)` — new function, NOT a flag on `mergeChildren`.
**When to use:** Only inside rotation's own CAS-409 handling paths (both `mergeConcurrentChildren` and the D-09 batched-republish call from `rotateReadFromNode`).
**Why not a flag on `mergeChildren`:** `mergeChildren` is consumed by every folder mutation (add/move/rename) via `updateFolderMetadataAndPublish`'s default; overloading its signature with a policy flag risks a caller passing the wrong flag by accident (silent security regression — a revoked reader's downgrade would look like ordinary folder-state desync). A separate, rotation-owned function makes the local-wins policy syntactically impossible to invoke from a non-rotation call site.
**Example (recommended shape):**
```typescript
// packages/sdk-core/src/rotation/merge.ts (NEW)
// Source: derived from folder/merge.ts's existing shape + the SC#1 todo's literal rule.
import type { SealedChildRef } from '@cipherbox/core';

/**
 * Rotation-only three-way merge: LOCAL WINS on conflict (preserves the D-02
 * re-seal), remote-only (not-in-base) entries are concurrent adds (included,
 * still under their pre-rotation seal — picked up, not re-keyed, per design
 * §4.5 step 5), base-only (not in local AND not in remote) entries are
 * intentional deletes (dropped).
 *
 * NEVER use this for non-rotation folder mutations — see folder/merge.ts's
 * mergeChildren (remote-wins) for the generic policy.
 */
export function mergeRotatedChildren(
  base: SealedChildRef[],
  local: SealedChildRef[],
  remote: SealedChildRef[]
): SealedChildRef[] {
  const baseNames = new Set(base.map((c) => c.ipnsName));
  const merged = new Map<string, SealedChildRef>();
  // Remote-only (concurrent add, not in base) — included first so local can override.
  for (const child of remote) {
    if (!baseNames.has(child.ipnsName)) merged.set(child.ipnsName, child);
  }
  // Local wins for everything local has (rotation's own re-sealed / unchanged set).
  for (const child of local) merged.set(child.ipnsName, child);
  return Array.from(merged.values());
}
```
See Common Pitfalls below for the concurrent-delete-during-rotation edge case this rule set does not resolve.

### Pattern 2: Injectable conflict policy on the shared publish helper (SC#1 site B)
**What:** Add an optional `mergeChildrenFn` parameter to `updateFolderMetadataAndPublish` (registration.ts), defaulting to today's `mergeChildren` (unchanged for all non-rotation callers: add/move/rename in client.ts and elsewhere).
**When to use:** The two D-09 batched-republish call sites inside `rotateReadFromNode` (engine.ts ~L1042 and ~L1110) pass `mergeChildrenFn: mergeRotatedChildren` explicitly.
**Coupled fix (SC#1 ↔ SC#3):** Also pass `baseChildren` at those two call sites — currently omitted (`baseData` ends up `undefined` → `mergeChildren(base ?? [], ...)` defaults `base` to `[]`, silently defeating the intentional-delete branch and, more importantly, meaning `mergeRotatedChildren`'s "remote-only-vs-base" check degrades to "everything remote is treated as a concurrent add" — harmless for the add case this phase targets, but worth fixing precisely since it's a one-line capture). Snapshot the parent's children array at `parentTracking.set(...)` time (before any child-driven mutation) into a new `baseChildrenSnapshot: SealedChildRef[]` field on `ParentTrackingState`, and pass it as `baseChildren` to `updateFolderMetadataAndPublish`.
**Consume the returned merged children (SC#1 ↔ SC#3 coupling):** `updateFolderMetadataAndPublish` already returns `publishedChildren` (the CAS-merged result) — currently ignored by both D-09 call sites. After the call, diff `result.publishedChildren` against the pre-call `parentState.children` snapshot by `ipnsName`; any entry present in `result.publishedChildren` but absent from the pre-call snapshot is a concurrently-added child that must be pushed onto the BFS `queue` (deriving its readKey via `unsealChildReadKey` against the PARENT's now-current key, exactly like the existing root/child enqueue blocks) so it gets its own `rotateOne` pass — otherwise the concurrent add survives in the parent's body but is never itself rotated, and (per design §4.5 step 5) that's acceptable for ONE rotation cycle (it's picked up, full re-key is a follow-on) but must not be silently forgotten from the walk's `completedNodeIds`/frontier bookkeeping.

### Pattern 3: `rotateOne`'s own CAS-409 merge must return plaintext merged children (SC#1 site A ↔ SC#3)
**What:** `rotateOne`'s final `return` (engine.ts L730-737) always uses `children: node.children ?? []` — the PRE-merge snapshot — even when the `merge` closure passed to `publishWithCas` (which calls `mergeConcurrentChildren`) ran and produced a different, merged set of children.
**Fix:** Capture the merged plaintext children in an outer-scope `let mergedChildrenForReturn: SealedChildRef[] | undefined` inside `rotateOne`'s CAS-409 `merge` closure (mirroring `registration.ts`'s existing `currentWriteChildren` capture pattern), and at the final `return`, use `mergedChildrenForReturn ?? node.children ?? []`.
**Example:**
```typescript
// packages/sdk-core/src/rotation/engine.ts — rotateOne, inside the publishWithCas call
let mergedChildrenForReturn: SealedChildRef[] | undefined;
// ...
merge: async (base, _local, remote) => {
  if (!base) { /* unchanged fallback */ }
  const mergedPublished = await mergeConcurrentChildren(/* ... */);
  // mergeConcurrentChildren must ALSO expose the plaintext merged children,
  // not just the re-sealed PublishedNode — e.g. return { published, mergedChildren }.
  mergedChildrenForReturn = mergedPublished.mergedChildren;
  return { merged: mergedPublished.published };
},
// ...
return {
  skipped: false,
  // ...
  children: mergedChildrenForReturn ?? node.children ?? [],
  newSequenceNumber: casResult.newSequenceNumber,
};
```
`mergeConcurrentChildren`'s signature needs a small return-shape change (`Promise<{ published: PublishedNode; mergedChildren: SealedChildRef[] }>` instead of `Promise<PublishedNode>`) — a mechanical, low-risk change; update its one call site and its unit tests (`engine.test.ts`'s "CAS-409 concurrent-add merge" describe block, ~L1106-1334) accordingly.

### Anti-Patterns to Avoid
- **Adding a `localWins: boolean` flag directly to `mergeChildren`:** violates the todo's explicit "do NOT change the generic default" instruction and creates a callable footgun for future non-rotation callers.
- **Recursing `verifySubtreeClean` by re-implementing key derivation ad hoc:** duplicates the BFS's `unsealChildReadKey`/`resolveAndFetch` logic with subtly different bugs. Prefer extracting a small shared internal helper (`resolveChildKey(parentReadKey, childRef, childPub)`) used by both the main BFS and the recursive verify walk.
- **Zeroing `RotateReadResult.readKey` inside the engine:** violates D-09 terminal-owner discipline and the explicit precedent that caused the 48/89 sdk-e2e regression. The zero must happen in `client.ts`, after the defensive copy, never inside `engine.ts`.
- **Returning `params.rootReadKey` (caller-owned) directly as `RotateReadResult.readKey` on the dirty-resume-republish path:** if the caller then zeroes the returned buffer (per the SC#6 fix), and the returned buffer is literally the same object as the caller's OWN live key reference (e.g., aliased into `folderTree`), that zero silently corrupts the caller's live state. Always return a **fresh copy** (`new Uint8Array(rootReadKey)`) on this specific path — see Common Pitfalls.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Cross-tab/cross-request IndexedDB write serialization for a single key | A custom mutex over `localStorage`/`BroadcastChannel` | A single IndexedDB `readwrite` transaction that reads-back-and-maxes before `put` (the existing `idbPut` pattern in `rotation-state.service.ts`) | IndexedDB transactions are already atomic per-database; reinventing locking on top is both slower and less correct |
| Rust cross-async-task mutual exclusion for the sidecar file | A custom spin-lock or file-lock (`flock`) | `tokio::sync::Mutex<()>` held for the whole load+modify+write critical section, with the blocking fs calls inside `spawn_blocking` | Matches the existing `WriteQueue` sidecar convention already in the crate; `flock` adds cross-process semantics the single-daemon model doesn't need and complicates testing |
| ECIES re-wrapping for grant re-mint | Custom asymmetric crypto | `wrapKey` from `@cipherbox/crypto` (already used by `reMintGrantsRootedAt`) | Unchanged by this phase — flagged here only because SC#4 threads the SAME seam into more call sites; no new crypto primitive needed |

**Key insight:** every "hand-roll" risk in this phase is actually a **wiring/threading** problem (get an existing correct primitive to run in more places), not a "build new crypto/locking" problem. The Rust `tokio::sync::Mutex` + `spawn_blocking` combination and the TS read-modify-write-in-one-IDB-transaction pattern are both already present elsewhere in this codebase — reuse the pattern, don't invent a new one.

## Common Pitfalls

### Pitfall 1: SC#1 fix applied only to `mergeConcurrentChildren`, missing the D-09 site
**What goes wrong:** `rotation-crash-safety.test.ts` test 3 continues to pass falsely (it only asserts child NAMES are present) while the actual downgrade (subfolder3's `readKeySealed` reverting to the pre-D-02 seal) still occurs, because the CAS-409 test 3 actually exercises fires inside `updateFolderMetadataAndPublish`'s inline merge, not `mergeConcurrentChildren`.
**Why it happens:** The todo names only `mergeConcurrentChildren` by file/function; the D-09 batched-republish path (`registration.ts`) is a separate, generic function shared with non-rotation mutations, easy to overlook when scoping the fix to "the rotation file."
**How to avoid:** Treat Pattern 2 (injectable conflict policy on `updateFolderMetadataAndPublish`, with the two D-09 call sites in `rotateReadFromNode` explicitly opted in) as a REQUIRED part of the SC#1 plan, not optional hardening.
**Warning signs:** If the strengthened e2e test 3 (navigate into `sub3IpnsName` and unseal with the new root key) still fails after fixing only `mergeConcurrentChildren`, this is the missed site.

### Pitfall 2: Concurrent-delete-during-rotation resurrection (accepted gray area)
**What goes wrong:** `mergeRotatedChildren`'s literal rule ("local wins for everything present in local") means: if a concurrent writer DELETES an existing child from the parent at the exact moment rotation is mid-walk on that same parent, rotation's local copy (which still includes the deleted child, since rotation itself never removes children) wins the merge and the deleted child is RESURRECTED in the merged result.
**Why it happens:** The todo's three rules are asymmetric by design — rule 1 ("local wins") is unconditional and listed first; rule 3 ("base-only-in-both-omitted = delete") only fires for entries ABSENT from local, which a rotation's own children list never produces (rotation doesn't structurally mutate membership).
**How to avoid:** This is not fully resolvable within this phase's stated rules without re-litigating the design (which the phase brief explicitly says NOT to do — "NOT to redesign"). Document it explicitly as an accepted, self-healing residual: the concurrent delete's OWN publish attempt will itself hit a later CAS conflict against the resurrected entry and can re-delete it on its own retry, OR the next owner-driven mutation on that parent naturally re-establishes the delete. Flag this precisely in the plan's Open Questions / VERIFICATION.md so it isn't silently treated as fully solved.
**Warning signs:** A test that deletes a child concurrently with a rotation and asserts the delete "sticks" immediately (rather than eventually) will fail — that's expected given this design boundary, not a regression.

### Pitfall 3: `verifySubtreeClean` recursion needs readKeys, not just names — breaks the existing dirty-resume caller contract
**What goes wrong:** Today's caller (`rotateReadFromNode`'s dirty-resume block, engine.ts ~L938-964) derives each frontier item's readKey by looking it up directly in `rootNode.children` (only works because today's frontier is always an IMMEDIATE child of root). Naively recursing `verifySubtreeClean` without changing its RETURN SHAPE breaks this lookup for any dirty node deeper than depth 1 — the caller has no way to derive a grandchild's readKey from `rootReadKey` alone.
**Why it happens:** Recursion changes what "the frontier" can contain (any depth), but the consumer contract was written assuming depth-1-only.
**How to avoid:** `verifySubtreeClean` must be restructured to perform its OWN key-derivation walk (same `unsealChildReadKey` mechanism as the main BFS) as it recurses, and its return type must carry enough to seed the BFS queue directly per dirty node: `{ ipnsName, nodeId, parentIpnsName, nodeReadKey (this node's own pre-rotation readKey, engine-derived), childPubKind, enqueuedGeneration }` — essentially the same shape as the BFS `queue` items. This is the single largest implementation lift in the phase; budget accordingly. Consider extracting a shared internal traversal helper used by both `verifySubtreeClean` (read-only) and the main walk (mutating), parameterized by a per-node visitor callback, to avoid duplicating the key-chain-walk logic twice with two independently-maintained bug surfaces.
**Warning signs:** Any implementation where `verifySubtreeClean`'s frontier items are just `{ ipnsName, nodeId }` (today's shape) cannot support depth > 1 without the caller re-deriving keys some other way — treat this signature as a hard blocker for SC#2's "full subtree" requirement.

### Pitfall 4: The "genuinely lost root key" scenario has no cryptographic recovery — don't silently pretend it does
**What goes wrong:** If a crash occurs strictly between "root's rotateOne CAS-publish succeeds (root now sealed under readKeyPrime)" and any durable persistence of that NEW key (the durable job checkpoint in `rotation-driver.service.ts` explicitly NEVER persists key material — "Pitfall 4 / T-68-83"), and the resuming session's `folderTree` also never got refreshed (because `performScopeExitRotation`'s `rotationResult` assignment never completed — the call threw), then NO party holds the current root readKey. `rotateOne(root)`'s unconditional `unsealNode(publishedRoot, rootReadKey)` (step 3) AEAD-fails and there is no cryptographic path forward for THAT specific node using ONLY the information available client-side in this exact window.
**Why it happens:** The durable floor (`rotation-high-water.ts`) intentionally stores only generation/seq NUMBERS (an anti-rollback gate), never keys — this is a deliberate zero-knowledge-adjacent security boundary (durable, disk-persisted key material would be a bigger attack surface), not an oversight. The ORIGINAL 2026-06-29 todo's scope-boundary text ("the M1 durable client floor ({nodeId → highestGeneration} **+ the minted keys**)") appears to have assumed key persistence would ALSO ship in Phase 68 — it did not.
**How to avoid:** Do not implement (or claim) a fix that "recovers" the key from the floor store — there is none to recover. Instead, scope SC#3's fresh-record resume to the cases that ARE solvable: (a) the caller always supplies a CURRENTLY-VALID `rootReadKey` (the common case — verified in Open Question 1 below for typical scope-exit rotations, where the root's real ancestor's SealedChildRef mirror is a separate, already-solved concern), and (b) `completedNodeIds` being empty must not, by itself, prevent `verifySubtreeClean`-driven dirty-tail recovery — i.e., the entry gate must be restructured to probe root-unseal viability rather than branch on `completedNodeIds.size`. See Open Question 1 for the precise restructuring recommendation and its residual limitation.
**Warning signs:** A plan or test that seeds a "fresh" resume by RE-DERIVING the post-crash root key out of thin air (rather than treating that scenario as an explicit, documented failure mode requiring a full top-down folderTree re-walk from the vault root) is silently assuming a capability that doesn't exist.

### Pitfall 5: Callee-zeroes-shared-buffer regression class (SC#6)
**What goes wrong:** Any zeroization change in `engine.ts` or `client.ts` that zeroes a buffer the CALLER still needs (e.g., zeroing `parentReadKey`, or zeroing the dirty-resume-republish path's `readKey` if it is accidentally the SAME object as `params.rootReadKey` rather than a defensive copy — see Anti-Patterns above) reproduces the exact regression class that broke 48/89 sdk-e2e once before.
**Why it happens:** Terminal-ownership discipline is easy to violate when a buffer is returned across a function boundary without a copy, especially when refactoring a return-value shape (exactly what SC#3's dirty-resume-result fix requires).
**How to avoid:** Every zeroization change added or moved in this phase must be paired with an explicit unit test asserting (a) the buffer IS zeroed by its new terminal owner, and (b) any buffer that must NOT be zeroed (parent-owned, caller-owned) is unchanged after the call — mirroring the existing pattern in `engine.test.ts`'s "zeroization invariant" describe block (~L324-368).
**Warning signs:** Any `fill(0)` call added without a comment identifying WHO owns the buffer and WHY this call site is the terminal owner is a red flag in review.

## Code Examples

### `mergeConcurrentChildren`'s current base/local/remote triple (verified against live code)
```typescript
// Source: packages/sdk-core/src/rotation/engine.ts L451-477 (current, remote-wins via mergeChildren)
export async function mergeConcurrentChildren(
  basePub: PublishedNode,
  remotePub: PublishedNode,
  oldReadKey: Uint8Array,
  localChildren: SealedChildRef[],   // = node.children from rotateOne's closure — PRE-rotation
                                       // children (rotation never mutates membership)
  newReadKey: Uint8Array,
  localNode: Node,
  generationPrime: number,
  writeKey: Uint8Array
): Promise<PublishedNode> {
  const baseNodeDecoded = await unsealNode(basePub, oldReadKey);
  const remoteNodeDecoded = await unsealNode(remotePub, oldReadKey);
  const mergedChildren = mergeChildren(          // <-- SC#1 fix: swap for mergeRotatedChildren
    baseNodeDecoded.children ?? [],
    localChildren,
    remoteNodeDecoded.children ?? []
  );
  const mergedNode: Node = { ...localNode, generation: generationPrime, children: mergedChildren };
  return sealNode(mergedNode, newReadKey, writeKey);
}
```

### `updateFolderMetadataAndPublish`'s inline merge — the ACTUAL SC#1 site test 3 exercises
```typescript
// Source: packages/sdk-core/src/folder/registration.ts L304-320 (current)
merge: (base, local, remote) => {
  if (params.writeKey) { /* write-body union, unaffected by SC#1 */ }
  return { merged: mergeChildren(base ?? [], local, remote) };  // <-- SC#1 fix site B
},
```

### `verifySubtreeClean`'s current depth-1-only implementation
```typescript
// Source: packages/sdk-core/src/rotation/engine.ts L491-524 (current)
export async function verifySubtreeClean(
  rootIpnsName: string,
  rootReadKey: Uint8Array,
  ctx: SdkContext
): Promise<{ isDirty: boolean; frontier: Array<{ ipnsName: string; nodeId: string }> }> {
  const rootResolved = await resolveIpnsRecord(rootIpnsName, ctx);
  if (!rootResolved) return { isDirty: false, frontier: [] };   // <-- SC#2 fix: must NOT be "clean"
  // ... unseal root, then ONLY iterate rootNode.children ?? [] — one level, never recurses.
}
```

### Rust `bump_floor`'s current unsynchronized read-compare-write
```rust
// Source: crates/sdk/src/rotation/high_water.rs L114-127 (current)
async fn bump_floor<S: HighWaterStore>(store: &S, node_id: &str, candidate: i64) -> u64 {
    let current = read_floor(store, node_id).await;   // <-- gap: no lock spans read..put
    if !is_valid_floor_value(candidate) { return current.unwrap_or(0); }
    let candidate_u64 = candidate as u64;
    match current {
        Some(cur) if candidate_u64 <= cur => cur,
        _ => { store.put(node_id, candidate_u64).await; candidate_u64 }
    }
}
```

### TS reference: the pattern already correctly implementing the SC#5 fix (port this to Rust)
```typescript
// Source: apps/web/src/services/rotation-state.service.ts L90-111 (current, ALREADY correct)
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
This is the concrete pattern to port to `JsonSidecarFloorStore::put` for SC#5 Rust-side parity: hold a `tokio::sync::Mutex` for the whole load-modify-write, computing `max(existing, candidate)` at write time (not relying solely on the caller's outer `bump_floor` read, which — like TS's abstract `bumpFloor` utility — remains a non-atomic orchestration layer whose safety is provided by the STORE's own internal max-preserving write, not by locking at the `RotationHighWater<S>` level).

## State of the Art

| Old Approach | Current/Target Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `verifySubtreeClean` checks 1 level, "clean" on missing root | Full recursive subtree walk, missing root ⇒ dirty/throw | This phase (SC#2) | Enables genuine fresh-record resume; changes the resume entry-gate contract |
| `rotateOne` returns pre-merge `node.children` | Returns CAS-merged children (incl. remote adds) | This phase (SC#3, coupled with SC#1) | Concurrent adds get enqueued into the BFS, not just preserved in the parent body |
| `grantCallbacks`/`innerGrants` — unit-test-only seam | Threaded through `RotationParams` into the real walk | This phase (SC#4) | `reMintGrantsRootedAt` becomes reachable in production, closing the orphaned-inner-grant gap for real |
| Rust floor store: blocking fs I/O inside `async fn`, no lock | `tokio::sync::Mutex` + `spawn_blocking` | This phase (SC#5) | Non-blocking executor, no lost updates under concurrency |
| `activeRootNodeId: string \| null` (single-root badge tracking) | `Set<string>` (per-root tracking) | This phase (SC#6) | Correct badge state under concurrent multi-root rotations |

**Deprecated/outdated:**
- The `verifySubtreeClean` docstring's "not yet wired here — it needs the Phase-68 durable client floor" comment (engine.ts L487-489) is stale per the phase brief and must be removed/corrected as part of SC#3 — but see Pitfall 4 and Open Question 1 for the precise, narrower scope of what's actually fixable.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | "Phase 68's durable floor now supplies the fresh-resume prerequisite" (phase description's own claim) is only partially true — it supplies the anti-rollback GATE, not key recovery | Pitfall 4, Open Question 1 | If the planner builds SC#3 assuming full key-recovery is possible, the plan will be unimplementable for the true crash-loses-root-key window; scope must be narrowed explicitly with the user/architect |
| A2 | The recommended `mergeRotatedChildren` rule (unconditional local-wins) can resurrect a concurrently-deleted child during a race with rotation | Pitfall 2 | If treated as fully solved rather than an accepted residual, a reviewer may block on it expecting a fix that isn't in scope per the todo's own literal rule ordering |
| A3 | SC#5's Rust fix should be pushed to the `JsonSidecarFloorStore` layer (matching TS's `idbPut` pattern) rather than adding locking at the `RotationHighWater<S>` orchestration layer | SC#5 section, Code Examples | If the planner instead adds a lock inside `RotationHighWater<S>::bump_floor` only, cross-node_id lost-updates in `JsonSidecarFloorStore::put` (a documented separate bug in the 2026-07-07 todo) remain unfixed |
| A4 | The "corrupt sidecar fails closed" requirement in this phase's SC#5 text is an explicit SCOPE ESCALATION beyond the 2026-07-07 todo's own "accepted risk, not a blocker, consider when hardening" framing | SC#5 section | If treated as already-covered by the todo's acceptance, the planner may skip it; the phase description's literal SC#5 wording requires it now |

## Open Questions

1. **Can "fresh-record resume" recover an already-rotated ROOT whose key was lost to a crash, or is that scenario a documented non-goal for this phase?**
   - What we know: The durable floor (`rotation-high-water.ts`/`high_water.rs`) stores only generation/seq NUMBERS. The durable job checkpoint (`rotation-driver.service.ts`) explicitly never persists key material (Pitfall 4/T-68-83). `rotateOne(root)` unconditionally attempts to unseal with the caller-supplied `rootReadKey` — if that key is stale (root rotated in a lost prior run), this AEAD-fails with no recovery path.
   - What's unclear: Whether the phase author intended SC#3 to cover this exact window, or whether "fresh-record resume" more narrowly means "a resume call where `rootReadKey` IS still current (the common same-session-retry / re-triggered-mutation case), but `completedNodeIds` happens to be empty" — i.e., removing the `completedNodeIds`-emptiness gate on `verifySubtreeClean`, not solving key loss.
   - Recommendation: The planner should restructure `rotateReadFromNode`'s entry logic to attempt a READ-ONLY unseal probe of the current root record with the supplied `rootReadKey` BEFORE deciding whether to run `rotateOne(root)` fresh or fall into the dirty-tail-only path — regardless of `completedNodeIds.size`. If the probe unseal fails, surface a distinct, actionable error (e.g. `RootKeyStaleError`) rather than letting `rotateOne` throw a generic AEAD failure — this lets `client.ts` fall back to a full top-down folderTree re-navigation from the vault root rather than silently failing the mutation. Get explicit confirmation from the user/architect on this narrower scope before planning tasks around it — this is exactly the kind of gray area the phase brief asked research to resolve, and the honest answer is "partially, with a documented residual failure mode," not "yes, fully solved."

2. **Does an OWNER's typical scope-exit rotation (non-vault-root share-root) leave the root's REAL ancestor's `SealedChildRef` mirror stale after rotation, and if so, does that block the normal (non-crash) top-down re-navigation path that Open Question 1's fallback relies on?**
   - What we know: `rotateReadFromNode` never touches the rotation ROOT's own parent link (no `parentTracking` entry is ever seeded for the root's true ancestor — only for nodes BELOW the root). For delete/move-out, design §3.6 says the "unlink/relink" step happens SEPARATELY (composed with rotation) — so the ancestor's link is corrected by the delete/move code path, not by rotation itself.
   - What's unclear: For a PURE revoke (no structural delete/move — the shared node stays exactly where it is in the owner's own tree), does the revoke-grant call path in `client.ts` ALSO re-seal the root's ancestor's `SealedChildRef` entry to the new key? This determines whether Open Question 1's fallback (top-down re-walk from vault root) actually reaches the CURRENT key, or reproduces the same staleness one level up.
   - Recommendation: Trace the actual revoke-grant call path in `client.ts` (search for the caller that invokes `performScopeExitRotation` with a `rootNodeIpnsName` that is NOT structurally moved) during planning, before committing to Open Question 1's fallback design. If the ancestor mirror IS left stale, the fallback is incomplete and the true fix requires rotation to ALSO update its own root's ancestor mirror — a larger change potentially exceeding this phase's "no redesign" mandate, and worth flagging back to the user.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Docker (redis 6380, kubo, postgres) | sdk-e2e live-API tests (Test strategy §7) | Not probed this session (read-only research; do not start services) | — | Plan must instruct the executor to run `docker compose -f docker/docker-compose.yml up -d` + `pnpm --filter @cipherbox/api dev` before the sdk-e2e phase gate, per the test file's own header comment |
| `tokio` (Rust) | SC#5 Rust fix | Yes | Already a `crates/sdk` dependency | — |
| Vitest / cargo test | Unit-level verification | Yes | Already configured (`vitest.config.ts`, `Cargo.toml`) | — |

**Missing dependencies with no fallback:** None — the sdk-e2e stack is a well-established, documented prerequisite (project memory: "SDK integration tests need a local API").

**Missing dependencies with fallback:** None applicable.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework (TS) | Vitest — `packages/sdk-core/vitest.config.ts` (coverage excludes `src/**/index.ts` and `*.test.ts`/`*.spec.ts` — `engine.ts` MUST stay out of any `index.ts` barrel per its own docblock warning) |
| Framework (Rust) | `cargo test` / `#[tokio::test]` — `crates/sdk/src/rotation/high_water.rs` and `crates/sdk/src/floor_store.rs` already have `#[cfg(test)] mod tests` blocks to extend |
| Framework (e2e) | Vitest, live-stack — `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` |
| Config file | `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts` (existing), `crates/sdk/Cargo.toml` (existing) |
| Quick run command (TS unit) | `pnpm --filter @cipherbox/sdk-core test -- rotation/engine` |
| Quick run command (Rust unit) | `cargo test -p cipherbox-sdk rotation::high_water` and `cargo test -p cipherbox-sdk floor_store` |
| Full suite command (sdk-e2e) | `pnpm --filter sdk-e2e test -- rotation-crash-safety` (requires docker stack + API up per file header) |

### Phase Requirements → Test Map
| SC | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|-------------------|-------------|
| SC#1 | Concurrent-add merge preserves rotated child's readKeySealed (local-wins) | unit + e2e | `pnpm --filter @cipherbox/sdk-core test -- folder-merge` (new `merge.test.ts` for `mergeRotatedChildren`) + strengthened e2e test 3 | ✅ `folder-merge.test.ts` exists (extend); ❌ new `rotation/merge.test.ts` — Wave 0 |
| SC#1 | Strengthened e2e: navigate into `sub3IpnsName` and unseal with `readKeyPrimeRoot3` after concurrent-add merge | e2e | `pnpm --filter sdk-e2e test -- rotation-crash-safety` (test 3, extended) | ✅ file exists, extend test 3 |
| SC#2 | `verifySubtreeClean` recurses full subtree; missing root ⇒ dirty | unit | `pnpm --filter @cipherbox/sdk-core test -- rotation/engine` (extend `verifySubtreeClean` describe block, engine.test.ts ~L1502) | ✅ exists, extend |
| SC#3 | `rotateOne` returns merged (incl. remote-added) children | unit | same file, extend CAS-409 describe block (~L1106) with a return-value assertion | ✅ exists, extend |
| SC#3 | Genuine fresh-record resume (empty `completedNodeIds`, no pre-seeded keys) | e2e | new e2e test in `rotation-crash-safety.test.ts` — crash BEFORE all nodes commit (mid-walk, not post-completion), then resume with a brand-new `RotationJobRecord` and the CURRENT valid `rootReadKey` (per Open Question 1's narrowed scope) | ❌ new test — Wave 0 |
| SC#3 | Missing job record does not desync `pendingChildCount` | unit | new test asserting `pendingChildCount` accounting on a simulated missing-record `continue` path | ❌ new test — Wave 0 |
| SC#4 | `grantCallbacks` reaches `reMintGrantsRootedAt` via the public `rotateReadFromNode` path (not just direct `rotateOne` injection) | unit | new test in engine.test.ts calling `rotateReadFromNode` (not `rotateOne` directly) with `grantCallbacks` supplied via `RotationParams` and asserting `queryGrantsFn` was invoked | ❌ new test — Wave 0 |
| SC#5 (Rust) | Concurrent `bump`/`put` on same and different `node_id`s preserve monotonic-max, no lost updates | Rust `#[tokio::test]` concurrency test | `cargo test -p cipherbox-sdk floor_store::tests::concurrent_puts_no_lost_update` (new) | ❌ new test — Wave 0 |
| SC#5 (Rust) | `JsonSidecarFloorStore` performs no blocking I/O on the async executor while holding the lock | Rust — manual review / `tokio::task::spawn_blocking` presence check (no automated perf assertion needed) | static review | N/A |
| SC#5 | Corrupt sidecar fails closed (not `unwrap_or_default`) | Rust unit | new test writing garbage bytes to the sidecar path then asserting `get`/`enforce_resolved` rejects rather than silently cold-starting | ❌ new test — Wave 0 |
| SC#5 (TS parity) | Document/prove TS's `idbPut` already provides the equivalent max-preserving atomic write | manual/doc | N/A — no code change expected on TS side per the recommended design (A3) | N/A |
| SC#6 | `rotationResult.readKey` is zeroed by `performScopeExitRotation` after its defensive copy | unit (packages/sdk client tests) | extend existing client.ts rotation test coverage with a buffer-identity zeroization assertion | Locate via `grep -rn "performScopeExitRotation" packages/sdk/src/__tests__` during planning |
| SC#6 | `activeRootNodeId` → `Set`, badge does not reset until the set drains | unit (apps/web, THIN — per doctrine no new `apps/web/src/*.spec.ts`; test via existing web-e2e badge lifecycle spec, or a light sdk-side simulation if the logic can be extracted testable) | `pnpm --filter web test:e2e -- rotation-ux` (existing 68-10 spec, extend for 2 concurrent roots) | Locate existing 68-10 rotation-ux web-e2e spec during planning |

### Sampling Rate
- **Per task commit:** TS quick unit run (`pnpm --filter @cipherbox/sdk-core test -- rotation`) + `cargo test -p cipherbox-sdk rotation`.
- **Per wave merge:** Full `sdk-core`/`sdk` vitest suite + full `cargo test -p cipherbox-sdk` + sdk-e2e rotation-crash-safety suite (requires docker stack — budget CI time or a local docker round-trip per project memory "SDK E2E is the only cross-package publish gate").
- **Phase gate:** Full sdk-e2e suite green (all 3 existing scenarios + the new genuine-fresh-resume scenario) before `/gsd-verify-work`.

### Wave 0 Gaps
- [ ] `packages/sdk-core/src/rotation/merge.ts` + `packages/sdk-core/src/__tests__/rotation/merge.test.ts` — new file, new tests for `mergeRotatedChildren`.
- [ ] New unit tests in `engine.test.ts` for: merged-children return threading (SC#1↔SC#3), full-recursion `verifySubtreeClean` (SC#2, requires a new multi-level test fixture beyond the existing depth-1 fixtures), `grantCallbacks` reachability via `rotateReadFromNode` (SC#4), `pendingChildCount` accounting on a missing-record path (SC#3).
- [ ] New e2e test in `rotation-crash-safety.test.ts` for genuine fresh-record resume (crash mid-walk, not post-completion — requires a NEW fault-injection point earlier than the existing 4th-persistCallback-call crash).
- [ ] New Rust concurrency tests in `crates/sdk/src/floor_store.rs`'s `#[cfg(test)]` module: concurrent same-node_id `put`, concurrent different-node_id `put`, corrupt-sidecar fail-closed.
- [ ] Locate (via grep during planning, not yet confirmed in this research pass) the existing client-side rotation test file and the 68-10 web-e2e rotation-ux spec, to extend for SC#6's two behaviors.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Unaffected — this phase does not touch login/session |
| V3 Session Management | No | — |
| V4 Access Control | Yes | Grant re-mint (SC#4) and the local-wins merge (SC#1) are both revocation-soundness controls — this phase directly strengthens V4-adjacent guarantees (a revoked reader must not regain access via a merge downgrade or an unreachable re-mint seam) |
| V5 Input Validation | Yes | `isValidFloorValue`/`is_valid_floor_value` fail-closed validation (already present, unchanged this phase) on floor inputs; the SC#5 corrupt-sidecar fix adds a NEW fail-closed validation surface (JSON parse failure must not silently degrade to "no floor") |
| V6 Cryptography | Yes | AES-256-GCM AAD-bound seals (`sealNode`/`unsealNode`, `sealChildReadKey`/`unsealChildReadKey`) — unchanged by this phase, but every merge/return-threading change touches code adjacent to these calls; never hand-roll, always route through the existing `@cipherbox/crypto`/`@cipherbox/core` primitives |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Revoked reader retains access via a merge that downgrades a rotated child's key | Elevation of Privilege | SC#1's local-wins merge (this phase) |
| Anti-rollback floor lost-update under concurrency allows a stale/lower generation to be accepted | Tampering | SC#5's atomic compare-and-set floor store (this phase) |
| Corrupt/tampered floor sidecar silently resets a node to cold-first-contact state, weakening the M1 defense | Tampering | SC#5's fail-closed corrupt-sidecar handling (this phase) — accepted residual: a local-disk attacker able to corrupt the sidecar is already outside the zero-knowledge threat model (ADR 0002) |
| Zeroizing a caller-owned/reused buffer corrupts live application state (not a confidentiality leak, but a correctness/availability regression with security-adjacent blast radius since it lives in rotation code) | Denial of Service (self-inflicted) | Terminal-owner zeroization discipline, unit-tested per buffer (SC#6, Pitfall 5) |
| Malicious relay omits a grant-root from the active-grant-root set, suppressing a revoke | Information Disclosure (residual, accepted per design §3.9) | Client cross-checks its own locally-known grant record (`getLocalGrantRecord`, already implemented) — unaffected by this phase |

## Sources

### Primary (HIGH confidence — read directly from the repository this session)
- `.planning/todos/pending/2026-06-29-rotation-concurrent-add-merge-downgrades-rotated-child-readkey.md` — SC#1 spec
- `.planning/todos/pending/2026-06-29-rotation-fresh-record-resume-and-sc4-double-bump.md` — SC#2/#3 spec
- `.planning/todos/pending/2026-06-29-rotation-coderabbit-followups-deferred.md` — SC#1/#2/#3/#4 refinements
- `.planning/todos/pending/2026-07-02-rotation-hardening-followups-from-pr-review.md` — SC#5/#6 spec
- `.planning/todos/pending/2026-07-07-sdk-floor-store-concurrency-atomicity.md` — SC#5 Rust spec
- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §4.2–§4.7 — crash-recovery/double-rotation model
- `packages/sdk-core/src/rotation/engine.ts` (full file, both halves read) — current implementation, all line references verified against live code this session
- `packages/sdk-core/src/folder/merge.ts`, `packages/sdk-core/src/folder/registration.ts` — the actual SC#1 site-B discovery
- `packages/sdk/src/state/rotation-high-water.ts`, `crates/sdk/src/rotation/high_water.rs`, `crates/sdk/src/floor_store.rs` — TS/Rust floor-store parity analysis
- `apps/web/src/services/rotation-driver.service.ts`, `apps/web/src/services/rotation-state.service.ts` — SC#6/SC#5-TS-parity source
- `packages/sdk/src/client.ts` (L1780-2100 read directly) — `reconcileFolderSequence`, `performScopeExitRotation`
- `packages/sdk-core/src/cas.ts` — `publishWithCas` merge/return contract
- `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` (full file) — existing test coverage and exact fault-injection mechanics
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts`, `packages/sdk/src/__tests__/rotation-high-water.test.ts` — existing unit coverage inventory
- `.planning/REQUIREMENTS.md`, `.planning/config.json` — confirmed no new REQ IDs, confirmed `nyquist_validation: true`

### Secondary (MEDIUM confidence)
- None — this phase required no external web research; all grounding is internal-codebase static analysis per the "no redesign, ground in current code" mandate.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- SC#1/#3 merge-and-return coupling: HIGH — verified against live `engine.ts`, `registration.ts`, `cas.ts` code; the "two merge sites" finding is a direct code read, not an inference.
- SC#2 recursion requirement: HIGH on the problem statement, MEDIUM on the exact recommended return-shape (a reasonable design, not the only possible one — flagged as Claude's Discretion where the todo doesn't mandate a shape).
- SC#3 "durable floor now supplies this" claim: LOW confidence that it is FULLY true — actively contradicted by direct code reading (the floor stores numbers, not keys); presented as Open Question 1, not asserted as solved.
- SC#4 threading: HIGH — confirmed via grep that `grantCallbacks`/`innerGrants` exist ONLY on `RotateOneParams`, never on `RotationParams`, never passed by `rotateReadFromNode`.
- SC#5: HIGH on the Rust-side gap (direct code read of `bump_floor`/`floor_store.rs`); HIGH on the TS-side "already correct" finding (direct code read of `rotation-state.service.ts`'s `idbPut`); MEDIUM on the exact recommended Rust locking API shape (reasonable, matches existing crate conventions, but not the only valid design).
- SC#6: HIGH — both gaps (unzeroed `RotateReadResult.readKey`, module-global `activeRootNodeId`) directly confirmed by code read; the dirty-resume-aliasing landmine (Pitfall 5/Anti-Patterns) is a novel finding from cross-referencing SC#3's dirty-resume-result fix against SC#6's zeroization fix — flag prominently to the planner as a genuinely non-obvious interaction.

**Research date:** 2026-07-07
**Valid until:** 30 days (internal-codebase-only research; stability bounded by how quickly this phase itself gets planned/executed, not by external ecosystem churn)
