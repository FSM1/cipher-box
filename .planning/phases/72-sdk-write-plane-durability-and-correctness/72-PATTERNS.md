# Phase 72: SDK Write-Plane Durability and Correctness - Pattern Map

**Mapped:** 2026-07-10
**Files analyzed:** 11 (5 source files modified, 6 test files touched)
**Analogs found:** 11 / 11 (all analogs are sibling functions in the SAME files — this phase is entirely internal-refactor; no cross-module analogs needed)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|---------------|
| `packages/sdk/src/client.ts` — `deleteItem` (SC#1) | service (write-chain mutation) | CRUD (delete) | `moveItem` (client.ts ~L2753-2818, shipped 68.1-31) — UUID-resolve + write-chain filter pattern | exact (same file, same class of write-chain edit) |
| `packages/sdk/src/client.ts` — `getWriteBodyParams` (SC#2) | utility (write-body param builder) | request-response | Itself (twin in `bin/index.ts`) — byte-for-byte identical logic today | exact (literal duplicate) |
| `packages/sdk/src/bin/index.ts` — `getWriteBodyParams` (SC#2 twin) | utility | request-response | `client.ts` `getWriteBodyParams` | exact (literal duplicate) |
| `packages/sdk/src/client.ts` — `restoreFromBin` (SC#3) | service (write-chain re-home) | CRUD (restore/move) | `moveItem` (client.ts ~L2753-2818) — dest-before-source unseal/reseal/drop template | role-match (cross-folder re-home, different trigger) |
| `packages/sdk/src/bin/index.ts` — `restoreFromBin` (SC#3, binOps) | service (bin state mutation) | CRUD | `bin/index.ts` `addToBin` (soft-delete counterpart, same file) | role-match |
| `packages/sdk/src/client.ts` — `maybeRepublishFolderForFileMigration` (SC#4) | service (cache/publish seam) | event-driven (emits `folder:updated`) | `updateSharedFile` (client.ts ~L5136-5265, specifically the 68.2-02 Rule-1-fix block ~L5239-5265) | exact (identical staleness mechanism, shared-path sibling) |
| `packages/sdk/src/client.ts` — `moveInSharedFolder` (SC#5, dead-branch removal) | service (shared-folder write-chain move) | CRUD | `moveItem` (owned-path cross-folder move, same file) for the surviving branch's shape | role-match |
| `packages/sdk/src/client.ts` — `updateSharedSingleFile` zeroize fix (todo) | service (key-unwrap + publish) | request-response | Existing `try/finally` zeroize idiom used at all 8 `unsealChildWriteKey` sites (e.g. `moveItem` ~L369-377 excerpt below) | exact (same D-09 idiom, different call site) |
| `packages/sdk-core/src/folder/registration.ts` — `updateFolderMetadataAndPublish` CAS-merge (Critical Finding 2, load-bearing for SC#1/SC#3) | service (CAS publish/merge) | CRUD (conflict resolution) | `packages/sdk-core/src/folder/merge.ts` `mergeChildren` (read-plane 3-way diff) | role-match (different key space: `childId` UUID vs `ipnsName`, but same 3-way-diff shape to replicate) |
| `packages/sdk-core/src/file/index.ts`, `packages/sdk-core/src/vault/index.ts` — TEE-wrap triplication (`wrapIpnsKeyForTee` extraction) | utility (extract shared helper) | transform | `packages/sdk-core/src/folder/registration.ts` (the 3rd triplicate site, all 3 symmetric) | exact (3 near-identical inline blocks, one is the analog for the other two) |
| `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` (SC#5 regression, currently `describe.skip`) | test | request-response | `packages/sdk/src/__tests__/update-shared-single-file.test.ts` (live, non-skipped sibling unit test for a shared-folder write op) | role-match (needs new/rewritten assertions, not a skip-lift) |

## Pattern Assignments

### `packages/sdk/src/client.ts` — `deleteItem` (SC#1)

**Analog:** `moveItem`, `packages/sdk/src/client.ts` ~L2753-2818 (68.1-31, shipped)

**Why this analog:** `moveItem` is the only existing site that resolves a child's `PublishedNode.id` (UUID) and uses it to filter/build `writeChildren` — exactly what `deleteItem` needs to do to drop the removed child's `WriteChildRef` (Pitfall 1: `deleteItem`'s `childId` param is an ipnsName, not the UUID `WriteChildRef.childId` needs).

**UUID-resolve + filter pattern to copy:**
```typescript
// Source: packages/sdk/src/client.ts, moveItem (~L2787), 68.1-31
const movedWriteRef = sourceWriteBodyParams.writeChildren?.find((wc) => wc.childId === childPub.id);
if (movedWriteRef) {
  let movedWriteKey: Uint8Array | null = null;
  try {
    movedWriteKey = await unsealChildWriteKey(
      movedWriteRef.writeKeySealed, sourceWriteBodyParams.writeKey,
      childPub.id, childPub.kind, destEntry.generation
    );
    // ... reseal under dest ...
    rehomedSourceWriteChildren = (sourceWriteBodyParams.writeChildren ?? []).filter((wc) => wc.childId !== childPub.id);
  } finally {
    movedWriteKey?.fill(0); // D-09 terminal owner
  }
}
```

**Adaptation for `deleteItem`:** No reseal step is needed (the child is gone, not moving) — just resolve `removedItem.ipnsName` via `this.resolvePublishedNode(removedItem.ipnsName)` to get `.published.id`, then `writeChildren.filter(wc => wc.childId !== resolvedUuid)`. Wrap the resolve+filter step in its own try/catch per **Pitfall 2**: a resolve failure here must NOT abort the already-succeeded read-plane delete — fail open (log a warning, skip the write-chain trim), unlike SC#2's fail-closed requirement. Do not conflate the two fail postures.

**Regression-test fixture rule (Pitfall 1's warning sign):** use genuinely DIFFERENT values for `SealedChildRef.ipnsName` and `WriteChildRef.childId` in the test fixture — a fixture that reuses the same string for both would pass even with the broken naive filter.

---

### `packages/sdk/src/client.ts` `getWriteBodyParams` / `packages/sdk/src/bin/index.ts` `getWriteBodyParams` (SC#2)

**Analog:** each other — byte-for-byte identical twins today (client.ts ~L1241-1258, bin/index.ts ~L72-90).

**Current (fail-open) shape to change:**
```typescript
// Both copies, approximate current shape
if (!wk || wk.length !== 32 || wk.every((b) => b === 0)) return {}; // legitimate read-only fallback — LEAVE AS-IS
// ...
if (!resolved || !resolved.published.writeSealed) {
  return { writeKey: wk, writeChildren: [] }; // <-- SC#2 target: fail-open on `!resolved` when wk IS real
}
```

**Fix scope (Pitfall 3 — do not over-apply):** the fail-closed change (throw instead of returning `writeChildren: []`) applies ONLY to the `!resolved` half of that condition, and ONLY when `wk` is a real, non-zero 32-byte key (already guaranteed at that point since the zero-key branch returned earlier). Leave `!resolved.published.writeSealed` (structurally never-write-capable) as the existing fail-open `writeChildren: []` — confirm this split at plan time (Assumption A1 in RESEARCH.md is unresolved).

**Dedupe note (ties into SC#6):** since both copies are identical, the eventual fix should land in one place and have `bin/index.ts` re-point at the `client.ts` helper (or a shared extracted primitive) per SC#6 — do not fix both copies independently and let them drift again.

---

### `packages/sdk/src/client.ts` — `restoreFromBin` (SC#3)

**Analog:** `moveItem`'s full dest-before-source re-homing block, `packages/sdk/src/client.ts` ~L2753-2818 (68.1-31).

**Full reference block (already verified live):**
```typescript
// Source: packages/sdk/src/client.ts moveItem, ~L2753-2818 (68.1-31, shipped)
const destWriteBodyParams = await this.getWriteBodyParams(destFolder);
const sourceWriteBodyParams = await this.getWriteBodyParams(sourceFolder);

let rehomedDestWriteChildren = destWriteBodyParams.writeChildren;
let rehomedSourceWriteChildren = sourceWriteBodyParams.writeChildren;

if (!destWriteBodyParams.writeKey || !sourceWriteBodyParams.writeKey) {
  console.warn(`moveItem: source or destination folder ... is read-only — the moved item will not be write-capable in its new location`);
} else {
  const movedWriteRef = sourceWriteBodyParams.writeChildren?.find((wc) => wc.childId === childPub.id);
  if (movedWriteRef) {
    let movedWriteKey: Uint8Array | null = null;
    try {
      movedWriteKey = await unsealChildWriteKey(movedWriteRef.writeKeySealed, sourceWriteBodyParams.writeKey, childPub.id, childPub.kind, destEntry.generation);
      const writeKeySealed = await sealChildWriteKey(movedWriteKey, destWriteBodyParams.writeKey, childPub.id, childPub.kind, destEntry.generation);
      rehomedDestWriteChildren = [...(destWriteBodyParams.writeChildren ?? []), { childId: childPub.id, writeKeySealed }];
      rehomedSourceWriteChildren = (sourceWriteBodyParams.writeChildren ?? []).filter((wc) => wc.childId !== childPub.id);
    } finally {
      movedWriteKey?.fill(0);
    }
  }
}
// ... then publish DEST, adopt, publish SOURCE, adopt (dest-before-source, D-12)
```

**Structural gap to close first (this is NOT in `moveItem` — new plumbing):** `restoreFromBin` (client.ts ~L4650) currently only calls `requireFolder(targetFolderIpnsName)`. It must ALSO `await this.requireFolder(entry.originalParentIpnsName)` (self-bootstraps via DFS from root, same mechanism the target-folder load already uses) before calling `binOps.restoreFromBin`. `binOps.restoreFromBin` (`packages/sdk/src/bin/index.ts` ~L520-618) must be extended to accept the source `FolderState` and perform the moveItem-style unseal/reseal/drop, publishing the RESTORE target before the ORIGINAL parent (dest-before-source ordering, mirrored).

**Generation-consistency rule (Pitfall 4):** use `restoredItem.generation` (the freshly-built `SealedChildRef.generation`, already equal to `nodeRef.generation`) as the write-plane reseal's generation AAD — do not derive a second, independent generation value. This mirrors how `moveItem` uses `destEntry.generation` for BOTH the read-plane reseal (L2724) and the write-plane reseal (L2792/2799) — same value both times.

**Fallback (fail-open, matching `moveItem`'s either-side-read-only branch):** if the original parent cannot be resolved (deleted/moved since soft-delete), restore succeeds read-plane-only, `console.warn`, no write-chain re-homing — never throw and block the restore.

---

### `packages/sdk/src/client.ts` — `maybeRepublishFolderForFileMigration` (SC#4)

**Analog:** `updateSharedFile`, `packages/sdk/src/client.ts` ~L5136-5265, specifically the shipped 68.2-02 Rule-1-fix block at ~L5239-5265.

**Exact pattern to replicate (already shipped for the shared-path sibling):**
```typescript
// Source: packages/sdk/src/client.ts, updateSharedFile (68.2-02 Rule 1 fix), ~L5239-5265
// File-only publish: the parent's children/sequence are unchanged — emit
// sharedFolder:updated with the current live snapshot so consumers
// re-resolve the file (mirrors refreshSharedFolder's file-only emission).
const live = this.sharedFolderTree.get(shareId);
if (live) {
  this.listingCache.delete(live.ipnsName);
  this.emitter.emit({
    type: 'sharedFolder:updated',
    shareId,
    ipnsName: live.ipnsName,
    children: await this.resolveListingChildren(
      live.children,
      live.folderKey,
      live.ipnsName,
      live.sequenceNumber
    ),
    sequenceNumber: live.sequenceNumber,
  });
}
```

**Owned-path target:** `maybeRepublishFolderForFileMigration` (client.ts ~L3801-3845) is missing exactly one line — `this.listingCache.delete(folderIpnsName);` — before its existing `resolveListingChildren` + emit call at the end. Per the locked SC#4 wording, gate this behind a "did size/mtime actually change" check (compare the NEW `NodeContent.size`/`Node.modifiedAt` against what the caller already has — do not re-derive inside this seam). This should run unconditionally on BOTH the migration branch and the no-op branch of the function.

**Anti-pattern (explicit, do not do):** do NOT add `size`/`modifiedAt` fields back onto `SealedChildRef`. That mirror was deliberately reverted in Phase 68.2-12 (commit `3e1fcb176`) in favor of `ResolvedChild`; reintroducing it violates the NODE-03 frozen-field-set invariant. `SealedChildRef` today is frozen to `{name, ipnsName, generation, versionFloor, readKeySealed}` (`packages/core/src/node/types.ts` ~L76-83).

---

### `packages/sdk/src/client.ts` — `moveInSharedFolder` (SC#5)

**Target:** remove the `shareKeys.length > 0` dead branch and the `getShareKeysFn` param (client.ts ~L5536-5579, dead branch; method starts ~L5504).

**Analog for the surviving (reachable) branch's shape:** the `else` branch already in the same function — unseal source state's write-body, one-hop walk by UUID to the dest `WriteChildRef`, fail-closed if destination is not a direct child (fail-open/fail-closed table site #6, ~L5635).

**Cross-package edit required in the same change (Pitfall 5):** two call sites in `apps/web/src/hooks/useSharedWriteOps.ts` (L219, L260) pass `getShareKeysFn: fetchShareKeys` — update both to drop the arg when the SDK signature drops the param. `fetchShareKeys` itself (`apps/web/src/services/share.service.ts:193`, always returns `[]`) is a documented historical stub; leave it unless explicitly asked to remove it too (out of the 9 todos' locked scope).

**Regression coverage is currently ZERO (Critical Finding 3) — mandatory new test, not optional:** `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` (13 tests) is 100% `describe.skip`'d and imports retired types (`FolderChild`/`FilePointer`/`FolderEntry`, none exist in `@cipherbox/core` today). `tests/web-e2e/tests/writable-shares.spec.ts` has zero "move" coverage. Do not attempt to un-skip/modernize all 13 existing tests (they test the branch being DELETED) — write ONE new, targeted unit test exercising the reachable `else` path before/after removal.

---

### `packages/sdk/src/client.ts` — `updateSharedSingleFile` zeroize fix (todo)

**Analog:** the D-09 `try { ...; return result; } finally { local?.fill(0); }` idiom used at every one of the 8 `unsealChildWriteKey` call sites (e.g. `moveItem` excerpt above, ~L369-377).

**Target shape (client.ts ~L5309-5320):**
```typescript
// Target shape — packages/sdk/src/client.ts updateSharedSingleFile, ~L5309-5320
let fileReadKey: Uint8Array | null = null;
let fileWriteKey: Uint8Array | null = null;
let currentFileNode: CoreNode | null = null;
try {
  fileReadKey = await unwrapKey(hexToBytes(args.encryptedReadKey), args.recipientPrivateKey);
  fileWriteKey = await unwrapKey(hexToBytes(args.encryptedWriteKey), args.recipientPrivateKey);
  // ... rest of the existing try body, unchanged
} finally {
  fileReadKey?.fill(0);
  fileWriteKey?.fill(0);
  currentFileNode?.writeBody?.ipnsPrivateKey?.fill(0);
  currentFileNode?.content?.fileKey?.fill(0);
}
```

**Critical invariant (do not violate):** every existing call site nulls the local BEFORE the `finally`-triggering `return` runs (ownership transfer on success); only a THROWN exit reaches `finally` with a non-null local to zero. Preserve this "null-before-return, fill-in-finally" idiom exactly — a naive refactor that always zeros in `finally` regardless of return path would corrupt a buffer just handed to the caller as their live result.

---

### `packages/sdk-core/src/folder/registration.ts` — `updateFolderMetadataAndPublish` CAS-merge (Critical Finding 2)

**Analog:** `packages/sdk-core/src/folder/merge.ts` `mergeChildren` — the read-plane 3-way diff that already "prunes intentional deletes: a base entry absent from BOTH local AND remote" (merge.ts L37-44).

**Current naive write-plane merge (registration.ts `merge()` callback, ~L324-338):** unions `currentWriteChildren`/`remoteWriteChildren` by `childId`, remote-wins-on-conflict, NO base snapshot, NO deletion-pruning. Its own comment (~L239-241) states the now-falsified premise: "write plane is add-only here... a union never resurrects an intentionally dropped entry."

**Adaptation required (NOT a mechanical copy):** `mergeChildren` diffs by `ipnsName` (read-plane key space); the write-plane equivalent must diff by `childId` (UUID) — a different key space entirely. The write-plane merge function also does not currently receive a captured pre-mutation `base` snapshot — that plumbing (`baseWriteChildren` threaded through `updateFolderMetadataAndPublish`) is new, not present today.

**Nearest existing test template for the fix's regression test:** `packages/sdk-core/src/__tests__/folder/registration.test.ts` L174 ("two CAS encode attempts (on retry) use the same nodeId") — closest existing 409-retry test shape to extend for a concurrent-delete-resurrection scenario. `packages/sdk-core/src/__tests__/folder/write-body.test.ts` covers only seal shape today, not CAS-merge/conflict behavior.

**Planner decision required (not optional-silent):** either (a) make the merge base-aware/prune-on-absent-from-both (mirroring `merge.ts`), or (b) explicitly document as an accepted residual race and defer — but SC#1 must not ship with this silently unaddressed.

---

### `packages/sdk-core/src/file/index.ts`, `packages/sdk-core/src/vault/index.ts` — TEE-wrap triplication (`wrapIpnsKeyForTee` extraction)

**Analog:** the 3rd symmetric site in `packages/sdk-core/src/folder/registration.ts` — all 3 sites are near-identical inline ECIES-wrap blocks; any one is the analog for extracting the shared helper.

**Buffer-ownership contract to preserve in the extracted helper (from RESEARCH.md's buffer-ownership table):**
```typescript
// Mirrors existing 3 sites' comment, verbatim contract to preserve:
// "Do NOT zero ipnsPrivateKey here — wrapKey reads but does not consume
// the buffer; the caller is the terminal owner (D-09)"
```
`wrapIpnsKeyForTee` owns nothing new on exit; `ipnsPrivateKey` is always caller-owned across all 3 existing sites — the extracted helper must preserve this borrow-only contract, not introduce a zero.

---

### `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` (SC#5 regression test)

**Analog:** `packages/sdk/src/__tests__/update-shared-single-file.test.ts` — a live (non-skipped) unit test suite for a comparable shared-folder write operation, useful as a structural template for mock setup (shared folder state, write-body unseal mocks) since the target file's own 13 existing tests are all `describe.skip`'d and reference retired types.

**Scope:** write ONE new, focused `it` block exercising the reachable (`shareKeys.length === 0`) branch of `moveInSharedFolder` — do not attempt to rewrite/un-skip the full existing suite (out of locked scope per RESEARCH.md's Deferred Ideas).

---

## Shared Patterns

### D-09 zeroize idiom (terminal-owner buffer zeroing)
**Source:** every one of the 8 `unsealChildWriteKey` call sites in `packages/sdk/src/client.ts` (e.g. `moveItem` ~L369-377 in excerpts above)
**Apply to:** `deleteItem`'s new UUID-resolve step (if it touches key material — likely not, since it's ipnsName resolve only), `restoreFromBin`'s re-homing unseal/reseal, `updateSharedSingleFile`'s zeroize fix, and the extracted `walkChildWriteKey`/`wrapIpnsKeyForTee` primitives (SC#6).
```typescript
let local: Uint8Array | null = null;
try {
  local = await unsealChildWriteKey(...);
  // ... use local, eventually `return`/transfer ownership before this block exits ...
} finally {
  local?.fill(0); // only fires if local is still non-null (i.e. a throw occurred before transfer)
}
```

### `listingCache` invalidation on any file-only publish
**Source:** `packages/sdk/src/client.ts` `updateSharedFile` ~L5250-5252 (68.2-02 Rule 1 fix)
**Apply to:** `maybeRepublishFolderForFileMigration` (SC#4) — the one-line fix `this.listingCache.delete(folderIpnsName)` before the existing `resolveListingChildren` + emit call.
```typescript
this.listingCache.delete(live.ipnsName);
// ... then resolveListingChildren + emit, as before
```

### Fail-open vs fail-closed write-chain hop-walk table (SC#6 primitive design input)
**Source:** RESEARCH.md's full 8-site table (§"Write-Chain Hop Walk"). Apply directly — do not re-derive.
**Apply to:** any new `unsealChildWriteKey` call site touched by this phase (SC#1's `deleteItem`, SC#3's `restoreFromBin`) must be explicitly classified into one of the 3 modes below (not assumed):
- Mode (a) missing-ref-throws + validation-throws — sites 3, 4, 6 (`resolveFileWriteChainKeys`, `resolveShareEncryptedWriteKey`, `moveInSharedFolder` reachable branch)
- Mode (b) missing-ref-skips + validation-throws — sites 1, 2, 5, 7 (`dfsFindFolder`, `moveItem`, `updateSharedFile` inline walk, `enumerateSharedSubtree`) — the dominant case, and the one `deleteItem`'s new step and `restoreFromBin`'s re-homing should follow (fail-open on missing ref per Pitfall 2, fail-closed on a genuine key-validation failure)
- Mode (c) missing-ref-returns-null + validation-returns-null — site 8 only (`resolveSharedSubfolderWriteKey`) — do not force other sites into this shape

### Cross-package caller update discipline
**Source:** CLAUDE.md "API Development Workflow" + Pitfall 5 (SC#5's `getShareKeysFn` removal)
**Apply to:** SC#5 — update `apps/web/src/hooks/useSharedWriteOps.ts` (L219, L260) in the SAME change as the SDK signature change; run `pnpm typecheck` before considering the task done.

## No Analog Found

None — every file in this phase's scope has a same-file or same-module sibling analog (this is an internal-refactor/bugfix phase within an already-established architecture; no new capability, no new module type).

## Metadata

**Analog search scope:** `packages/sdk/src/client.ts`, `packages/sdk/src/bin/index.ts`, `packages/sdk-core/src/folder/{registration,merge,metadata-ops}.ts`, `packages/sdk-core/src/{file,vault}/index.ts`, `packages/core/src/node/types.ts`, `packages/core/src/bin/types.ts`, existing test files under `packages/sdk/src/__tests__/` and `packages/sdk-core/src/__tests__/folder/`
**Files scanned:** covered fully by RESEARCH.md's Primary Sources list (verified this session via targeted grep against `packages/sdk/src/client.ts` to confirm current line anchors for `deleteItem` (2924), `maybeRepublishFolderForFileMigration` (3801), `restoreFromBin` (4650), `updateSharedFile`/`listingCache.delete` (5136/5252), `moveInSharedFolder` (5504) — all consistent with RESEARCH.md's cited line numbers)
**Pattern extraction date:** 2026-07-10
