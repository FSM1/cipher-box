# Phase 72: SDK Write-Plane Durability and Correctness - Research

**Researched:** 2026-07-10
**Domain:** SDK write-chain (node/v3) correctness, dedup/refactor of `packages/sdk/src/client.ts` write-plane helpers
**Confidence:** HIGH (all findings are direct code reads/greps against the current tree, cross-checked against runtime test execution — no external library research was needed; this is a pure internal-codebase phase)

## Summary

This phase closes six correctness/durability gaps in the SDK's owned write-chain (node/v3), all scoped to `packages/sdk/src/client.ts`, `packages/sdk/src/bin/index.ts`, and three `packages/sdk-core` TEE-enrollment sites. Every one of the 9 source todos was re-verified against the CURRENT tree (not just the todo text) — one todo (SC#4, the size/modifiedAt mirror) is **materially stale**: the `SealedChildRef.size`/`modifiedAt` mirror it describes was reverted in Phase 68.2-12, and the actual current bug is a **`listingCache` staleness** issue with an established fix pattern already shipped for the shared-folder analog (`updateSharedFile`). A second load-bearing finding not called out in any todo: the write-body CAS-merge in `updateFolderMetadataAndPublish` is currently a naive union (`byChildId.set`, remote-wins, no base-diff) whose own comment admits it only works because "deletes are preserved verbatim" — a premise SC#1 is about to falsify. This is a real concurrency landmine for SC#1/SC#3 and needs a task of its own.

The write-chain hop walk (`unsealChildWriteKey` call site) appears at **8** locations, not 7 as the todo estimated — mapped exactly below with fail-open/fail-closed classification per site. The dedupe target (todo #6) is genuinely design-first: a `walkChildWriteKey` primitive needs an explicit mode parameter, not a mechanical extract, because the 8 sites disagree on fail-open vs fail-closed by design, not by accident.

**Primary recommendation:** Sequence the six correctness fixes (SC#1–#5, todo #9) as small, independently-testable client.ts/bin.ts edits first (each has a narrow blast radius and an obvious regression test), and treat SC#6 (the dedupe) as a separate, later, larger wave — it depends on knowing the final fail-open/fail-closed contract of each of the other fixes, and touches `bin/index.ts` re-pointing which should not race with SC#1–#5 landing in `client.ts`.

## User Constraints

### Locked Decisions (from the phase brief — pre-resolved, do not re-litigate)

1. **SC#1** — `deleteItem` must drop the removed child's `WriteChildRef` from the parent's write chain in the same CAS publish that removes the read-plane `SealedChildRef`. Regression test asserts write-chain length shrinks.
2. **SC#2** — `getWriteBodyParams` (both copies) fails **closed** (not open) on a null/transient resolve when a real writeKey is present — never seals `writeChildren: []` and silently discards the chain. This is the decided fork; do not implement the "preserve last-known mirror" alternative from the todo — the todo's Option (a) fail-closed was locked.
3. **SC#3** — `restoreFromBin` to a different parent re-homes the `WriteChildRef` (reuse the shipped Phase 68.1-31 `moveItem` re-homing pattern: dest-before-source publish ordering, unseal-under-source → drop-from-source → reseal-under-dest, keyed by node UUID + dest-mirror generation).
4. **SC#4** — `replaceFile`/`restoreFileVersion` refresh the "display mirror" after an in-place edit. Locked as "Option A: refresh + republish the parent, gated behind a did-it-actually-change check, reuse the `maybeRepublishFolderForFileMigration` piggyback seam." **See Critical Finding 1 below — the mechanism this maps to in the CURRENT codebase is `listingCache` invalidation, not a parent SealedChildRef field refresh; the parent already unconditionally republishes/emits via that seam.**
5. **SC#5** — Remove the unreachable `moveInSharedFolder` `shareKeys.length > 0` branch and its `getShareKeysFn` param, eliminating the latent Ed25519-as-AES wrong-key bug.
6. **SC#6** — Consolidate the near-identical write-plane helper sequences into one primitive; harden `write-chain-rotation.test.ts` (identify rotated seeds by provenance, not fixed offset) and `upload-batch.test.ts` (current `SealedChildRef` mock shape).

### Claude's Discretion
None explicitly delegated by the phase brief beyond ordinary implementation choices (exact helper names/signatures for the dedupe, exact test names).

### Deferred Ideas (OUT OF SCOPE)
- Anything beyond the 9 source todos listed in the phase brief.
- Re-litigating SC#2's fail-open vs fail-closed choice or SC#4's Option A vs B choice — both are locked.
- Rewriting `move-in-shared-folder.test.ts`'s fully-`describe.skip`'d suite wholesale (flagged as a landmine below, but full modernization is a plan-time decision, not a locked scope item).

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SC#1 | `deleteItem` drops removed child's `WriteChildRef` | Exact site mapped (client.ts `deleteItem`, ~L2924-3001); UUID-resolution gap identified; CAS-merge landmine identified (Critical Finding 2) |
| SC#2 | `getWriteBodyParams` fails closed on transient resolve miss | Both copies mapped byte-for-byte identical (client.ts ~L1241-1258, bin/index.ts ~L72-90); fail-closed contract defined |
| SC#3 | `restoreFromBin` re-homes `WriteChildRef` to different parent | `moveItem`'s 68.1-31 pattern read in full (client.ts ~L2655-2911) as the template; `restoreFromBin`'s missing source-folder load identified as the actual gap |
| SC#4 | Refresh size/modifiedAt display after in-place edit | **Materially reframed** — `SealedChildRef` mirror reverted in 68.2-12; root cause is `listingCache` staleness; established fix pattern found in `updateSharedFile` (Critical Finding 1) |
| SC#5 | Remove dead `moveInSharedFolder` branch + `getShareKeysFn` | Dead branch mapped exactly (client.ts ~L5536-5579); 2 web callers found; **zero regression coverage exists today** (Critical Finding 3) |
| SC#6 | Dedupe write-plane helpers | All 8 `unsealChildWriteKey` call sites mapped with fail-open/fail-closed table; buffer-ownership table produced; TEE triplication sites confirmed |
| todo (zeroize) | `updateSharedSingleFile` zero-on-error-path | Confirmed still live at client.ts ~L5312-5395, unchanged shape from todo |
| todo (seed-index) | `write-chain-rotation.test.ts` fixed-offset fragility | Confirmed still live at tests/sdk-e2e L353/355; fix approach (spy `generateEd25519Keypair`) validated as feasible |
| todo (mock drift) | `upload-batch.test.ts` retired-field mocks | Confirmed still live (19 tests, all pass at runtime — transpile-only, no typecheck) |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Write-chain hop walk / key recovery | API/Backend (SDK, in-process) | — | `packages/sdk/src/client.ts` is a client-side library, but architecturally it is the "backend" for this codebase's crypto/write-chain logic — no server involvement (server is zero-knowledge, CLAUDE.md) |
| CAS-merge / publish retry | API/Backend (sdk-core) | — | `packages/sdk-core/src/folder/registration.ts` `updateFolderMetadataAndPublish` — pure logic, no UI |
| Listing display cache (`listingCache`) | API/Backend (SDK) | Frontend Server (apps/web renders it) | Cache lives in `CipherBoxClient`; web only consumes `ResolvedChild[]` it emits |
| Bin soft-delete/restore | API/Backend (SDK: `packages/sdk/src/bin/index.ts`) | — | Stateless functions taking explicit params, no store/UI coupling |
| TEE key-wrap enrollment | API/Backend (sdk-core: file/vault/folder modules) | — | ECIES wrap under TEE public key; symmetric shape in 3 files |

This phase touches exactly one tier (SDK/API, in-process library code) — no browser, no CDN, no database. This is a correctness/durability phase within an already-established architecture, not a new capability.

## Standard Stack

Not applicable — this phase adds no new external dependencies. All work is internal refactor/bugfix inside `packages/sdk`, `packages/sdk-core`, `packages/core`. No new libraries, no version bumps.

## Package Legitimacy Audit

**Not applicable.** This phase installs no external packages. No `npm view` / registry verification was required or performed.

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                packages/sdk/src/client.ts                │
                    │                  (CipherBoxClient)                       │
                    │                                                           │
  deleteItem() ─────┼──> sdkCore.deleteFromFolder (read-plane, by ipnsName)     │
                    │      │                                                    │
                    │      ├─ [SC#1 GAP] resolve removedItem's PublishedNode.id │
                    │      │   (UUID) then filter it out of writeChildren       │
                    │      │                                                    │
                    │      v                                                    │
  getWriteBodyParams()──> resolvePublishedNode(folder.ipnsName)                 │
     (also bin/index.ts │      │                                                │
      identical twin)   │      ├─ [SC#2] null resolve + real writeKey present   │
                    │      │     => MUST throw (fail closed), currently         │
                    │      │     returns writeChildren:[] (fail OPEN)           │
                    │      v                                                    │
                    │  sdkCore.updateFolderMetadataAndPublish (registration.ts) │
                    │      │                                                    │
                    │      ├─ encodeAndUpload: seals currentWriteChildren       │
                    │      ├─ decodeRemote: unseals remote on 409               │
                    │      └─ [CRITICAL FINDING 2] merge(): byChildId union,    │
                    │         remote-wins, NO base-diff => will resurrect an    │
                    │         SC#1 delete raced by a concurrent writer          │
                    │                                                           │
  replaceFile() ────┼──> resolveFileWriteChainKeys() ──> sdkCore.updateFileMetadata│
  restoreFileVersion()   (file-only IPNS publish; parent sequence UNCHANGED)     │
  deleteFileVersion()    │                                                       │
                    │      v                                                     │
                    │  maybeRepublishFolderForFileMigration()                    │
                    │      │  ALWAYS emits folder:updated via resolveListingChildren│
                    │      │  [CRITICAL FINDING 1] listingCache keyed by          │
                    │      │  (ipnsName, parent sequenceNumber) — unchanged by    │
                    │      │  a file-only publish => emits STALE size/modifiedAt  │
                    │      │  MISSING: this.listingCache.delete(folderIpnsName)   │
                    │      │  (updateSharedFile already does this — the pattern   │
                    │      │  to copy is one line away, in the same file)         │
                    │                                                             │
  restoreFromBin() ─┼──> requireFolder(targetFolderIpnsName) only                 │
     (client.ts)        │  [SC#3 GAP] never loads/touches originalParentIpnsName  │
                    │    │  => cannot re-home (source WriteChildRef untouched,    │
                    │    │  still sitting under the ORIGINAL parent's write-body) │
                    │    v                                                        │
                    │  binOps.restoreFromBin (bin/index.ts) — preserves target's   │
                    │    write-body VERBATIM, no re-homing                        │
                    │                                                             │
  moveInSharedFolder()┼──> args.getShareKeysFn(shareId)                           │
                    │    │                                                        │
                    │    ├─ [SC#5 DEAD] shareKeys.length>0 branch — unreachable    │
                    │    │  (fetchShareKeys always returns []); contains Ed25519-  │
                    │    │  as-AES-key bug at destWriteKey = destIpnsPrivateKey    │
                    │    │                                                        │
                    │    └─ else (REACHABLE): unseal srcState write-body, walk one │
                    │       hop by UUID to dest WriteChildRef (fail-closed if      │
                    │       destination not a direct child)                       │
                    └─────────────────────────────────────────────────────────┘
```

### Recommended Project Structure

No new files/directories are needed. All fixes land in the existing structure:

```
packages/sdk/src/
├── client.ts              # SC#1, SC#2 (client copy), SC#3, SC#4, SC#5, most of SC#6
├── bin/index.ts            # SC#2 (bin copy) — re-point at client helper per SC#6
└── __tests__/
    ├── upload-batch.test.ts             # todo: mock shape fix
    ├── update-shared-single-file.test.ts # todo: zeroize-on-error-path test
    └── move-in-shared-folder.test.ts     # currently describe.skip'd wholesale — see Landmine 3

tests/sdk-e2e/src/suites/
└── write-chain-rotation.test.ts   # todo: seed-index-by-provenance fix

packages/sdk-core/src/
├── folder/registration.ts   # write-body CAS-merge (Critical Finding 2) — NOT in the 9 todos but load-bearing for SC#1/SC#3
├── file/index.ts            # TEE-wrap triplication site 1
└── vault/index.ts           # TEE-wrap triplication site 3
```

### Pattern 1: `listingCache` invalidation on a file-only publish (the SC#4 fix)

**What:** After ANY publish that changes a child's own content/metadata WITHOUT bumping the parent folder's sequence number (a "file-only publish"), the parent's `listingCache` entry must be explicitly invalidated before the next `resolveListingChildren` call, or the emitted `ResolvedChild[]` will serve stale `size`/`modifiedAt` for that child.

**When to use:** Any write path that publishes a child's own IPNS record but does not republish the parent (currently: `replaceFile`, `restoreFileVersion`, `deleteFileVersion`, via `maybeRepublishFolderForFileMigration`).

**Example (already shipped for the SHARED-folder analog, `updateSharedFile`, client.ts ~L5239-5265 — this is the exact pattern to replicate for the OWNED path):**
```typescript
// Source: packages/sdk/src/client.ts, updateSharedFile (68.2-02 Rule 1 fix)
// File-only publish: the parent's children/sequence are unchanged — emit
// sharedFolder:updated with the current live snapshot so consumers
// re-resolve the file (mirrors refreshSharedFolder's file-only emission).
//
// 68.2-02 (Rule 1 fix): the parent folder's OWN ipnsName+sequenceNumber
// is unchanged by a file-only content publish, but the just-updated
// FILE's own PublishedNode (content/modifiedAt) is now stale in
// `listingCache` if it was resolved before this update. Invalidate
// the parent's cache entry so the emitted ResolvedChild[] re-resolves
// every child (including the just-updated file) instead of serving a
// stale cached size/modifiedAt for it.
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

**The owned-path equivalent is `maybeRepublishFolderForFileMigration` (client.ts ~L3801-3845) — it is missing exactly one line: `this.listingCache.delete(folderIpnsName);` before its `resolveListingChildren` call at the end.** This should be unconditional (runs on BOTH the migration branch and the no-op branch), since a file-only publish always makes the child's own Node fresher than whatever the cache holds — gating it behind "did size/mtime actually change" (per the locked SC#4 wording) means checking the NEW `NodeContent.size`/`Node.modifiedAt` against what `resolveFileWriteChainKeys`/`updateFileMetadata`'s caller already has, not re-deriving it inside this seam.

### Pattern 2: `moveItem`'s dest-before-source re-homing (the SC#3 template)

**What:** To re-home a `WriteChildRef` across two write-capable folders: (1) resolve both folders' `getWriteBodyParams`, (2) if BOTH have a real writeKey, unseal the child's writeKey under the SOURCE writeKey using the moved-child's UUID + the destination-mirror `generation`, reseal it under the DEST writeKey with the same UUID/generation, remove from source's `writeChildren`, add to dest's; (3) publish DEST before SOURCE (crash safety — a crash between publishes never orphans the node from both folders); (4) if EITHER folder is read-only (no real writeKey), skip re-homing with a `console.warn`, never throw and never fabricate a write link.

**When to use:** Any cross-folder write-chain move — `moveItem` (shipped, 68.1-31) and `restoreFromBin`-to-different-parent (SC#3, this phase).

**Example:**
```typescript
// Source: packages/sdk/src/client.ts, moveItem (~L2759-2818), 68.1-31
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
      movedWriteKey = await unsealChildWriteKey(
        movedWriteRef.writeKeySealed, sourceWriteBodyParams.writeKey,
        childPub.id, childPub.kind, destEntry.generation
      );
      const writeKeySealed = await sealChildWriteKey(
        movedWriteKey, destWriteBodyParams.writeKey, childPub.id, childPub.kind, destEntry.generation
      );
      rehomedDestWriteChildren = [...(destWriteBodyParams.writeChildren ?? []), { childId: childPub.id, writeKeySealed }];
      rehomedSourceWriteChildren = (sourceWriteBodyParams.writeChildren ?? []).filter((wc) => wc.childId !== childPub.id);
    } finally {
      movedWriteKey?.fill(0); // D-09 terminal owner
    }
  }
}
// ... then publish DEST, adopt, publish SOURCE, adopt (dest-before-source, D-12)
```

**For `restoreFromBin` (SC#3), the gap is structural, not just missing re-homing logic: the function today never loads the ORIGINAL parent folder at all.** `BinEntry.originalParentIpnsName` is already captured at `addToBin` time (see `packages/core/src/bin/types.ts` ~L25), so the source folder CAN be resolved by IPNS name — but the caller (`client.ts` `restoreFromBin`, ~L4650-4688) must add `await this.requireFolder(entry.originalParentIpnsName)` (self-bootstraps via DFS from root, same as `requireFolder(targetFolderIpnsName)` already does) before calling into `binOps.restoreFromBin`, and `binOps.restoreFromBin` (bin/index.ts ~L520-618) must be extended to accept the source `FolderState`, perform the moveItem-style unseal/reseal/drop, and publish the ORIGINAL parent (dropping the ref) in addition to the target (adding it) — mirroring dest-before-source ordering (publish the RESTORE target before the ORIGINAL parent, so a crash never orphans the node write-capability entirely).

**Fallback when the original parent cannot be resolved** (e.g. it was itself deleted/moved since the soft-delete): fail OPEN exactly like `moveItem` does when either side is read-only — restore succeeds with the read-plane only, `console.warn`, no write-chain re-homing, never throw and block the restore.

### Anti-Patterns to Avoid

- **Treating SC#4 as "add fields back to SealedChildRef":** The `size`/`modifiedAt` mirror on `SealedChildRef` was deliberately reverted in Phase 68.2-12 (commit `3e1fcb176`) in favor of `ResolvedChild` (per-folder-load resolve). Reintroducing mirror fields on `SealedChildRef` would violate the NODE-03 frozen-field-set invariant re-established by that revert. The fix is cache invalidation, not schema change.
- **Extending the write-body CAS-merge with a mechanical copy of `mergeChildren`'s logic without adapting it:** `mergeChildren` (read-plane, `packages/sdk-core/src/folder/merge.ts`) diffs by `ipnsName`; the write-plane equivalent must diff by `childId` (UUID) — a different key space, and the write-plane merge function does not currently even receive a `base` writeChildren snapshot (only `params.writeChildren` as "current"/local — no captured pre-mutation base is threaded through `updateFolderMetadataAndPublish` today for the write body). This is new plumbing, not a copy-paste.
- **Assuming `getShareKeysFn` removal is SDK-only:** two callers in `apps/web/src/hooks/useSharedWriteOps.ts` (L219, L260) pass `getShareKeysFn: fetchShareKeys` — these must be updated in the same change, and `fetchShareKeys` itself (which "always returns []", `apps/web/src/services/share.service.ts:193`) should be evaluated for removal or left as a documented historical stub (out of the 9 todos' scope to decide — flag as an open question).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Cross-folder write-key re-homing | A new bespoke unseal/reseal sequence for restoreFromBin | The shipped `moveItem` 68.1-31 pattern (dest-before-source, fail-open on either-side-read-only) | Already reviewed, already has an established fail-open contract; a second bespoke implementation risks a THIRD divergent fail-open/fail-closed choice (compounding the exact problem SC#6 is trying to fix) |
| "Is this a real 32-byte non-zero writeKey" check | A 9th inline spelling | Extract the ALREADY-DUPLICATED predicate (8 inline spellings found — see below) as part of SC#6 | One more inline spelling makes the eventual dedupe harder, not easier |
| Stale-listing invalidation | A bespoke per-child cache-bust for the owned path | `this.listingCache.delete(folderIpnsName)` — the exact one-liner already proven in `updateSharedFile` (68.2-02) | Identical cache, identical staleness mechanism, already shipped and presumably covered by whatever regression caught the shared-path bug originally |

**Key insight:** Every one of this phase's "hard" problems (re-homing, stale display, TEE key-wrap) already has a working, shipped reference implementation elsewhere in this same codebase (moveItem, updateSharedFile, or one of the 3 TEE sites). The research risk here is NOT "what's the right pattern" — it's "did you find the sibling that already solved this" before writing a new one.

## Write-Chain Hop Walk: Fail-Open / Fail-Closed Table (SC#6 primary input)

All 8 current `unsealChildWriteKey` call sites in `packages/sdk/src/client.ts`, with their behavior when the `WriteChildRef` lookup misses (before any `unsealChildWriteKey` call is even attempted):

| # | Site (function, approx line) | Read or Write path | Behavior on missing `WriteChildRef` | Behavior on `unsealChildWriteKey`/validation failure (wrong key) |
|---|---|---|---|---|
| 1 | `dfsFindFolder` (~L1506) | READ (descent/cold-load) | Fail-OPEN: `continue` (skip this child, try siblings) | Fail-CLOSED: not caught, propagates (T-68.1-01-03 validate-before-trust) |
| 2 | `moveItem` (~L2787) | WRITE (re-home, shipped 68.1-31) | Fail-OPEN: `else` branch — "nothing to re-home, lists stay verbatim" | Fail-CLOSED: not caught inside the `if (movedWriteRef)` block |
| 3 | `resolveFileWriteChainKeys` (~L3602) | WRITE (used by replaceFile/restoreFileVersion/deleteFileVersion/resolveFileIpnsPrivateKey) | Fail-CLOSED: throws `File ${fileId} is not write-capable (no WriteChildRef)` | Fail-CLOSED: not caught |
| 4 | `resolveShareEncryptedWriteKey` (~L3762) | WRITE (mint a share/invite grant) | Fail-CLOSED: throws "cannot mint a write grant for an item with no write-chain entry" | Fail-CLOSED: not caught |
| 5 | `updateSharedFile` inline walk (~L5200) | WRITE (shared-folder file edit) | Fail-OPEN-ish: falls back to `args.getFileIpnsKeyFn` (legacy share-key lookup); only throws if THAT also fails | Fail-CLOSED: not caught |
| 6 | `moveInSharedFolder` reachable branch (~L5635) | WRITE (shared-folder cross-subtree move) | Fail-CLOSED: throws "known blocker" error — destination not a direct child | Fail-CLOSED: not caught |
| 7 | `enumerateSharedSubtree` walk (~L5827) | READ (enumeration for a folder picker; `writable` is a display flag) | Fail-OPEN: `writable = false`, continues enumeration | Fail-CLOSED (but caught by the enclosing `try/finally`'s per-node scope — a wrong key here would throw and abort enumeration for that node, not silently mark unwritable; only a MISSING ref is fail-open) |
| 8 | `resolveSharedSubfolderWriteKey` (~L5941) | WRITE (one-hop write-key recovery for shared subfolder navigation) | Fail-OPEN: returns `null` (caller treats null as "read-only at this depth") | Fail-CLOSED: validated via `unsealNode` before trust; a validation failure returns `null` too (T-68.1-30-02) — this is the ONE site where even a wrong-key failure is fail-open by design, not just a missing-ref |

**Implication for the `walkChildWriteKey` primitive (SC#6):** the mode parameter needs at minimum THREE settings, not two: (a) missing-ref-throws + validation-throws (sites 3, 4, 6), (b) missing-ref-skips + validation-throws (sites 1, 2, 5, 7 — the dominant case), (c) missing-ref-returns-null + validation-returns-null (site 8 only — swallows AEAD failures too, the sole outlier). Do not force site 8 into mode (b)'s shape; it is intentionally the most permissive by design (a cold-navigation "is this depth even writable" probe, not a mutation).

Site 5 (`updateSharedFile`)'s fallback-to-legacy-key-lookup shape does not fit any of the above modes cleanly — it is arguably a 4th, bespoke shape (fail-open on ref-miss THEN fail-closed only if the fallback also misses). Recommend treating site 5 as out-of-scope for the mechanical primitive extraction and leaving it as a documented exception, unless the planner determines `getFileIpnsKeyFn`'s fallback is itself dead code (not verified in this research pass — worth one grep before deciding).

## Buffer Ownership Table (D-09 compliance for extracted helpers)

| Extracted helper (proposed) | Owns (zeros on exit) | Borrows (never zeros — caller-owned) |
|---|---|---|
| `walkChildWriteKey` (the unseal step itself) | The unsealed child writeKey it returns, ONLY on a failure path inside itself (mirrors every existing site's `finally` pattern: local var zeroed only if the call doesn't reach a `return`/ownership-transfer line) | `parentWriteKey` (tree/caller-owned, passed in) |
| `hasRealWriteKey` predicate (pure boolean check) | Nothing — never touches key contents beyond `.every()` read | The key it inspects (read-only) |
| `wrapIpnsKeyForTee` (TEE enrollment wrap) | Nothing new — mirrors existing 3 sites' comment: "Do NOT zero ipnsPrivateKey here — wrapKey reads but does not consume the buffer; the caller is the terminal owner (D-09)" | `ipnsPrivateKey` input (always caller-owned per all 3 existing sites) |
| Version-op core (replaceFile/restoreFileVersion/deleteFileVersion shared body) | `fileReadKey`/`fileWriteKey` derived via `resolveFileWriteChainKeys` (existing `finally` pattern, unchanged) | `fileData.fileIpnsPrivateKey` / `params.fileIpnsPrivateKey` — NOT zeroed by the client method; `updateFileMetadata` (sdk-core) is documented as the terminal owner (T-47-01) |

**Critical invariant to preserve:** every one of the 8 write-chain-walk call sites currently follows the SAME shape — a `try { ...; return result; } finally { local?.fill(0); }` where the return path nulls the local BEFORE the `finally` runs (transferring ownership), and only a THROWN exit reaches the `finally` with a non-null local to zero. A mechanical extraction that moves this into a shared primitive must preserve this exact "null-before-return, fill-in-finally" idiom — a naive refactor that always zeros in `finally` regardless of return-path would zero a buffer that was just handed to the caller as their live result, corrupting it before use.

## Critical Findings (not in any todo verbatim — discovered during codebase verification)

### Critical Finding 1: SC#4's stated mechanism no longer exists — the fix is `listingCache` invalidation, not a mirror refresh

The todo `2026-07-04-child-ref-size-modifiedat-mirror-stale-after-inplace-edit.md` describes a `SealedChildRef.size`/`modifiedAt` display mirror from commit `ba3e0229a`. **That mirror was reverted** in Phase 68.2-12 (`packages/core/src/node/types.ts` ~L76-83: "A prior interim revision (commit ba3e0229a) added optional size/modifiedAt display mirrors; these were reverted (D-08/68.2-12) in favor of ResolvedChild"). `SealedChildRef`'s field set today is frozen to exactly `{name, ipnsName, generation, versionFloor, readKeySealed}` — no size/modifiedAt field exists to go stale.

The ACTUAL current staleness mechanism is `CipherBoxClient.listingCache` (client.ts L199), a `Map<ipnsName, {sequenceNumber, children: ResolvedChild[]}>` keyed by the PARENT folder's `ipnsName` and invalidated ONLY when the parent's `sequenceNumber` changes (client.ts ~L845-869). Since `replaceFile`/`restoreFileVersion`/`deleteFileVersion` publish only the FILE's own IPNS record (parent sequence unchanged, by design — documented in multiple docstrings), the cache entry survives the edit and the next `folder:updated` emission (via `maybeRepublishFolderForFileMigration`, which ALWAYS calls `resolveListingChildren` + emits regardless of whether a TEE migration happened) returns the STALE cached `ResolvedChild[]` with pre-edit `size`/`modifiedAt`.

**The fix already exists as a shipped, one-line pattern** in the SHARED-folder analog `updateSharedFile` (client.ts ~L5239-5252, explicitly labeled "68.2-02 (Rule 1 fix)"): `this.listingCache.delete(live.ipnsName)` before the `resolveListingChildren` + emit call. `maybeRepublishFolderForFileMigration` (the owned-path equivalent, client.ts ~L3801-3845) is missing this exact line.

**Planner action:** Reframe SC#4's task as "add `this.listingCache.delete(folderIpnsName)` to `maybeRepublishFolderForFileMigration`, gated behind the locked 'did size/mtime actually change' check" rather than "refresh a SealedChildRef field" — the latter does not exist to refresh. This is a MUCH smaller fix than the todo implies (one line + one regression test), not a schema/mirror change.

### Critical Finding 2: The write-body CAS-merge is a naive union that will resurrect an SC#1 delete under a concurrent-write race

`packages/sdk-core/src/folder/registration.ts` `updateFolderMetadataAndPublish`'s `merge()` callback (~L324-338) unions `currentWriteChildren` and `remoteWriteChildren` by `childId`, remote-wins-on-conflict, with **no base snapshot and no deletion-pruning** — unlike the read-plane's `mergeChildren` (`packages/sdk-core/src/folder/merge.ts`), which does a proper 3-way diff and explicitly "prunes intentional deletes: a base entry absent from BOTH local AND remote" (merge.ts L37-44).

The write-plane merge's own comment (registration.ts ~L239-241) states the design rationale: "write plane is add-only here — deletes are preserved verbatim per D-03/68.1-02 — so a union never resurrects an intentionally dropped entry." **This premise is exactly what SC#1 is about to falsify.** Once `deleteItem` actually drops a `WriteChildRef` (SC#1) or `restoreFromBin` moves one (SC#3), a concurrent writer's publish racing the SAME folder — hitting the `publishWithCas` 409-retry path — will have that `childId` in `remoteWriteChildren` (if the concurrent writer's snapshot predates the delete) and the union will silently RESURRECT the write-chain entry SC#1 just removed.

This is a genuine, narrow, real race (the `reconcileFolderSequence` pre-check, SC#3/D-04 from Phase 65, closes the common case but not the CAS-retry-internal race, which is a different layer — `publishWithCas`'s own 409 handling, triggered by a TOCTOU gap between the pre-check and the actual publish).

**No existing test exercises this.** `packages/sdk-core/src/__tests__/folder/write-body.test.ts` covers only the seal shape, not CAS-merge/conflict behavior. `packages/sdk-core/src/__tests__/folder/registration.test.ts` L174 ("two CAS encode attempts (on retry) use the same nodeId") is the closest existing template for a 409-retry test and should be used as the starting point for a new regression test.

**Planner action:** This is NOT one of the 9 named todos, but it is load-bearing for SC#1's stated correctness goal ("no unbounded write-chain growth" implicitly also means "no resurrected entries"). Recommend either (a) a small task to make the write-body merge base-aware (thread a `baseWriteChildren` snapshot through, mirror `mergeChildren`'s prune-on-absent-from-both logic keyed by `childId`), or (b) explicitly document this as an accepted residual race (same severity class as the pre-68.1 read-plane race that 65/D-04 closed) and defer to a future phase, but do NOT silently ship SC#1 without addressing or explicitly deferring this — the planner must make an active decision here, not an accidental omission.

### Critical Finding 3: `moveInSharedFolder` has ZERO regression coverage today — SC#5's "gate with sdk unit suites" has nothing to gate against

`packages/sdk/src/__tests__/move-in-shared-folder.test.ts` (13 tests) is entirely wrapped in `describe.skip('CipherBoxClient.moveInSharedFolder — TODO(phase 63)', ...)` and `describe.skip('moveInSharedFolder stateless op — TODO(phase 63)', ...)` (confirmed via `vitest run`: "13 tests | 13 skipped"). The file also imports retired core types (`FolderChild`, `FilePointer`, `FolderEntry` — none of which exist in `@cipherbox/core` today; confirmed via grep). Additionally, `tests/web-e2e/tests/writable-shares.spec.ts` — the phase brief's named e2e gate for SC#5 — has **no move test at all** (confirmed via grep for "move"/"Move": zero hits outside an unrelated comment).

**Planner action:** SC#5 cannot be meaningfully "gated" by existing suites — both named regression surfaces are currently inert for this function. The plan MUST include a NEW test (unit, e2e, or both) that actually exercises `moveInSharedFolder`'s REACHABLE branch (the `else` — `shareKeys.length === 0` — path) before/after the dead-branch removal, or the removal ships with no safety net. Un-skipping and modernizing all 13 existing tests is likely too large for this phase (they test the branch being DELETED); a smaller, targeted new test covering the reachable path is the pragmatic scope.

## Common Pitfalls

### Pitfall 1: `deleteItem`'s `childId` is an ipnsName, not the node UUID `WriteChildRef.childId` needs

**What goes wrong:** `deleteItem(folderIpnsName, childId)`'s `childId` param is matched against `SealedChildRef.ipnsName` (`sdkCore.deleteFromFolder`, `packages/sdk-core/src/folder/metadata-ops.ts` L62: `params.children.findIndex((c) => c.ipnsName === params.childId)`). `WriteChildRef.childId` is the node's hyphenated UUID (`published.id`), a DIFFERENT value. A naive `writeChildren.filter(wc => wc.childId !== childId)` using the read-plane `childId` param will never match anything — it's comparing an ipnsName against a UUID.

**Why it happens:** `SealedChildRef` (NODE-03) deliberately carries no UUID field; the UUID only lives on the child's own `PublishedNode.id` (plaintext envelope) and inside `WriteChildRef.childId`. `moveItem` already solves this correctly (resolves `childPub.id` via `resolveIpnsRecord`+`fetchFromIpfs` or the `resolvePublishedNode` helper before touching `writeChildren`) — `deleteItem` needs the same extra resolve step.

**How to avoid:** After `sdkCore.deleteFromFolder` returns `removedItem: SealedChildRef`, call `this.resolvePublishedNode(removedItem.ipnsName)` to get `.published.id`, THEN filter `writeChildren` by that UUID.

**Warning signs:** A regression test that asserts "write-chain length shrinks by 1" but constructs its fixture using the SAME value for a SealedChildRef's `ipnsName` and a WriteChildRef's `childId` would pass even with the naive/broken filter — make sure the test fixture uses genuinely DIFFERENT values for these two fields (as production data always does) to catch this class of bug.

### Pitfall 2: A resolve failure while looking up the removed item's UUID must not block the delete

**What goes wrong:** If the extra `resolvePublishedNode(removedItem.ipnsName)` call (Pitfall 1) itself fails (item's own IPNS record already unresolvable — e.g. a prior partial-delete, or a network blip), a naive implementation might let that failure propagate and abort the whole `deleteItem` call, even though the read-plane deletion already fully succeeded.

**Why it happens:** SC#1 is explicitly a hygiene fix ("not a data-loss risk, not a mis-traversal risk... dead weight" per the todo) — it should never make delete LESS reliable than it is today.

**How to avoid:** Wrap the UUID-resolve-and-filter step in its own try/catch (or treat a null resolve as "skip the write-chain trim, log a warning, proceed with the read-plane delete"), matching the fail-open posture the todo describes for this specific fix. This is different from SC#2's fail-closed requirement — do not conflate the two.

### Pitfall 3: `getWriteBodyParams` fail-closed (SC#2) must not turn EVERY read-only-device fallback into a throw

**What goes wrong:** The zero-writeKey read-only-device fallback (`if (!wk || wk.length !== 32 || wk.every((b) => b === 0)) return {};`) is a DIFFERENT, intentional, still-fail-open case from the "real writeKey present but resolve missed" case SC#2 targets. A careless fix that makes the whole function throw on ANY resolve-related null would also break the legitimate read-only path.

**Why it happens:** The function has two distinct null/absent conditions guarding two different scenarios (zero-writeKey vs. missing-resolve), and they're adjacent in the code (client.ts L1244-1254 / bin/index.ts L76-84).

**How to avoid:** The fail-closed change applies ONLY to the branch at `if (!resolved || !resolved.published.writeSealed)` — and specifically only when `wk` IS a real (non-zero, 32-byte) key (already guaranteed by that point, since the zero-key branch already returned early). Distinguish "resolve genuinely returned null" (transient network miss — the SC#2 target) from "resolve returned a record with no writeSealed field" (a legitimately never-write-capable folder, pre-D-03 — should this also throw, or is it a distinct case?). **This distinction is not resolved by the todo text and should be confirmed at plan time**: the todo's problem statement specifically says "TRANSIENT IPNS resolve miss" (i.e., `!resolved`), not "resolved but no write-body" — recommend fail-closed ONLY on `!resolved` when `wk` is real, and leave `!resolved.published.writeSealed` as the existing `writeChildren: []` fail-open (a structurally-absent write-body is not a transient miss).

### Pitfall 4: SC#3's re-homing needs the DEST-mirror generation from the TARGET folder, but the moved node's generation witness during a bin-restore comes from `BinEntry.nodeRef.generation` (captured at delete time), not a fresh child resolve

**What goes wrong:** `moveItem`'s re-homing uses `destEntry.generation` — the destination `SealedChildRef`'s OWN generation mirror, freshly created during THIS move's read-plane re-seal. `restoreFromBin`'s restored `SealedChildRef` (bin/index.ts ~L567-573) is built directly from `entry.nodeRef.generation` (captured at soft-delete time, NOT refreshed). If the write-chain re-homing re-uses this same `generation` value as the AAD input for `sealChildWriteKey` under the destination writeKey, it must be the SAME value used for the read-plane re-seal in the SAME restore call (consistency within one call, not staleness against the live network) — verify this is threaded consistently when implementing SC#3, mirroring how `moveItem` uses `destEntry.generation` for BOTH its read-plane reseal AND its write-plane reseal (client.ts L2724 vs L2792/2799 — same value, both times).

**How to avoid:** Use `restoredItem.generation` (the freshly-built `SealedChildRef.generation`, which already equals `nodeRef.generation`) as the write-plane reseal's generation AAD too — do not introduce a second, independently-derived generation value.

### Pitfall 5: The dead `moveInSharedFolder` branch removal touches an "unreachable but currently type-checked" API surface

**What goes wrong:** `getShareKeysFn` is a real, type-checked parameter on a PUBLIC SDK method (`moveInSharedFolder`). Two `apps/web` call sites (`useSharedWriteOps.ts` L219, L260) currently pass `fetchShareKeys` (itself a stub always returning `[]`, `share.service.ts:193`) into it. Removing the param without updating both call sites breaks the web build's typecheck immediately (per CLAUDE.md's `pnpm api:generate`/typecheck discipline and the project's cross-package dist-staleness gotcha).

**How to avoid:** This is a small, mechanical, same-PR edit — update both call sites to drop the arg when the SDK signature drops the param. Not a design risk, just a "don't forget the caller" checklist item.

## Code Examples

### The full fail-open moveItem re-homing block (reference for SC#3's design, already verified against live code)

```typescript
// Source: packages/sdk/src/client.ts moveItem, ~L2753-2818 (68.1-31, shipped)
// Preserve BOTH folders' existing write-bodies on republish (D-03).
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
```

### The listingCache invalidation one-liner (SC#4's actual fix, already shipped for the shared-path sibling)

```typescript
// Source: packages/sdk/src/client.ts updateSharedFile, ~L5250-5252 (68.2-02 Rule 1 fix)
const live = this.sharedFolderTree.get(shareId);
if (live) {
  this.listingCache.delete(live.ipnsName);
  // ... then resolveListingChildren + emit, as before
}
```

### The zeroize-on-error-path fix for `updateSharedSingleFile` (todo, exact target)

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

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `SealedChildRef.size`/`modifiedAt` display mirror (updated at child creation, preserved across moves) | `ResolvedChild` — each child's own Node resolved fresh per folder-load, cached by `listingCache` keyed on parent sequence | Phase 68.2-12 (commit `3e1fcb176`, PR #589 area) | SC#4's todo (written against the mirror-era code) is stale in its problem description; the STALENESS SYMPTOM persists but via a different mechanism (cache, not mirror field) — see Critical Finding 1 |
| Legacy `share_keys` fan-out table for shared-folder write-key resolution | Write-chain walk from `SharedFolderState` (unseal source write-body, one-hop lookup by `childId`) | Phase 68.1-20 (`fetchShareKeys` now hard-returns `[]`) | The `moveInSharedFolder` `shareKeys.length > 0` branch is dead code from this transition — SC#5 target |

**Deprecated/outdated:**
- `FolderChild`/`FilePointer`/`FolderEntry` types (retired Phase 62, replaced by `SealedChildRef`) — still referenced in `move-in-shared-folder.test.ts`'s imports (dead-branch-only test file, will need attention alongside or after SC#5).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The `getWriteBodyParams` fail-closed fix (SC#2) should apply ONLY to `!resolved` (transient miss), not `!resolved.published.writeSealed` (structurally never-write-capable) | Pitfall 3 | If wrong, a legitimate pre-D-03 read-only folder could start throwing where it previously degraded gracefully to `writeChildren: []` — needs explicit confirmation at plan/discuss time, not assumed |
| A2 | `getFileIpnsKeyFn`'s legacy fallback in `updateSharedFile` (site 5 of the fail-open table) is out of scope for the SC#6 primitive extraction | SC#6 fail-open table | If this fallback is actually dead (like `fetchShareKeys`), it should be investigated/removed alongside SC#5's dead-code removal rather than preserved as a "4th mode" — not verified in this research pass |
| A3 | The write-body CAS-merge landmine (Critical Finding 2) is real and exploitable, not just theoretically possible | Critical Finding 2 | This is grounded in reading the merge code and its own comments, not in reproducing the race — if the planner disagrees this is exploitable in practice (e.g. because `reconcileFolderSequence` closes it more completely than analyzed), downgrade from "must address" to "document as known limitation" |

## Open Questions

1. **Should `deleteItem`'s new UUID-resolve step also run for `bin/index.ts`'s `addToBin` (soft-delete)?**
   - What we know: `addToBin` (bin/index.ts ~L452-459) has an IDENTICAL "preserve write-body verbatim, removal owned by 68.1-02" comment to `deleteItem`'s pre-fix state. SC#1's literal wording only names `deleteItem` (client.ts hard-delete, which explicitly does NOT go through the bin).
   - What's unclear: whether leaving `addToBin` un-fixed creates an inconsistency where hard-delete shrinks the write-chain but soft-delete (the much more common UI path — "move to bin") still doesn't, OR whether this is intentionally deferred because SC#3's restoreFromBin re-homing fix (which loads the ORIGINAL parent) will incidentally also drop the ref from the original parent as a side effect of the re-home (meaning addToBin's non-fix is fine as long as SC#3 ships, since the ref only truly goes unbounded if an item is soft-deleted and NEVER restored, sitting in the bin/parent forever).
   - Recommendation: Plan-time decision — if SC#3 makes restoreFromBin re-home (which requires touching the ORIGINAL parent and would naturally support dropping-if-permanently-deleted too), consider whether `permanentDeleteFromBin` also needs the same UUID-resolve-and-drop fix `deleteItem` gets, for full symmetry. Flag to the user/planner rather than silently expanding scope.

2. **Does the `writable-shares` web-e2e spec need a NEW test added, or is a new SDK unit test sufficient for SC#5's regression gate?**
   - What we know: Critical Finding 3 established zero coverage exists today in either location.
   - What's unclear: whether adding e2e coverage (slower, but exercises the real API round-trip per this phase's stated primary regression-gate philosophy) or a new focused SDK unit test (faster, more isolated) is the right call for this specific fix.
   - Recommendation: Given the phase brief's own framing ("the primary regression gate is the sdk-e2e suite... plus web-e2e for the shared paths"), lean toward a NEW unit test in a rewritten (not skip'd) `move-in-shared-folder.test.ts` for the mechanical dead-code-removal safety net, and treat a `writable-shares.spec.ts` move-test addition as a nice-to-have unless the plan-checker requires e2e coverage for this class of change.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Node.js / vitest | SDK unit test suites (`packages/sdk`, `packages/sdk-core`) | ✓ (confirmed via successful `vitest run` during this research) | vitest 3.2.4 | — |
| Docker (redis 6380, kubo, postgres) + local API (`pnpm --filter @cipherbox/api dev`) | `tests/sdk-e2e` suites, incl. `write-chain-rotation.test.ts` | Not verified in this research session (no live-stack check performed) | — | If unavailable at execution time, sdk-e2e work must be deferred to a session with the stack up — this phase's SC#1/#2/#3 regression tests are explicitly required to run against the live stack per the phase brief |
| Playwright | `tests/web-e2e` (`writable-shares.spec.ts`) | Not verified in this research session | — | Same as above — web-e2e verification requires the full local stack + browser |

**Missing dependencies with no fallback:** None identified — this is a code-only phase; the live-stack dependencies are for VERIFICATION, not implementation, and are standard, already-documented project setup (see MEMORY.md "Web-e2e local full-suite recipe" / "sdk-e2e live checkpoint run" entries).

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Vitest 3.2.4 (unit: `packages/sdk`, `packages/sdk-core`), Vitest (sdk-e2e: `tests/sdk-e2e`, live-stack), Playwright (web-e2e: `tests/web-e2e`) |
| Config file | `packages/sdk/vitest.config.ts`; `tests/sdk-e2e/package.json` scripts; `tests/web-e2e` Playwright config |
| Quick run command | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/<file>.test.ts` |
| Full suite command | `pnpm --filter @cipherbox/sdk test` (unit); `pnpm --filter sdk-e2e test` (live-stack, requires docker+API up); `pnpm --filter web-e2e test` (Playwright, requires full stack) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SC#1 | `deleteItem` drops removed child's `WriteChildRef`; write-chain length shrinks | unit + sdk-e2e | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/delete-item.test.ts` (new) + a live sdk-e2e assertion in an existing or new suite | ❌ Wave 0 — no dedicated `delete-item.test.ts` found; check for delete coverage inside a broader client test file before assuming net-new |
| SC#2 | `getWriteBodyParams` fails closed on transient resolve miss with real writeKey present | unit (both client.ts and bin/index.ts copies) + sdk-e2e (concurrent-ops resolve-failure injection, per todo) | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/<new-or-existing>.test.ts` | ❌ Wave 0 — needs a resolve-mock-returns-null-with-real-writeKey unit test for BOTH copies |
| SC#3 | `restoreFromBin` to a different parent re-homes `WriteChildRef` | sdk-e2e, mirroring `move-restore-content.spec.ts` test 2b (web-e2e) for the restore direction — the phase brief explicitly names this as the pattern to mirror | `pnpm --filter web-e2e test -- move-restore-content` and/or a new sdk-e2e suite test | ⚠️ `tests/web-e2e/tests/move-restore-content.spec.ts` exists (confirmed) — read its "test 2b" before writing the restore-direction mirror to match its structure exactly |
| SC#4 | `replaceFile`/`restoreFileVersion` refresh the listing after in-place edit | web-e2e (upload a file, replace with larger content, assert list size/date update) + unit (listingCache invalidated) | New Playwright test in an existing file-operations spec + `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/<file>.test.ts` | ❌ Wave 0 — no existing test asserts listingCache invalidation on `maybeRepublishFolderForFileMigration` |
| SC#5 | Dead `moveInSharedFolder` branch removed; reachable path still works | unit (new, targeted — NOT the full 13-test skip'd suite) + optionally web-e2e | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/move-in-shared-folder.test.ts` (after rewrite) | ⚠️ File exists but is 100% `describe.skip`'d and tests the WRONG (dead) branch — see Critical Finding 3 |
| SC#6 | Dedupe write-plane helpers; no behavior change per site | unit (existing suites must still pass unchanged — this is a refactor, its "test" is the FULL existing suite staying green) + `write-chain-rotation.test.ts` seed-by-provenance fix + `upload-batch.test.ts` mock-shape fix | `pnpm --filter @cipherbox/sdk test` (full) + `pnpm --filter sdk-e2e test -- write-chain-rotation` | ✅ Both target files exist; fixes are localized edits to existing files |
| todo (zeroize) | `updateSharedSingleFile` zeros both keys even when the SECOND unwrapKey throws | unit | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/update-shared-single-file.test.ts` | ⚠️ File exists (confirmed, 4 existing `it` blocks) but no test currently covers this exact throw-on-second-unwrap scenario — needs a new `it` block |

### Sampling Rate
- **Per task commit:** `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/<touched-file>.test.ts`
- **Per wave merge:** `pnpm --filter @cipherbox/sdk test` (full unit) + relevant `sdk-e2e`/`web-e2e` targeted spec (per-MEMORY.md guidance: don't run full e2e suites gratuitously; scope to the touched area)
- **Phase gate:** Full `sdk-e2e` suite green (live docker+API stack) before `/gsd-verify-work` — per the phase brief's own framing ("the primary regression gate is the sdk-e2e suite... plus web-e2e for the shared paths"), this phase should NOT be considered verified on unit tests alone.

### Wave 0 Gaps
- [ ] `packages/sdk/src/__tests__/delete-item.test.ts` (or equivalent existing-file addition) — covers SC#1's write-chain-shrink assertion, using DISTINCT ipnsName vs UUID values in the fixture (Pitfall 1)
- [ ] A resolve-returns-null-with-real-writeKey unit test for BOTH `getWriteBodyParams` copies (client.ts private method — test via a public method that calls it, e.g. `deleteItem` or `moveItem`; bin/index.ts's copy — test via `addToBin`/`restoreFromBin`) — covers SC#2
- [ ] A new or extended sdk-core `write-body.test.ts`/`registration.test.ts` covering the CAS-merge-under-409-with-a-concurrent-delete race (Critical Finding 2) — only if the planner decides to fix rather than defer this
- [ ] A rewritten, un-skipped `move-in-shared-folder.test.ts` targeted test for the REACHABLE branch, OR a new web-e2e move test in `writable-shares.spec.ts` — covers SC#5 (Critical Finding 3, Open Question 2)
- [ ] `packages/sdk/src/__tests__/update-shared-single-file.test.ts` — new `it` block: second `unwrapKey` call rejects, assert `fileReadKey` was still zeroed (currently no such test exists per the 4 confirmed `it` blocks)

*(No framework installs needed — vitest/Playwright are already configured and working, confirmed by live test runs during this research.)*

## Landmines / Pitfalls

This section consolidates the highest-severity items already detailed above, for quick planner reference:

1. **[BLOCKING for SC#1 correctness under concurrency]** Write-body CAS-merge is a naive union with no deletion-pruning (Critical Finding 2) — SC#1 must either fix this or explicitly accept/document the residual race.
2. **[BLOCKING for SC#4 as literally worded]** The `SealedChildRef` size/modifiedAt mirror the todo describes does not exist in the current tree (Critical Finding 1) — implement against `listingCache` invalidation instead, using the shipped `updateSharedFile` pattern as the template.
3. **[BLOCKING for SC#5's "gate with sdk unit suites" instruction]** Zero regression coverage exists for `moveInSharedFolder` today, in either unit or e2e form (Critical Finding 3) — a new test is mandatory, not optional, or the fix ships with no safety net.
4. **[Correctness gap in SC#1's naive implementation]** `deleteItem`'s `childId` param is an ipnsName; `WriteChildRef.childId` is a UUID — a direct string-compare filter will silently no-op (Pitfall 1).
5. **[Design gap in SC#3 as scoped]** `restoreFromBin` currently never loads the ORIGINAL parent folder at all — re-homing requires a structural addition (load original parent via `BinEntry.originalParentIpnsName`, extend `binOps.restoreFromBin`'s signature), not just an unseal/reseal tweak (Pattern 2 discussion).
6. **[Scope creep risk]** `bin/index.ts`'s `addToBin` (soft-delete) has the SAME "preserve write-body verbatim, 68.1-02" deferred comment as `deleteItem` did, but SC#1 only names `deleteItem` — Open Question 1 flags this for an explicit plan-time scoping decision, not a silent expand-or-skip.
7. **[Cross-package edit required]** SC#5's `getShareKeysFn` removal requires updating 2 call sites in `apps/web/src/hooks/useSharedWriteOps.ts` in the same change (Pitfall 5) — small, but easy to miss if the SDK and web edits land in separate commits/waves.

## Sources

### Primary (HIGH confidence — direct code reads against the current tree, this session)
- `packages/sdk/src/client.ts` (6101 lines, read in full-function excerpts covering `getWriteBodyParams`, `adoptPublishedFolderState`, `dfsFindFolder`, `moveItem`, `deleteItem`, `resolveFileWriteChainKeys`, `resolveShareEncryptedWriteKey`, `maybeRepublishFolderForFileMigration`, `replaceFile`, `restoreFileVersion`, `deleteFileVersion`, `restoreFromBin`, `updateSharedFile`, `updateSharedSingleFile`, `moveInSharedFolder`, `enumerateSharedSubtree`, `resolveSharedSubfolderWriteKey`, `resolveListingChildren`, `gatedResolveChild`, `listFolder`)
- `packages/sdk/src/bin/index.ts` (777 lines, read in full for `getWriteBodyParams`/`adoptPublishedFolderState` twins, `addToBin`, `restoreFromBin`)
- `packages/sdk/src/folder-listing.ts` (full file — `resolveChildren`/`ResolvedChild`)
- `packages/core/src/node/types.ts` (`SealedChildRef`/`WriteChildRef`/`NodeWriteBody` definitions and the 68.2-12 revert documentation)
- `packages/core/src/bin/types.ts` (`BinEntry` fields, incl. `nodeRef`, `nodeReadKey`, `originalParentIpnsName`)
- `packages/sdk-core/src/folder/registration.ts` (`updateFolderMetadataAndPublish`, the CAS-merge logic — Critical Finding 2 source)
- `packages/sdk-core/src/folder/merge.ts` (`mergeChildren` reference 3-way-diff pattern)
- `packages/sdk-core/src/folder/metadata-ops.ts` (`deleteFromFolder` — confirms ipnsName-keyed matching, Pitfall 1 source)
- `packages/sdk-core/src/file/index.ts`, `packages/sdk-core/src/vault/index.ts`, `packages/sdk-core/src/folder/registration.ts` (TEE-wrap triplication sites)
- `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` (full read of the seed-index section)
- `packages/sdk/src/__tests__/upload-batch.test.ts`, `packages/sdk/src/__tests__/move-in-shared-folder.test.ts`, `packages/sdk/src/__tests__/update-shared-single-file.test.ts`, `packages/sdk-core/src/__tests__/folder/write-body.test.ts`, `packages/sdk-core/src/__tests__/folder/registration.test.ts` (read + live-executed via `vitest run` this session)
- `apps/web/src/hooks/useSharedWriteOps.ts`, `apps/web/src/services/share.service.ts` (`fetchShareKeys` caller/producer confirmation)
- `git log` for `packages/core/src/node/types.ts` (confirmed the 68.2-12 revert commit sequence: `3e1fcb176`, `89dce548a`, `f8c3281dd`, `37bf74230`)
- Live `vitest run` executions this session: `move-in-shared-folder.test.ts` (13 skipped), `upload-batch.test.ts` (19 passed)
- 9 source todo files in `.planning/todos/pending/` (read in full)

### Secondary (MEDIUM confidence)
- None — this phase required no external documentation lookup; all claims are grounded in direct reads of the current repository state.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: N/A — no external dependencies in this phase
- Architecture: HIGH — every pattern cited is read directly from shipped, working code in the same file/module
- Pitfalls: HIGH — Critical Findings 1-3 and Pitfalls 1-5 are all derived from direct code reads and, where applicable, live test execution, not inference

**Research date:** 2026-07-10
**Valid until:** Short-lived — this research is tied to the EXACT current state of `client.ts`/`bin/index.ts`/`registration.ts`. Any other phase landing on these files before Phase 72 executes invalidates the line-number references (though the architectural findings, especially Critical Findings 1-3, would remain valid). Recommend re-verification of exact line numbers immediately before planning if more than a few days elapse.
