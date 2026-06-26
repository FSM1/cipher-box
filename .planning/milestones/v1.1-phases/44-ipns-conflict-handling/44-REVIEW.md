---
phase: 44-ipns-conflict-handling
reviewed: 2026-06-13T00:00:00Z
depth: standard
files_reviewed: 13
files_reviewed_list:
  - apps/web/src/hooks/useFileOperations.ts
  - apps/web/src/hooks/useFileVersions.ts
  - packages/sdk-core/src/__tests__/file.test.ts
  - packages/sdk-core/src/__tests__/folder-merge.test.ts
  - packages/sdk-core/src/__tests__/folder.test.ts
  - packages/sdk-core/src/errors.ts
  - packages/sdk-core/src/file/index.ts
  - packages/sdk-core/src/folder/index.ts
  - packages/sdk-core/src/folder/merge.ts
  - packages/sdk-core/src/index.ts
  - packages/sdk/src/bin/index.ts
  - packages/sdk/src/client.ts
  - packages/sdk/src/share/shared-write.ts
findings:
  critical: 2
  warning: 8
  info: 7
  total: 17
status: issues_found
---

# Phase 44: Code Review Report

Reviewed: 2026-06-13
Depth: standard
Files Reviewed: 13
Status: issues_found

## Summary

Reviewed the IPNS conflict-handling implementation: the 4-attempt merge-and-republish
loop in `updateFolderMetadataAndPublish`, the three-way `mergeChildren`, the new file
CAS path in `updateFileMetadata` with loser-becomes-version, and all consuming call
sites. Caller sweep verified: every `updateFolderMetadataAndPublish` call site in TS
code (client.ts x7, bin/index.ts x2, shared-write.ts x4, useFileOperations x1,
useFileVersions x2) passes a correct pre-mutation `baseChildren` snapshot; no caller
still consumes the old `{ ipnsRecord }` return shape from `updateFileMetadata`; no
double-publish of file records remains (the redundant `batchPublishIpnsRecords` /
`replaceFileInFolder` calls were removed from `updateSharedFile` and
`handleUpdateFile`). Backoff is bounded, non-409 errors are rethrown immediately, and
no key material or plaintext names are logged or embedded in `ConflictError`.

I also verified server-side that a CAS failure inside a batch publish surfaces as an
HTTP 409 for the whole batch (`apps/api/src/ipns/ipns.service.ts:171` rethrows
`ConflictException`), so the `withConflictRetry` wrapper around `addFileToFolder` /
`addFilesToFolder` in `useFileOperations` still receives a recognizable 409.

However, two critical defects remain. First, the merge loop publishes merged children
to IPNS but never returns them, so every caller's in-memory state silently drops the
other writer's children while holding a fresh sequence number — the very next local
write overwrites the remote children with no 409 to stop it. The lost-update bug is
fixed only for the single write where the conflict fires; it is re-opened one write
later. Second, on the file-conflict path `prunedCids` can include CIDs that are still
referenced by the published merged `versions[]`; callers unpin those CIDs, destroying
restorable version content.

## Critical Issues

### CR-01: Merged children are not returned to callers — next write silently overwrites remote children

**File:** `packages/sdk-core/src/folder/index.ts:197,230` (contract), with affected callers at `packages/sdk/src/client.ts:427-431,514-517,579-584,638-641,791-794,1053-1056`, `packages/sdk/src/bin/index.ts:254-257,353-356`, `packages/sdk/src/share/shared-write.ts:226,327,362,390`, `apps/web/src/hooks/useFileOperations.ts:467-468`

**Issue:** When the loop hits a 409, it merges remote children into
`currentLocalChildren` and publishes the merged set, but returns only
`{ cid, newSequenceNumber }`. Every caller then commits its own pre-merge
`updatedChildren` into local state together with the fresh `newSequenceNumber`
(e.g. `client.ts:791-792`: `folder.children = updatedChildren; folder.sequenceNumber = newSequenceNumber`).

Concrete lost-update trace:

1. Device A holds `children=[X]`, seq 4. Device B publishes `Y` (server seq 5).
2. A uploads `F`: publishes `[X, F]` expectedSeq=4 → 409 → merge → publishes `[X, F, Y]` at seq 6. Returns seq 6.
3. A stores `children=[X, F]` (no `Y`) and seq 6.
4. A's next write (rename, delete, second upload) composes from `[X, F]` and publishes with expectedSeq=6 — which matches the server, so CAS passes with NO 409 and no merge. `Y` is gone from the authoritative record.

If `Y` is a `FolderEntry`, its wrapped `folderKeyEncrypted`/`ipnsPrivateKeyEncrypted`
are lost with it, making the entire subtree unrecoverable. IPNS polling cannot heal
this: after step 4 the published record itself lacks `Y`. The same staleness exists in
`shared-write.ts` (returns its own pre-merge `updatedChildren` to `useSharedWriteOps`)
and in the fire-and-forget republish in `useFileOperations.ts:458-468` (store gets
`newSequenceNumber` but keeps pre-merge children).

**Fix:** Return the published children and adopt them in every caller:

```ts
// folder/index.ts
return { cid, newSequenceNumber: newSeq, publishedChildren: currentLocalChildren };

// client.ts (and bin, shared-write, web hooks)
const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish({...});
folder.children = publishedChildren;
folder.sequenceNumber = newSequenceNumber;
```

Alternatively (weaker) emit/flag `merged: true` and force callers to re-resolve, but
returning `publishedChildren` is exact and free.

### CR-02: `prunedCids` on the file 409 path can list CIDs still referenced by the published metadata — downstream unpin destroys version content

**File:** `packages/sdk-core/src/file/index.ts:251-263,347-355` (consumed at `apps/web/src/hooks/useFileOperations.ts:507-511`)

**Issue:** Step 1 computes `prunedCids` against the local pre-conflict version list
(`allVersions.slice(maxVersions)`). On 409, the published `versions[]` is recomputed
by `mergeVersions(winner.versions + loserAsVersion, remoteMeta.versions, maxVersions)`,
and the step-1 `prunedCids` are blindly accumulated (`prunedCids = [...prunedCids, ...extraPruned]`)
without re-checking them against the final merged list.

Reachable trace (versions diverged via the `deleteVersion` feature):

1. `currentMetadata.versions = [v1, v2, v3]`, `maxVersions = 3` (at cap).
2. Local edit with `createVersion=true` → step 1 prunes `v3`: `prunedCids = [v3.cid]`.
3. Remote device concurrently ran `deleteVersion` on `v1`,`v2` → `remoteMeta.versions = [v3]`, and remote wins on `modifiedAt`.
4. `mergeVersions([v3, loserAsVersion], [v3], 3)` → merged = `[loserAsVersion, v3]` (2 ≤ 3), `extraPruned = []`.
5. Published metadata references `v3`, but the function returns `prunedCids = [v3.cid]`.
6. `useFileOperations.ts:507` unpins `v3.cid` → the version listed in the live metadata has its content unpinned → restore of that version fails permanently. Data loss.

The same desync occurs whenever remote's version list is shorter than local's (version
deletion, differing `maxVersionsPerFile` across devices — web passes a vault setting,
`shared-write.ts` uses the default 10).

**Fix:** After building `mergedMetadata`, filter the accumulated set against what the
published record actually references (also dedupes the double-`v3` case):

```ts
const referenced = new Set([
  mergedMetadata.cid,
  ...(mergedMetadata.versions ?? []).map((v) => v.cid),
]);
prunedCids = [...new Set([...prunedCids, ...extraPruned])].filter((c) => !referenced.has(c));
```

## Warnings

### WR-01: Remote deletes are unconditionally resurrected by any conflicting local writer

**File:** `packages/sdk-core/src/folder/merge.ts:53-57`

**Issue:** The `!r && b` branch keeps the local entry whenever it exists, with no
`modifiedAt` check — unlike the local-delete branch (lines 47-52), which honors the
delete unless remote edited after base. Result: device A deletes file `F`; device B
(whose loaded snapshot still contains `F` untouched) renames a sibling concurrently →
409 on B → merge re-adds `F`. If A's delete went through `deleteToBin`/`deleteItem`,
the resurrected `FilePointer` references an IPNS name that was already unenrolled
(`client.ts:653` `fireAndForgetUnenroll`) — a ghost entry, and a duplicate if A later
restores from bin. Delete handling is asymmetric: local deletes can win; remote
deletes never can.

**Fix:** Mirror the edit-beats-delete rule:

```ts
} else if (!r && b) {
  // remote-delete: keep local only if local was edited after base
  if (l && (l.modifiedAt ?? 0) > (b.modifiedAt ?? 0)) {
    merged.push(l);
  }
}
```

If unconditional keep-local is a deliberate D-01 decision, document the
resurrection/ghost-entry consequence at the call site and in the merge header.

### WR-02: When remote wins a file conflict, the loser's `versions[]` is discarded — base content vanishes from history

**File:** `packages/sdk-core/src/file/index.ts:333-351`

**Issue:** `mergeVersions` receives `[...winner.versions, loserAsVersion]` and
`remoteMeta.versions`. When remote wins, `winner.versions === remoteMeta.versions`, so
the loser's (local) version list — including the step-1 `VersionEntry` for the
pre-update content (`params.currentMetadata.cid`) created when `createVersion=true` —
is never merged. If the remote writer used `createVersion=false` (text-editor save),
the previous published content disappears from version history entirely (it stays
pinned as an orphan, so it is unrecoverable through the UI and leaks quota).

**Fix:** Merge both sides' version lists plus the loser head:

```ts
const { versions: mergedVersions, prunedCids: extraPruned } = mergeVersions(
  [...(winner.versions ?? []), loserAsVersion, ...(loser.versions ?? [])],
  remoteMeta.versions,
  maxVersions
);
```

### WR-03: `mergeChildren` can produce duplicate names in one folder

**File:** `packages/sdk-core/src/folder/merge.ts:38-46`

**Issue:** local-add and remote-add of the same `name` with different `id`s both
survive the merge (children are keyed by id only). Every other code path enforces
unique names (`addFilePointerToFolder:339`, `renameInFolder:296`, `moveItem:383`,
`uploadFile` in client.ts:685), and the desktop FUSE mount cannot represent two
dirents with the same name. Post-merge, duplicate names persist until manual rename.

**Fix:** After the merge loop, detect name collisions among entries with distinct ids
and deterministically rename the loser (e.g. suffix `" (conflict)"` keyed by lower
`modifiedAt`/id), or document that consumers must tolerate duplicate names.

### WR-04: Stale contract comment in `handleUpdateFile` contradicts the code below it

**File:** `apps/web/src/hooks/useFileOperations.ts:347-350`

**Issue:** The docblock states "No conflict detection here -- handleUpdateFile
publishes only the per-file IPNS record. Folder metadata is NOT touched, so no 409 is
possible." Both claims are now false: `updateFileMetadata` performs CAS with conflict
merge, and step 6b (line 458) publishes folder metadata. Misleading docs on a
concurrency-sensitive path invite regressions.

**Fix:** Rewrite the NOTE to describe the actual behavior (file CAS inside
`updateFileMetadata`; fire-and-forget folder republish with three-way merge).

### WR-05: Version restore/delete still publish file IPNS without CAS

**File:** `apps/web/src/hooks/useFileVersions.ts:94-111,234-251` (via `apps/web/src/services/file-metadata.service.ts:415-421,484-490` and `replaceFileInFolder`)

**Issue:** Phase 44 closed the file TOCTOU window only for `updateFileMetadata`.
`restoreVersion` and `deleteVersion` still resolve the sequence number, build a record
at `seq + 1`, and publish via `replaceFileInFolder` → `batchPublishIpnsRecords` with
no `expectedSequenceNumber`. A concurrent content edit (which now goes through CAS)
racing a restore/delete silently loses one of the writes — the exact bug class this
phase targets, on the same per-file IPNS names.

**Fix:** Route restore/delete through the CAS publish path (pass
`expectedSequenceNumber` in the record payload, or refactor them onto
`updateFileMetadata`'s publish helper) and handle 409 like content edits.

### WR-06: `updateFileMetadata` zeroizes the caller-owned private key buffer in-place — undocumented, retry footgun

**File:** `packages/sdk-core/src/file/index.ts:393-397`

**Issue:** The `finally` block fills `params.fileIpnsPrivateKey` with zeros. This is
an in-place mutation of a caller-owned buffer that is not mentioned in the function's
JSDoc `@param` docs (only in an inline comment). Current callers happen to re-zero and
discard the buffer themselves (`useFileOperations.ts:433`, `shared-write.ts:489`), so
nothing breaks today, but any future caller that retries the call (e.g. wrapping it in
`withConflictRetry`) will sign the second attempt with an all-zero seed, producing a
record for the wrong derived key that fails server validation in a confusing way.
Sibling functions with identical signatures (`restoreVersion`, `deleteVersion` in the
web service) do NOT zero their input, so ownership semantics are inconsistent.

**Fix:** Document the buffer-consumption contract in the JSDoc (`@param
fileIpnsPrivateKey - consumed; zeroed before return`) and/or operate on an internal
copy (`const key = new Uint8Array(params.fileIpnsPrivateKey)`) zeroed in `finally`,
leaving the caller's buffer ownership intact.

### WR-07: `ConflictError` is invisible to `@cipherbox/sdk`'s `isConflictError` / `withConflictRetry`

**File:** `packages/sdk-core/src/errors.ts:8-22` vs `packages/sdk/src/error.ts:28-37`

**Issue:** `ConflictError` carries no `status` field, so `isConflictError()` returns
false for it and `withConflictRetry` rethrows without resync. Today no in-scope caller
wraps `updateFolderMetadataAndPublish` in `withConflictRetry`, but the two packages
now expose two near-homonym predicates (`isConflictError` vs `isConflictExhausted`)
with disjoint matching — an easy trap for the next caller who wraps a folder op and
expects the resync path to fire on exhaustion.

**Fix:** Add `readonly status = 409` to `ConflictError` (making it match both
predicates), or re-export `isConflictExhausted` from `@cipherbox/sdk` next to
`isConflictError` with a doc note distinguishing raw-409 vs exhausted-retries.

### WR-08: Conflict tests never assert the merged file metadata payload

**File:** `packages/sdk-core/src/__tests__/file.test.ts:234-333`

**Issue:** The two 409-merge tests assert only that `decryptFileMetadata` was called
and that the retry used the fresh sequence number. They never inspect what was passed
to `encryptFileMetadata` on the retry — i.e. the central D-07 invariant
(loser-becomes-version: `loserAsVersion.cid` present, winner's head kept, versions
merged/capped) is untested, which is exactly where CR-02 and WR-02 hide. Similarly,
`folder.test.ts` exercises the merge loop only with `baseChildren: []` (union path);
the delete semantics (local-delete, edit-beats-delete, remote-delete) are tested only
at the pure `mergeChildren` level, never through `updateFolderMetadataAndPublish`.

**Fix:** Capture `encryptFileMetadata.mock.calls[1][0]` in the conflict tests and
assert `versions` contains the loser's cid and respects the cap; add one folder
conflict test with non-empty `baseChildren` covering a delete case.

## Info

### IN-01: 409-detection snippet duplicated three times

**File:** `packages/sdk-core/src/folder/index.ts:232-234`, `packages/sdk-core/src/file/index.ts:307-309,383-385`

**Issue:** The identical `status === 409 || response?.status === 409` cast-dance is
copy-pasted. **Fix:** Extract `isHttp409(err: unknown): boolean` into
`packages/sdk-core/src/errors.ts`.

### IN-02: Final attempt does a full resolve/fetch/decrypt/merge before throwing

**File:** `packages/sdk-core/src/folder/index.ts:237-269`

**Issue:** On attempt 3's 409, the code still re-resolves, fetches, decrypts, and
merges remote metadata, then throws `ConflictError` — wasted network/crypto work, and
a transient error from that resolve/fetch masks the `ConflictError` the caller
expects. **Fix:** Check `attempt === 3` immediately after confirming the 409.

### IN-03: Failed CAS attempts leave orphaned pinned metadata blobs

**File:** `packages/sdk-core/src/folder/index.ts:214`, `packages/sdk-core/src/file/index.ts:286`

**Issue:** Each loop iteration uploads (pins) an encrypted metadata blob before the
publish; on 409 that CID is never referenced or unpinned. Up to 3 orphan blobs per
exhausted folder conflict, 1 per file conflict — slow quota leak. **Fix:**
best-effort `unpinFromIpfs` of the superseded CID when retrying, or track and return
them for cleanup.

### IN-04: Exhaustion test sleeps through real backoff timers

**File:** `packages/sdk-core/src/__tests__/folder.test.ts:315-343`

**Issue:** The 4-attempt exhaustion test executes the real `setTimeout` backoff
(roughly 350-700 ms wall time, jittered). **Fix:** `vi.useFakeTimers()` +
`vi.advanceTimersByTimeAsync`, or inject the delay function.

### IN-05: `file.test.ts` mocks `../errors` with a hand-copied `ConflictError`

**File:** `packages/sdk-core/src/__tests__/file.test.ts:31-46`

**Issue:** `ConflictError` is a pure local class with no heavy deps; duplicating its
implementation inside `vi.mock` risks silent divergence from the real class (the
message-format assertion would keep passing against the copy). **Fix:** Drop the
`vi.mock('../errors')` and let the real module load.

### IN-06: Union-fallback warning fires on every retry iteration via bare `console.warn`

**File:** `packages/sdk-core/src/folder/index.ts:258-263`

**Issue:** A single exhausted call without `baseChildren` logs the same warning up to
4 times, via `console.warn` rather than any injectable logger. Content is safe (IPNS
name only), but it is noisy. **Fix:** Log once per call (hoist a flag above the loop).

### IN-07: Resolve-failure after a 409 is mislabeled as conflict exhaustion

**File:** `packages/sdk-core/src/folder/index.ts:239-241`, `packages/sdk-core/src/file/index.ts:316-318`

**Issue:** When `resolveIpnsRecord` returns null mid-retry, the code throws
`ConflictError` with `attempts: attempt + 1` — callers (e.g.
`useFileOperations.ts:471`) then log "conflict exhausted after retries" for what is
actually a resolution failure, hampering diagnosis. **Fix:** Throw a distinct error
(or include a `reason: 'resolve-failed'` field) for this branch.

---

Reviewed: 2026-06-13
Reviewer: Claude (gsd-code-reviewer)
Depth: standard
