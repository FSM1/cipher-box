---
phase: 44-ipns-conflict-handling
verified: 2026-06-13T01:00:00Z
status: passed
score: 14/14 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 12/14
  gaps_closed:
    - "CR-01: updateFolderMetadataAndPublish now returns publishedChildren; all 14 adoption sites (8 client.ts, 2 bin, 4 shared-write, 4 useSharedWriteOps, 3 web fire-and-forget) store the merged set"
    - "CR-02: prunedCids filtered against referenced Set(mergedMetadata.cid + mergedMetadata.versions[].cid) before return; de-duped; WR-08 file+folder tests assert the invariants"
  gaps_remaining: []
  regressions: []
---

# Phase 44: IPNS Conflict Handling Verification Report

**Phase Goal:** Stop lost updates on concurrent IPNS writes in `packages/sdk-core`: on 409, re-fetch remote folder metadata and merge (children union, per-entry reconcile) before republishing, and extend CAS coverage to file records; full CRDT model explicitly deferred to the CRDT-inbox research todo.

**Verified:** 2026-06-13T01:00:00Z
**Status:** passed
**Re-verification:** Yes — round 2 after gap closure (plans 44-06, 44-07)

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| 1 | D-01: mergeChildren three-way-merges FolderChild[] keyed by id with all 8 permutations | VERIFIED | merge.ts:21-65; folder-merge.test.ts covers all 8 permutations (unchanged from round 1) |
| 2 | D-02: mergeChildren with empty base degrades to children union | VERIFIED | merge.ts:38-61; baseById empty on empty base (unchanged) |
| 3 | D-05: ConflictError class in sdk-core/src/errors.ts with ipnsName/attempts/lastRemoteSeq; isConflictExhausted exported | VERIFIED | errors.ts:8-26; both re-exported from index.ts:2 (unchanged) |
| 4 | D-01/D-03: updateFolderMetadataAndPublish re-fetches+decrypts remote on 409, calls mergeChildren, re-encrypts+re-uploads merged children to fresh CID | VERIFIED | folder/index.ts:246-264; fetchAndDecryptMetadata called; mergeChildren at 251/263; addToIpfs inside loop (unchanged) |
| 5 | D-02: union-fallback warning logged when baseChildren absent | VERIFIED | folder/index.ts:257-263; folder.test.ts:282-313 (unchanged) |
| 6 | D-04: 4-attempt loop with exponential backoff+jitter | VERIFIED | folder/index.ts:205 `for (let attempt = 0; attempt < 4; attempt++)`; retryDelayMs at 41-43 (unchanged) |
| 7 | D-05: ConflictError(ipnsName, 4, lastRemoteSeq) thrown after exhaustion | VERIFIED | folder/index.ts:267-269; folder.test.ts:315-343 (unchanged) |
| 8 | D-06: updateFileMetadata publishes via createAndPublishIpnsRecord with expectedSequenceNumber (CAS) | VERIFIED | file/index.ts:292-299 first attempt; 374-381 retry; expectedSequenceNumber: currentSeq.toString() at both sites (unchanged) |
| 9 | D-07: on file 409 — latest-wins + loser-becomes-version; versions[] merged/deduped/capped; prunedCids returned | VERIFIED | file/index.ts:328-368 implements latest-wins; loserAsVersion at 337-344; mergeVersions at 347-351; reference filter at 364-368 closes CR-02 |
| 10 | D-08: all SDK callers pass pre-mutation baseChildren (8 client.ts, 2 bin, 4 shared-write) | VERIFIED | client.ts: `const baseChildren = [...]` at 411, 496, 623, 729, 971 (5 snapshot sites covering 8 call sites); bin: 243, 342; shared-write: `baseChildren: swCtx.children` at 4 sites (unchanged) |
| 11 | D-08: shared-write.ts updateFileMetadata call rewired to Plan-03 return shape; redundant batchPublishIpnsRecords removed | VERIFIED | shared-write.ts:453-468; no ipnsRecord destructuring; batchPublishIpnsRecords for file absent (unchanged) |
| 12 | D-08: web hook callers pass baseChildren (useFileOperations:460, useFileVersions:132+265) | VERIFIED | useFileOperations.ts:460 `baseChildren: parentFolder.children`; useFileVersions.ts:132,265 confirmed (unchanged) |
| 13 | D-01/D-08 phase goal: on 409, merged children are published AND adopted in all callers' in-memory state for subsequent writes | VERIFIED | folder/index.ts:197 return type now `Promise<{ cid; newSequenceNumber; publishedChildren: FolderChild[] }>`. Line 230: `return { cid, newSequenceNumber: newSeq, publishedChildren: currentLocalChildren }`. All 14 adoption sites confirmed (CR-01 closed — see detail below) |
| 14 | D-07: prunedCids returned by updateFileMetadata are safe to unpin (not referenced by published metadata) | VERIFIED | file/index.ts:364-368: `const referenced = new Set([mergedMetadata.cid, ...(mergedMetadata.versions ?? []).map((v) => v.cid)]); prunedCids = [...new Set([...prunedCids, ...extraPruned])].filter((c) => !referenced.has(c));` Built from mergedMetadata (published record) not winner/loser intermediates; de-duped before filter (CR-02 closed) |

**Score:** 14/14 truths verified

---

### CR-01 Gap Closure Detail

**Root fix** — `packages/sdk-core/src/folder/index.ts`:
- Line 197: return type widened to `Promise<{ cid: string; newSequenceNumber: bigint; publishedChildren: FolderChild[] }>`
- Line 230: `return { cid, newSequenceNumber: newSeq, publishedChildren: currentLocalChildren }` — reuses the exact variable just encrypted and published (merged set after 409, input children on clean first attempt)

**Adoption sites verified by grep and direct line reads:**

client.ts (8 sites, 19 `publishedChildren` grep hits):
- createFolder: lines 415, 429, 452 — destructures + assigns `parent.children = publishedChildren` + folder:updated event
- renameItem: lines 504, 517, 527 — destructures + assigns + event
- moveItem: lines 582, 584, 594, 601 — `sourceResult.publishedChildren` and `destResult.publishedChildren` for both folders + both events
- deleteItem: lines 630, 643, 653 — destructures + assigns + event
- uploadFile: lines 793, 796, 812 — destructures from `folderResult.value` + assigns + event
- addManyFiles: lines 1055, 1058, 1077 — destructures from `folderResult.value` + assigns + event

bin/index.ts (2 sites, 4 grep hits):
- addToBin: lines 243, 254 — destructures + `folder.children = publishedChildren`
- restoreFromBin: lines 342, 353 — destructures + `targetFolder.children = publishedChildren`

shared-write.ts (4 folder functions, 12 grep hits):
- uploadToSharedFolder: line 202 destructures; line 227 returns `{ updatedChildren, publishedChildren, ... }`
- createSharedSubfolder: line 299 destructures; line 329 returns `publishedChildren`
- renameInSharedFolder: line 358 destructures; line 368 returns `publishedChildren`
- deleteFromSharedFolder: line 390 destructures; line 400 returns `publishedChildren`
- Return type interface at lines 109, 252, 351, 385 — `publishedChildren: FolderChild[]`

useSharedWriteOps.ts (4 handlers, 8 `result.publishedChildren` grep hits):
- All 4 handlers assign `result.publishedChildren` to both `p.folderChildrenRef.current` and `p.setFolderChildren()` (lines 144/146, 191/193, 238/240, 348/350) — ref used by `withConflictRetry` on next retry AND React state both converge on merged set

useFileOperations.ts (1 fire-and-forget, 1 grep hit):
- Line 467-469: `.then(({ newSequenceNumber, publishedChildren }) => { updateFolderSequence; updateFolderChildren(parentId, publishedChildren) })`

useFileVersions.ts (2 fire-and-forget, 2 grep hits):
- Restore path line 139-141: same pattern
- Delete path line 273-275: same pattern

**WR-08 folder test** (`folder.test.ts:365-410`): non-empty `baseChildren` exercises three-way merge path. `result.publishedChildren` asserted to contain both `local-2` (local-only) and `remote-3` (remote-only child, proving merge ran). Stale pre-merge local-only publish would have failed this assertion.

---

### CR-02 Gap Closure Detail

**Root fix** — `packages/sdk-core/src/file/index.ts` lines 360-368:

After `mergedMetadata` is built (line 354-358), before retry publish:
```
const referenced = new Set([
  mergedMetadata.cid,
  ...(mergedMetadata.versions ?? []).map((v) => v.cid),
]);
prunedCids = [...new Set([...prunedCids, ...extraPruned])].filter((c) => !referenced.has(c));
```

Key properties:
- `referenced` Set built from `mergedMetadata` (the published record), not from `winner`/`loser` intermediates
- `new Set([...prunedCids, ...extraPruned])` de-dupes the accumulated set before filter
- Non-referenced overflow CIDs still pass through (filter is not over-broad)
- Non-conflict return path (lines 300-305) is unaffected — its `prunedCids` comes from pre-conflict overflow only

**WR-08 file test** (`file.test.ts:335-439`): Reproduces exact CR-02 scenario — `v-NEW` pruned by positional `slice(2)` then resurrected by remote `mergeVersions`. Three assertions:
- (a) `encryptFileMetadata.mock.calls[1][0]` contains `v-NEW` in `versions[]` — published record references it
- (b) `result.prunedCids` intersection with published refs is empty (core CR-02 invariant)
- (c) `result.prunedCids` contains `v-old` — genuinely overflowed, filter not over-broad

grep count `referenced` in file/index.ts: 3 (comment + Set construction + filter predicate).

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk-core/src/errors.ts` | ConflictError class + isConflictExhausted | VERIFIED | Unchanged from round 1 |
| `packages/sdk-core/src/folder/merge.ts` | mergeChildren pure three-way merge | VERIFIED | Unchanged from round 1 |
| `packages/sdk-core/src/__tests__/folder-merge.test.ts` | D-01/D-02 permutation matrix | VERIFIED | Unchanged from round 1 |
| `packages/sdk-core/src/folder/index.ts` | 4-attempt merge-and-republish loop + publishedChildren return | VERIFIED | Line 197 return type; line 230 return value; loop at 205 unchanged |
| `packages/sdk-core/src/__tests__/folder.test.ts` | Retry-loop tests + WR-08 publishedChildren assertion | VERIFIED | WR-08 test at line 365; 15 total tests (was 14) |
| `packages/sdk-core/src/file/index.ts` | File CAS publish + mergeVersions + reference filter on prunedCids | VERIFIED | CAS at 297/380; mergeVersions at 347; reference filter at 364-368 |
| `packages/sdk-core/src/__tests__/file.test.ts` | D-06/D-07 unit tests + WR-08 prunedCids safety assertion | VERIFIED | 14 total tests; WR-08 at line 335 asserts loser-cid in versions[] and prunedCids ∩ refs = empty |
| `packages/sdk/src/client.ts` | 8 publishedChildren adoptions | VERIFIED | 19 grep hits; 8 distinct call sites |
| `packages/sdk/src/bin/index.ts` | 2 publishedChildren adoptions | VERIFIED | 4 grep hits; 2 call sites |
| `packages/sdk/src/share/shared-write.ts` | 4 publishedChildren in return shapes | VERIFIED | 12 grep hits; 4 folder functions return publishedChildren |
| `apps/web/src/hooks/useSharedWriteOps.ts` | result.publishedChildren into folderChildrenRef + setFolderChildren | VERIFIED | 8 grep hits; all 4 handlers adopt both ref and state |
| `apps/web/src/hooks/useFileOperations.ts` | publishedChildren adopted in fire-and-forget .then | VERIFIED | Line 467-469 |
| `apps/web/src/hooks/useFileVersions.ts` | 2 publishedChildren adoptions in lazy-migration .then | VERIFIED | Lines 139-141, 273-275 |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| folder/index.ts | callers | publishedChildren in return shape | VERIFIED | Line 197 type; line 230 return; reuses currentLocalChildren (provably the published array) |
| client.ts | folder.children store | publishedChildren assignment | VERIFIED | 8 call sites; all events also carry publishedChildren |
| bin/index.ts | folder.children store | publishedChildren assignment | VERIFIED | 2 call sites |
| shared-write.ts | return shape | publishedChildren forwarded | VERIFIED | 4 folder functions; return types declare publishedChildren: FolderChild[] |
| useSharedWriteOps.ts | folderChildrenRef + setFolderChildren | result.publishedChildren | VERIFIED | 4 handlers; withConflictRetry ref and React state both converge |
| useFileOperations.ts | useFolderStore | updateFolderChildren(parentId, publishedChildren) | VERIFIED | Line 469 |
| useFileVersions.ts | useFolderStore | updateFolderChildren(parentId, publishedChildren) | VERIFIED | Lines 141, 275 |
| file/index.ts | prunedCids return | filter against Set of referenced CIDs from mergedMetadata | VERIFIED | referenced.has filter at line 368 |
| folder/index.ts | folder/merge.ts | mergeChildren call inside 409 branch | VERIFIED | Unchanged from round 1 |
| folder/index.ts | errors.ts | throw ConflictError on exhaustion | VERIFIED | Unchanged from round 1 |
| file/index.ts | errors.ts | throw ConflictError on 2nd 409 | VERIFIED | Unchanged from round 1 |
| sdk-core/index.ts | errors.ts + folder/merge.ts | barrel re-exports | VERIFIED | Unchanged from round 1 |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| folder/index.ts updateFolderMetadataAndPublish | publishedChildren (= currentLocalChildren) | mergeChildren result on 409; params.children on clean publish | Yes — merged from real remote fetch, returned to callers | VERIFIED — published and returned; callers adopt as next-write base |
| file/index.ts updateFileMetadata | prunedCids | allVersions.slice(maxVersions) filtered against Set(mergedMetadata.cid + versions[].cid) | Correct — referenced CIDs excluded; genuine overflow retained | VERIFIED |

---

### Behavioral Spot-Checks

Step 7b SKIPPED per constraint — no pnpm/vitest execution allowed (RAM-constrained host). Orchestrator reports 190/190 sdk-core vitest green (including new WR-08 folder and file tests); sdk tsc clean; web tsc clean after sdk dist rebuild.

---

### Probe Execution

No probe scripts for this phase.

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|---------|
| Todo 2026-06-11-ipns-409-retry-lost-update (folder stale-CID) | Plans 01-05, 44-06 | On 409 re-fetch+merge before republish; merged children adopted by all callers | SATISFIED | folder/index.ts returns publishedChildren; 14 call sites adopt it; WR-08 folder test proves merged set surfaced |
| Todo 2026-06-11-ipns-409-retry-lost-update (file TOCTOU) | Plans 03-05, 44-07 | CAS for file IPNS publishes; loser preserved as version; prunedCids safe | SATISFIED | CAS at expectedSequenceNumber; loser-becomes-version; reference filter at line 364-368; WR-08 file test proves prunedCids ∩ refs = empty |

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| packages/sdk-core/src/folder/merge.ts | 53-57 | remote-delete branch keeps local unconditionally with no modifiedAt check — asymmetric vs local-delete branch | WARNING (WR-01, unchanged) | Advisory; remote deletes never honored; out of scope for this phase |
| packages/sdk-core/src/file/index.ts | 347-351 | When remote wins, loser's (local) versions[] discarded — only loserAsVersion appended | WARNING (WR-02, unchanged) | Advisory; ghost version entries dropped on remote-wins path; out of scope |

No blockers. The two CR-01/CR-02 blockers are resolved. WR-01 and WR-02 are unchanged advisory items deferred from round 1.

---

### Human Verification Required

None. All phase behaviors are unit-testable and verified by code inspection. The orchestrator-reported 190/190 sdk-core vitest suite (including new WR-08 tests for both blockers) provides behavioral confirmation.

---

### Gaps Summary

No gaps. Both round-1 blockers are closed:

**CR-01 (closed):** `updateFolderMetadataAndPublish` returns `publishedChildren: currentLocalChildren` at `folder/index.ts:230`. All 14 downstream store-write sites (client.ts, bin, shared-write, useSharedWriteOps, useFileOperations, useFileVersions) adopt `publishedChildren` as the authoritative post-publish children. The stale pre-merge `updatedChildren` pattern is gone from all folder mutation paths. The one-write-later re-drop of remote additions cannot recur.

**CR-02 (closed):** `file/index.ts:364-368` builds a `referenced` Set from `mergedMetadata.cid` and every `mergedMetadata.versions[].cid`, then filters the de-duped accumulated `prunedCids` against it before returning. A CID resurrected into the published record by the remote merge is never returned for unpinning. Genuine overflow CIDs still pass through.

---

_Verified: 2026-06-13T01:00:00Z_
_Verifier: Claude (gsd-verifier) — re-verification round 2_
