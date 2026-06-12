---
phase: 44-ipns-conflict-handling
verified: 2026-06-13T00:00:00Z
status: gaps_found
score: 12/14 must-haves verified
overrides_applied: 0
gaps:
  - truth: "D-01/D-08: on 409 the merged children are published but NOT returned to callers — every caller stores updatedChildren (stale pre-merge local set) alongside the fresh newSequenceNumber, so the next write (which passes the wrong children as the new base) overwrites the remote-only children with no 409, re-opening the lost-update one write later"
    status: failed
    reason: "updateFolderMetadataAndPublish returns { cid, newSequenceNumber } (folder/index.ts:197,230) but never returns the merged children (currentLocalChildren after merge at line 251-263). Every caller then stores updatedChildren — the pre-merge local set — not the published merged set. Traced at: client.ts:428-429 (createFolder stores updatedChildren), client.ts:514-515 (renameItem stores updatedChildren), client.ts:579-582 (moveItem stores updated{Source,Dest}Children), client.ts:638-639 (deleteItem stores updatedChildren), client.ts:791-792 (uploadFile stores updatedChildren), shared-write.ts:226 (returns updatedChildren to useSharedWriteOps), shared-write.ts:362 (renameInSharedFolder returns updatedChildren), useFileOperations.ts:467-468 (updates sequence but keeps pre-merge children in store). The next operation by the same device uses the stale children + fresh sequence, publishes without a 409 (CAS passes), and silently drops the remote additions again."
    artifacts:
      - path: "packages/sdk-core/src/folder/index.ts"
        issue: "Return type is Promise<{ cid: string; newSequenceNumber: bigint }> — no publishedChildren field. Line 230 returns { cid, newSequenceNumber: newSeq }. The merged children are in currentLocalChildren inside the closure but not surfaced."
      - path: "packages/sdk/src/client.ts"
        issue: "Lines 428-429, 514-515, 579-582, 638-639, 791-792: all set folder.children = updatedChildren after the publish, not the merged children returned from updateFolderMetadataAndPublish."
      - path: "packages/sdk/src/share/shared-write.ts"
        issue: "Lines 226, 362, 390: return { updatedChildren, newSequenceNumber } to callers — updatedChildren is the pre-merge local set."
      - path: "apps/web/src/hooks/useFileOperations.ts"
        issue: "Line 467-468: fire-and-forget .then updates sequence only; store retains pre-merge children. Line 452 sets the store to updatedChildren before the fire-and-forget even runs."
    missing:
      - "Add publishedChildren: FolderChild[] (=== currentLocalChildren at point of successful return) to the updateFolderMetadataAndPublish return shape in folder/index.ts"
      - "Update all callers to adopt publishedChildren as the new in-memory children snapshot: client.ts (8 sites), bin/index.ts (2 sites), shared-write.ts (4 folder sites), useFileOperations.ts fire-and-forget, useFileVersions.ts (2 lazy-migration sites)"
      - "Emit the merged children in folder:updated events so downstream listeners (FUSE, sync polling) converge"

  - truth: "D-07: versions[] capped by maxVersionsPerFile — overflow prunedCids are safe to unpin (no CID still referenced by the published metadata appears in prunedCids)"
    status: failed
    reason: "CR-02 confirmed by code inspection. file/index.ts:263 computes prunedCids from the pre-conflict local version list (allVersions.slice(maxVersions)). On 409 the merge path recomputes merged versions via mergeVersions and accumulates extraPruned (line 354: prunedCids = [...prunedCids, ...extraPruned]) without filtering out CIDs that ended up in the published mergedMetadata.versions[]. If a version that was initially pruned from the local list is re-added to the merged list (e.g. remote retained it), its CID is returned in prunedCids and unconditionally unpinned by useFileOperations.ts:507-510, permanently destroying a version that the published record still references. Trace matches CR-02 exactly."
    artifacts:
      - path: "packages/sdk-core/src/file/index.ts"
        issue: "Lines 249-263 compute initial prunedCids. Line 354 accumulates extraPruned without cross-checking against mergedMetadata.versions. mergedMetadata is built at line 357-361. No filter of final prunedCids against referenced CIDs (mergedMetadata.cid + mergedMetadata.versions[].map(v=>v.cid)) before return."
      - path: "apps/web/src/hooks/useFileOperations.ts"
        issue: "Lines 507-510 unpin every CID in prunedCids unconditionally. These CIDs can include versions referenced by the currently-published file metadata record."
    missing:
      - "After building mergedMetadata in the conflict path, filter the accumulated prunedCids set against the set of CIDs actually referenced by the published record: const referenced = new Set([mergedMetadata.cid, ...(mergedMetadata.versions ?? []).map(v => v.cid)]); prunedCids = [...new Set([...prunedCids, ...extraPruned])].filter(c => !referenced.has(c));"
      - "Add a unit test asserting that a CID present in both the initial prune list and the merged versions[] does NOT appear in prunedCids"
---

# Phase 44: IPNS Conflict Handling Verification Report

**Phase Goal:** Stop lost updates on concurrent IPNS writes in `packages/sdk-core`: on 409, re-fetch remote folder metadata and merge (children union, per-entry reconcile) before republishing, and extend CAS coverage to file records; full CRDT model explicitly deferred to the CRDT-inbox research todo.

**Verified:** 2026-06-13T00:00:00Z
**Status:** gaps_found — 2 critical defects block the phase goal
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| 1 | D-01: mergeChildren three-way-merges FolderChild[] keyed by id with all 8 permutations | VERIFIED | merge.ts:21-65; all branches present; folder-merge.test.ts covers all 8 permutations + union fallback + undefined modifiedAt + no-mutation |
| 2 | D-02: mergeChildren with empty base degrades to children union | VERIFIED | merge.ts:38-61 — empty base means baseById is empty; all ids fall through to the local-add/remote-add/added-by-both branches, none to the delete branches |
| 3 | D-05: ConflictError class in sdk-core/src/errors.ts with ipnsName/attempts/lastRemoteSeq; isConflictExhausted exported | VERIFIED | errors.ts:8-26; exact fields; name='ConflictError'; guard uses instanceof; both re-exported from index.ts:2 |
| 4 | D-01/D-03: updateFolderMetadataAndPublish re-fetches+decrypts remote on 409, calls mergeChildren, re-encrypts+re-uploads merged children to fresh CID | VERIFIED | folder/index.ts:246-264; fetchAndDecryptMetadata called; mergeChildren called with base/local/remote; addToIpfs inside loop (line 214) |
| 5 | D-02: union-fallback warning logged when baseChildren absent | VERIFIED | folder/index.ts:257-263; console.warn fires with message containing ipnsName; folder.test.ts:282-313 asserts warn contains 'baseChildren not provided' |
| 6 | D-04: 4-attempt loop with exponential backoff+jitter | VERIFIED | folder/index.ts:205 `for (let attempt = 0; attempt < 4; attempt++)`; retryDelayMs helper at line 41-43; BACKOFF_BASE_MS=100, BACKOFF_CAP_MS=1500 |
| 7 | D-05: ConflictError(ipnsName, 4, lastRemoteSeq) thrown after exhaustion | VERIFIED | folder/index.ts:267-269 `if (attempt === 3) throw new ConflictError(params.ipnsName, 4, lastRemoteSeq)`; fallback throw at 277; folder.test.ts:315-343 asserts isConflictExhausted+attempts===4+ipnsName |
| 8 | D-06: updateFileMetadata publishes via createAndPublishIpnsRecord with expectedSequenceNumber (CAS) | VERIFIED | file/index.ts:292-299; expectedSequenceNumber: currentSeq.toString() passed; createAndPublishIpnsRecord used (NOT batch); file.test.ts:189-212 asserts |
| 9 | D-07: on file 409 — latest-wins + loser-becomes-version; versions[] merged/deduped/capped; prunedCids returned | PARTIALLY VERIFIED — prunedCids unsafe (CR-02) | file/index.ts:328-381 implements latest-wins correctly; loserAsVersion constructed at 337-344; mergeVersions called at 347-351; BUT prunedCids accumulation at line 354 can include CIDs still in mergedMetadata.versions[] |
| 10 | D-08: all SDK callers pass pre-mutation baseChildren (8 client.ts, 2 bin, 4 shared-write) | VERIFIED | client.ts baseChildren count: 13 grep hits; verified 8 distinct call sites each with pre-mutation snapshot; bin/index.ts: 4 hits (2 call sites x key+declaration); shared-write.ts: 4 `baseChildren: swCtx.children` hits |
| 11 | D-08: shared-write.ts updateFileMetadata call rewired to Plan-03 return shape; redundant batchPublishIpnsRecords removed | VERIFIED | shared-write.ts:453-468; `await updateFileMetadata({...})` with no destructuring; comment at line 470-473 confirms redundant publish removed; no `ipnsRecord` destructuring present |
| 12 | D-08: web hook callers pass baseChildren (useFileOperations:461, useFileVersions:126+251) | VERIFIED | useFileOperations.ts:460 `baseChildren: parentFolder.children`; useFileVersions.ts:132,265 both have `baseChildren: parentFolder.children` (grep count: 2) |
| 13 | D-01/D-08 phase goal: on 409, merged children are published AND adopted in all callers' in-memory state for subsequent writes | FAILED (CR-01) | updateFolderMetadataAndPublish returns only { cid, newSequenceNumber } (folder/index.ts:197,230); all callers store updatedChildren (pre-merge) + newSequenceNumber; next write uses wrong children as base and passes CAS without 409, silently dropping remote additions |
| 14 | D-07: prunedCids returned by updateFileMetadata are safe to unpin (not referenced by published metadata) | FAILED (CR-02) | file/index.ts:249-263 computes initial prunedCids from pre-conflict local list; line 354 accumulates conflict-path extraPruned without filtering against final mergedMetadata.versions[]; versions resurrected by merge can appear in prunedCids and be unpinned |

**Score:** 12/14 truths verified (2 critical failures)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk-core/src/errors.ts` | ConflictError class + isConflictExhausted | VERIFIED | Exists; class ConflictError extends Error with 3 readonly fields; isConflictExhausted uses instanceof |
| `packages/sdk-core/src/folder/merge.ts` | mergeChildren pure three-way merge | VERIFIED | Exists; exports mergeChildren; keyed by c.id; 6 branches + fallbacks; no mutations |
| `packages/sdk-core/src/__tests__/folder-merge.test.ts` | D-01/D-02 permutation matrix | VERIFIED | 18 tests: 7 ConflictError + 11 mergeChildren covering all permutations |
| `packages/sdk-core/src/folder/index.ts` | 4-attempt merge-and-republish loop | VERIFIED | Loop with re-fetch, mergeChildren, re-encrypt, CAS publish, backoff, ConflictError on exhaustion |
| `packages/sdk-core/src/__tests__/folder.test.ts` | Retry-loop tests | VERIFIED | 4 conflict-handling tests: merge-on-409, union-fallback warning, ConflictError-after-4, non-409 propagation |
| `packages/sdk-core/src/file/index.ts` | File CAS publish + mergeVersions + maxVersionsPerFile | VERIFIED (with CR-02 caveat) | CAS publish wired; mergeVersions exported; maxVersionsPerFile param present; loser-becomes-version implemented |
| `packages/sdk-core/src/__tests__/file.test.ts` | D-06/D-07 unit tests | VERIFIED (with WR-08 caveat) | 13 tests; covers CAS, conflict paths, ConflictError; does not inspect encryptFileMetadata payload on retry (loser cid not asserted) |
| `packages/sdk/src/client.ts` | 8 baseChildren snapshots | VERIFIED | 13 grep hits; 8 distinct call sites each capture pre-mutation children |
| `packages/sdk/src/bin/index.ts` | 2 baseChildren snapshots | VERIFIED | 4 grep hits; 2 call sites with pre-mutation snapshot |
| `packages/sdk/src/share/shared-write.ts` | 4 folder baseChildren + file return shape rewire | VERIFIED | 4 `baseChildren: swCtx.children` hits; file call at line 454 uses new shape; batchPublishIpnsRecords for file removed |
| `apps/web/src/hooks/useFileOperations.ts` | baseChildren + file CAS rewire + maxVersionsPerFile + isConflictExhausted | VERIFIED | All 4 acceptance criteria pass (baseChildren, no ipnsRecord, maxVersionsPerFile, isConflictExhausted) |
| `apps/web/src/hooks/useFileVersions.ts` | 2 baseChildren snapshots | VERIFIED | `grep -c "baseChildren: parentFolder.children"` returns 2; both fire-and-forget; isConflictExhausted in both catches |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| folder/index.ts | folder/merge.ts | mergeChildren call inside 409 branch | VERIFIED | folder/index.ts:47-48 imports mergeChildren; called at lines 251-263 |
| folder/index.ts | errors.ts | throw ConflictError on exhaustion | VERIFIED | folder/index.ts:34 `import { ConflictError } from '../errors'`; thrown at 268,277,240 |
| folder/index.ts | fetchAndDecryptMetadata | re-fetch remote on 409 | VERIFIED | folder/index.ts:246 calls fetchAndDecryptMetadata(resolved.cid, params.folderKey, params.ctx) |
| file/index.ts | createAndPublishIpnsRecord | CAS publish with expectedSequenceNumber | VERIFIED | file/index.ts:292-299 first attempt; 368-375 retry attempt |
| file/index.ts | errors.ts | throw ConflictError on 2nd 409 | VERIFIED | file/index.ts:23 imports ConflictError; thrown at 317, 388 |
| sdk-core/index.ts | errors.ts | barrel re-export of ConflictError, isConflictExhausted | VERIFIED | index.ts:2 |
| sdk-core/index.ts | folder/merge.ts | barrel re-export of mergeChildren | VERIFIED | index.ts:37 `mergeChildren` in folder barrel export |
| client.ts | updateFolderMetadataAndPublish.baseChildren | pre-mutation snapshot | VERIFIED | 8 call sites each take `const baseChildren = [...folder.children]` before mutation helper |
| shared-write.ts | updateFileMetadata new return shape | internal CAS publish | VERIFIED | shared-write.ts:454 `await updateFileMetadata({...})`; no destructuring; batchPublishIpnsRecords removed for file |

---

### Data-Flow Trace (Level 4)

The core data flow for the conflict merge itself (merge → encrypt → publish) is correctly wired. The defect is downstream: the published merged children are not surfaced to callers.

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| folder/index.ts updateFolderMetadataAndPublish | currentLocalChildren (merged) | mergeChildren result at line 251-263 | Yes — merged from real remote fetch | HOLLOW_PROP — merged children computed and published but not returned; callers store stale `updatedChildren` |
| file/index.ts updateFileMetadata | prunedCids | allVersions.slice(maxVersions) + extraPruned | Conditionally wrong — may include CIDs in mergedMetadata.versions | STATIC — pre-conflict prunedCids not refiltered after conflict merge |

---

### Behavioral Spot-Checks

Step 7b SKIPPED per constraint — no pnpm/cargo/vitest execution allowed (RAM-constrained host). Orchestrator reports 188/188 sdk-core vitest green; verification of the two critical gaps is code-reading-only.

---

### Probe Execution

No probe scripts for this phase (TypeScript code phase; no `scripts/*/tests/probe-*.sh`).

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|---------|
| Todo 2026-06-11-ipns-409-retry-lost-update (folder stale-CID) | Plans 01-05 | On 409 re-fetch+merge before republish | PARTIAL | Merge happens correctly; IPNS record published with merged children; BUT callers never adopt the merged children into local state → lost update recurs one write later (CR-01) |
| Todo 2026-06-11-ipns-409-retry-lost-update (file TOCTOU) | Plans 03-05 | CAS for file IPNS publishes; loser preserved as version | PARTIAL | CAS wired correctly; loser-becomes-version implemented; prunedCids can list CIDs still in published versions[] → version content may be destroyed (CR-02) |

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| packages/sdk-core/src/folder/index.ts | 197 | Return type omits publishedChildren — callers have no way to adopt merged state | BLOCKER | Every caller stores stale updatedChildren; CR-01 |
| packages/sdk-core/src/file/index.ts | 354 | prunedCids accumulated without filtering against final mergedMetadata.versions | BLOCKER | Version content destructively unpinned; CR-02 |
| packages/sdk-core/src/__tests__/file.test.ts | 234-283 | Conflict tests never inspect encryptFileMetadata payload — loser-becomes-version invariant (D-07) untested | WARNING | WR-08 confirmed; CR-02 hides here because the test would have caught the prunedCids accumulation bug if it checked the retry payload |
| packages/sdk-core/src/folder/merge.ts | 53-57 | remote-delete branch keeps local unconditionally with no modifiedAt check — asymmetric vs local-delete branch | WARNING | WR-01 from REVIEW.md; remote deletes never honored; ghost entries after conflict |

---

### Review Claim Verification (44-REVIEW.md)

Each claim independently verified against the actual code:

**CR-01 (merged children not returned to callers):** CONFIRMED. Return type at folder/index.ts:197 is `Promise<{ cid: string; newSequenceNumber: bigint }>`. Line 230 returns only `{ cid, newSequenceNumber }`. The review's concrete trace (device A stores `[X,F]` + seq 6 → next write publishes `[X,F]` successfully → Y lost) is structurally sound. Every caller verified: client.ts:428-429, 514-515, 579-582, 638-639, 791-792; shared-write.ts:226,362; useFileOperations.ts:467-468. BLOCKER.

**CR-02 (prunedCids can unpin CIDs still in published metadata):** CONFIRMED. file/index.ts:263 computes initial prunedCids. Line 354 does `prunedCids = [...prunedCids, ...extraPruned]` with no reference filter against mergedMetadata. The review's trace (remote's versions list shorter → step-1 pruned CID re-added by merge → returned as prunedCid → unpinned by useFileOperations.ts:507) is structurally sound. BLOCKER.

**WR-01 (remote-delete branch asymmetry):** CONFIRMED. merge.ts:53-57 — `!r && b` branch pushes `l` unconditionally if `l` exists. No modifiedAt guard unlike the local-delete branch (lines 47-52). WARNING.

**WR-02 (loser's versions[] discarded when remote wins):** CONFIRMED as present in code. file/index.ts:347-351: `mergeVersions([...(winner.versions ?? []), loserAsVersion], remoteMeta.versions, maxVersions)`. When remote wins, `winner === remoteMeta` so `winner.versions === remoteMeta.versions` — the loser's (local) versions[] including createVersion entries are dropped. WARNING.

**WR-03 (duplicate names from both-add):** CONFIRMED as possible by merge.ts logic — both local-add and remote-add survive for different ids with the same name. WARNING.

**WR-04 (stale docblock in handleUpdateFile):** Not independently checked — comment-only issue; INFO.

**WR-05 (restore/delete still publish without CAS):** CONFIRMED structure: useFileVersions.ts:245-251 uses `replaceFileInFolder` which goes through `batchPublishIpnsRecords` with no expectedSequenceNumber. WARNING — out of scope for this phase but regression risk for the file CAS work.

**WR-06 (fileIpnsPrivateKey zeroed in-place):** CONFIRMED. file/index.ts:393-397 `params.fileIpnsPrivateKey.fill(0)` in finally. WARNING.

**WR-07 (ConflictError invisible to isConflictError / withConflictRetry):** Not independently checked at sdk/src/error.ts — advisory compatibility issue; WARNING.

**WR-08 (file conflict tests don't assert merged payload):** CONFIRMED. file.test.ts:278 asserts `decryptFileMetadata` was called; line 280-281 checks retry publish seq. Neither test captures `encryptFileMetadata.mock.calls[1][0]` to verify loser cid in versions. WARNING.

---

### Gaps Summary

Two blockers prevent the phase goal from being fully achieved:

**Gap 1 (CR-01) — Goal-defeating:** The merge is computed and published correctly, but the merged children are never returned to callers. Every call site stores the pre-merge `updatedChildren` alongside the new `newSequenceNumber`. The device's next write — which now has a correct CAS sequence — will republish the stale pre-merge children without triggering a 409, silently erasing the remote additions. The fix requires surfacing `publishedChildren` from `updateFolderMetadataAndPublish` and adopting them in all 14 call sites. This is the same root cause the todo describes, just displaced one write later.

**Gap 2 (CR-02) — Data integrity:** The file conflict merge path accumulates `prunedCids` from the pre-conflict local version list then blindly appends the conflict-path extra prunes without cross-checking against the final published `mergedMetadata`. A CID that was pruned locally but re-added by the remote merge survives in `prunedCids` and is unconditionally unpinned by `useFileOperations.ts:507-510`, permanently destroying a version that the live metadata still references. The fix is a one-line reference filter before returning.

The warnings (WR-01 through WR-08) are advisory hardening items and do not block the primary goal, but WR-08 is the reason CR-02 was not caught by the tests — the conflict test assertions are too shallow to detect the prunedCids accumulation bug.

---

_Verified: 2026-06-13T00:00:00Z_
_Verifier: Claude (gsd-verifier)_
