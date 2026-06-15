---
phase: 47-sdk-folder-state-publish-consolidation
verified: 2026-06-15T14:47:00Z
status: human_needed
score: 5/5
overrides_applied: 0
human_verification:
  - test: "Delete-file-resurrection regression (PR #489 TC08)"
    expected: "After replacing a file's content or editing a version in a shared or private folder, the deleted file must NOT reappear in the folder listing on the next IPNS poll cycle."
    why_human: "Requires a live API server + IPNS polling environment to trigger the resurrection race and observe the folder listing after a 30-second sync cycle."
---

# Phase 47: SDK Folder-State / Publish Consolidation Verification Report

**Phase Goal:** SDK folder-state and publish consolidation. The SDK client becomes the single source of truth for folder state; the file/folder IPNS CAS-retry is unified into one helper; shared-write pin leak closed; redundant updatedChildren dropped.

**Verified:** 2026-06-15T14:47:00Z

**Status:** human_needed

**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | publishWithCas in cas.ts owns the CAS-retry skeleton for both file and folder paths | VERIFIED | `packages/sdk-core/src/cas.ts` (124 lines) exports `publishWithCas<TData>` with the full resolve->encrypt->upload->CAS->409->merge->retry->ConflictError loop; `maxAttempts 4 + backoff`; 6 unit tests in `cas.test.ts` (198 lines) — all 6 pass |
| 2 | updateFolderMetadataAndPublish and updateFileMetadata delegate to publishWithCas with maxAttempts 4 + backoff; public signatures unchanged | VERIFIED | `folder/index.ts` line 205: `await publishWithCas<FolderChild[]>({...maxAttempts:4, backoff:true...})`; `file/index.ts` line 287: `await publishWithCas<FileMetadata>({...maxAttempts:4, backoff:true...})`; BACKOFF constants and `retryDelayMs` removed from `folder/index.ts` (grep returns 0); 202 sdk-core tests pass including folder.test.ts (15) and file.test.ts (15) |
| 3 | fileIpnsPrivateKey.fill(0) preserved in updateFileMetadata finally on all exit paths; publishWithCas never zeroes keys | VERIFIED | `file/index.ts` line 368-371: `} finally { // Zeroize the private key... params.fileIpnsPrivateKey.fill(0); }` wraps the `publishWithCas` call; `cas.ts` doc comment line 8: "publishWithCas NEVER zeroes key material — callers are responsible" |
| 4 | updateFolderMetadataAndPublish encapsulates baseChildren snapshot internally; updatedChildren dropped from all 4 shared-write return shapes | VERIFIED | `folder/index.ts` lines 193-203: union-fallback warn fires when `params.baseChildren === undefined`, then `const baseChildren = params.baseChildren ?? []` sets baseData before `publishWithCas`; `shared-write.ts` return shapes (lines 227, 328, 366, 397) all return `{ publishedChildren, newSequenceNumber, ... }` — no `updatedChildren` in any return type (grep on return types returns 0) |
| 5 | updateSharedFile destructures prunedCids from updateFileMetadata and fire-and-forget unpins each; failure tolerated | VERIFIED | `shared-write.ts` lines 461-486: `const { prunedCids } = await updateFileMetadata(...)` then `for (const cid of prunedCids) { unpinFromIpfs(params.ctx, cid).catch(...)` — fire-and-forget pattern |
| 6 | CipherBoxClient gains replaceFile, restoreFileVersion, deleteFileVersion that own publish + folderTree bookkeeping + folder:updated emission | VERIFIED | `client.ts` lines 1145-1226 (replaceFile), 1255-1316 (restoreFileVersion), 1337-1397 (deleteFileVersion); each calls `this.folderTree.set(parentIpnsName, folder)` and `this.emitter.emit({ type: 'folder:updated', ... })` |
| 7 | Web hooks route replaceFile/restore/delete through SDK client; no direct updateFolderMetadataAndPublish calls; no direct folder-state store writes for these paths | VERIFIED | `useFileOperations.ts` line 416: `await getSdkClient().replaceFile(...)` with comment "no direct store writes here (PR #489 desync closed)"; `useFileVersions.ts` lines 102, 203: `getSdkClient().restoreFileVersion(...)` / `getSdkClient().deleteFileVersion(...)` — grep for `updateFolderMetadataAndPublish` in both hook files returns 0 |
| 8 | folder.store children/sequenceNumber written ONLY by folder:updated/folder:loaded subscription; folder.store.test.ts proves it including root folder | VERIFIED | `folder.store.ts` lines 206-230: `subscribeToSdk` handler on `folder:updated`/`folder:loaded` calls `updateFolderChildren` + `updateFolderSequence`; no other code path writes these for file-op results; `folder.store.test.ts` (5 tests, all pass) covers child+sequence update, root folder, folder:loaded, unknown ipnsName no-op |
| 9 | reconcileFolderState DELETED repo-wide (packages/sdk/src + apps/web/src grep === 0) | VERIFIED | `grep -rn reconcileFolderState packages/sdk/src apps/web/src` returns 0 matches |

**Score:** 5/5 must-haves verified (9 constituent truths all VERIFIED)

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `packages/sdk-core/src/cas.ts` | publishWithCas generic CAS helper | EXISTS + SUBSTANTIVE | 124 lines; exports `publishWithCas`; retryDelayMs + BACKOFF constants defined here; imports `is409`, `ConflictError`, `createAndPublishIpnsRecord`, `resolveIpnsRecord` |
| `packages/sdk-core/src/__tests__/cas.test.ts` | 6 unit tests for publishWithCas | EXISTS + SUBSTANTIVE | 198 lines; 6 tests covering: success first attempt, 409-merge-retry, ConflictError exhaustion, prunedCids passthrough, non-409 rethrow, backoff toggle |
| `packages/sdk-core/src/folder/index.ts` | Delegates to publishWithCas | EXISTS + SUBSTANTIVE | `publishWithCas` imported line 34; called line 205; `retryDelayMs` and BACKOFF constants removed |
| `packages/sdk-core/src/file/index.ts` | Delegates to publishWithCas; fill(0) finally preserved | EXISTS + SUBSTANTIVE | `publishWithCas` imported line 23; called line 287; `fill(0)` in finally line 371 |
| `packages/sdk/src/client.ts` | replaceFile, restoreFileVersion, deleteFileVersion | EXISTS + SUBSTANTIVE | Three methods at lines 1145, 1255, 1337; each owns folderTree.set + folder:updated emit |
| `packages/sdk/src/share/shared-write.ts` | updateSharedFile unpins prunedCids; return shapes use publishedChildren | EXISTS + SUBSTANTIVE | prunedCids unpin at lines 483-486; 4 return statements all use `publishedChildren` |
| `apps/web/src/hooks/useFileOperations.ts` | replaceFile path routes through SDK client | EXISTS + SUBSTANTIVE | `getSdkClient().replaceFile(...)` at line 416; no direct folder store writes for this path |
| `apps/web/src/hooks/useFileVersions.ts` | restore/delete routes through SDK client | EXISTS + SUBSTANTIVE | `getSdkClient().restoreFileVersion(...)` line 102; `getSdkClient().deleteFileVersion(...)` line 203; no direct folder store writes |
| `apps/web/src/lib/sdk-provider.ts` | No reconcileFolderState; no call site | EXISTS + SUBSTANTIVE | `reconcileFolderState` absent; comment at lines 94-101 documents the PR #489 closure rationale |
| `apps/web/src/stores/__tests__/folder.store.test.ts` | Proves subscription-only children/sequenceNumber writes incl. root | EXISTS + SUBSTANTIVE | 209 lines; 5 tests pass; includes root folder case (line 115) and folder:loaded case (line 145) |

**Artifacts:** 10/10 verified

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `folder/index.ts` | `cas.ts` | updateFolderMetadataAndPublish calls publishWithCas | WIRED | `import { publishWithCas } from '../cas'` line 34; called line 205 |
| `file/index.ts` | `cas.ts` | updateFileMetadata calls publishWithCas | WIRED | `import { publishWithCas } from '../cas'` line 23; called line 287 |
| `sdk-core/src/index.ts` | `cas.ts` | re-exports publishWithCas | WIRED | Line 5: `export { publishWithCas } from './cas'` |
| `client.ts replaceFile` | `sdkCore.updateFileMetadata` + `sdkCore.updateFolderMetadataAndPublish` | file publish then folder touch | WIRED | Lines 1172-1207 |
| `client.ts replaceFile` | `this.folderTree` + `this.emitter (folder:updated)` | folderTree.set + emitter.emit | WIRED | Lines 1213-1222 |
| `client.ts restoreFileVersion` | `sdkCore.updateFileMetadata` | file publish only (conditional folder) | WIRED | Line ~1290; conditional maybePublishKeyMigration |
| `client.ts deleteFileVersion` | `this.emitter (folder:updated)` | always emits folder:updated | WIRED | Lines 1387-1393 |
| `useFileOperations.ts updateFile` | `getSdkClient().replaceFile` | routes through SDK | WIRED | Line 416 |
| `useFileVersions.ts restoreVersion` | `getSdkClient().restoreFileVersion` | routes through SDK | WIRED | Line 102 |
| `useFileVersions.ts deleteVersion` | `getSdkClient().deleteFileVersion` | routes through SDK | WIRED | Line 203 |
| `folder.store.ts` | `updateFolderChildren` + `updateFolderSequence` | only via folder:updated/folder:loaded subscription | WIRED | Lines 206-230 |
| `shared-write.ts updateSharedFile` | `unpinFromIpfs` | fire-and-forget on each prunedCid | WIRED | Lines 483-486 |

**Wiring:** 12/12 connections verified

### Behavioral Spot-Checks (Builds + Tests)

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| sdk-core builds clean | `pnpm --filter @cipherbox/sdk-core build` | dist/index.mjs 54.56 KB, no tsc errors | PASS |
| sdk package builds clean | `pnpm --filter @cipherbox/sdk build` | dist/index.mjs 81.29 KB, no tsc errors | PASS |
| sdk-core 202 tests pass | `pnpm --filter @cipherbox/sdk-core test` | 18 test files, 202 tests — all pass | PASS |
| sdk unit suites pass (excl. live-API) | `pnpm --filter @cipherbox/sdk test` | 13 test files pass, 171 unit tests pass; 3 integration.test.ts live-API tests fail (no server) | PASS (env failures excluded) |
| new client-file-ops.test.ts (8 tests) | included in sdk test run | 8/8 pass | PASS |
| new shared-write.test.ts | included in sdk test run | 17/17 pass | PASS |
| web 31 tests pass | `pnpm --filter @cipherbox/web test` | 5 test files, 31 tests — all pass | PASS |
| web typecheck clean | `tsc --noEmit` in apps/web | no errors | PASS |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `apps/web/src/hooks/useFileOperations.ts` | 130-131 | `store.updateFolderChildren` / `store.updateFolderSequence` | Info | These are in `handleAddFile` (file ADD path), not the file replace/version paths. The must-have scopes to "6b block" (update/replace) and version ops. File ADD is an older flow not in scope for this phase. Not a blocker. |

No TBD, FIXME, or XXX markers found in any changed file.

**Anti-patterns:** 0 blockers, 0 warnings, 1 informational observation

### Explicit Verification Requirement Confirmations

1. **reconcileFolderState DELETED**: `grep -rn reconcileFolderState packages/sdk/src apps/web/src` returns ZERO matches. CONFIRMED.

2. **SDK client folderTree is SINGLE SOURCE OF TRUTH**: `replaceFile` (line 1213), `restoreFileVersion` (~line 1304), and `deleteFileVersion` (line 1386) each call `this.folderTree.set(parentIpnsName, folder)` and emit `folder:updated`. The three web hooks (`useFileOperations.updateFile`, `useFileVersions.restoreVersion`, `useFileVersions.deleteVersion`) route through these client methods with zero calls to `updateFolderMetadataAndPublish` and zero direct folder-state store writes on those paths. `folder.store.ts` lines 206-230 write `children`/`sequenceNumber` ONLY inside the `folder:updated`/`folder:loaded` subscription. `folder.store.test.ts` 5 tests prove it including root folder. CONFIRMED.

3. **publishWithCas wired into BOTH folder/index.ts and file/index.ts**: `grep -c 'publishWithCas' packages/sdk-core/src/folder/index.ts` = 2 (import + call). `grep -c 'publishWithCas' packages/sdk-core/src/file/index.ts` = 2 (import + call). CONFIRMED.

4. **fill(0) still present in updateFileMetadata finally**: `file/index.ts` line 371: `params.fileIpnsPrivateKey.fill(0)` inside a `} finally {` block (lines 368-372). CONFIRMED.

5. **updatedChildren NOT in any shared-write return object; updateSharedFile unpins prunedCids**: All 4 return statements in `shared-write.ts` (lines 227, 328, 366, 397) return `publishedChildren`, not `updatedChildren`. The `updatedChildren` variable appears only as a local intermediate (input to `updateFolderMetadataAndPublish`), not in the return type. `updateSharedFile` (lines 461-486) destructs `prunedCids` and fire-and-forget unpins each. CONFIRMED.

### Human Verification Required

### 1. Delete-file resurrection regression (PR #489 TC08)

**Test:** With a running local stack (API + IPFS + IPNS polling), upload a file to a folder, delete a second file in the same folder, then immediately replace the first file's content using the web UI. Wait one IPNS poll cycle (30 seconds). Observe the folder listing.

**Expected:** The deleted file does NOT reappear. The folder listing after the poll should contain only the first file (replaced content) and not the previously deleted file.

**Why human:** Requires a live API server and a full IPNS polling cycle to trigger the deleted-file resurrection race condition that Phase 47 / PR #489 targeted. The fix routes all folder-state mutations through the SDK client `folderTree`, preventing the stale-sequence 409 + merge that previously resurrected deleted files. Cannot be verified by grep, static analysis, or offline unit tests.

## Gaps Summary

No gaps found. All 5 must-haves (9 constituent truths) are VERIFIED. Phase goal achieved pending one human runtime check.

---

_Verified: 2026-06-15T14:47:00Z_

_Verifier: Claude (gsd-verifier)_
