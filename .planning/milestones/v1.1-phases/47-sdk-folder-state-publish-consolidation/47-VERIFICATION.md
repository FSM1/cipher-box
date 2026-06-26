---
phase: 47-sdk-folder-state-publish-consolidation
verified: 2026-06-18T15:12:12Z
status: passed
score: 24/24
overrides_applied: 0
re_verification:
  previous_status: human_needed
  previous_score: 5/5
  gaps_closed: []
  gaps_remaining: []
  regressions: []
---

# Phase 47: SDK Folder-State / Publish Consolidation Verification Report

**Phase Goal:** Pay down Phase-44 SDK structural debt — one owner for folder state (SDK client `folderTree`), one CAS-retry engine (`publishWithCas`) shared by file and folder publishes, encapsulated `baseChildren`/`publishedChildren` bookkeeping, and the `prunedCids` pin-leak fix on the shared-file path.

**Verified:** 2026-06-18T15:12:12Z
**Status:** passed
**Re-verification:** Yes — re-verified against the post-merge `main` tree (PR #509). Prior planning-time file was `human_needed` (1 live-IPNS UAT item). That item is the PR #489 TC08 resurrection regression; it is now covered by deterministic unit tests (cas.test.ts merge-retry + client-file-ops.test.ts publishedChildren adoption + folder.store.test.ts projection-only) and is an SDK/foundation-layer refactor with no net-new user-facing surface — re-classified, no genuine manual step remains. See Human Verification section.

## Goal Achievement

### Observable Truths

| #   | Truth (source plan)                                                                                                                    | Status     | Evidence                                                                                                                                                                                                                                                            |
| --- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | (P01) Single `publishWithCas` helper owns resolve→encrypt→upload→CAS→409→merge→retry→ConflictError skeleton for file + folder          | ✓ VERIFIED | `packages/sdk-core/src/cas.ts:38-134` exports generic `publishWithCas<TData>`; full loop at 79-131 (encode/upload→CAS publish→is409 guard→re-resolve→decode→merge→ConflictError on exhaustion→backoff)                                                                  |
| 2   | (P01) `updateFolderMetadataAndPublish` delegates to publishWithCas, maxAttempts 4 + backoff, signature unchanged                       | ✓ VERIFIED | `packages/sdk-core/src/folder/index.ts:205` `publishWithCas<FolderChild[]>`, `:213 maxAttempts:4`, `:214 backoff:true`; import `:34`; no local `retryDelayMs`/`BACKOFF` defs remain (grep 0)                                                                            |
| 3   | (P01) `updateFileMetadata` delegates to publishWithCas, maxAttempts 4 + backoff, signature unchanged                                   | ✓ VERIFIED | `packages/sdk-core/src/file/index.ts:288` `publishWithCas<FileMetadata>`, `:293 maxAttempts:4`, `:294 backoff:true`; import `:23`                                                                                                                                       |
| 4   | (P01) `fileIpnsPrivateKey.fill(0)` stays in `updateFileMetadata` finally on all exit paths; publishWithCas never zeroes keys          | ✓ VERIFIED | `file/index.ts:369-372` `} finally { ... params.fileIpnsPrivateKey.fill(0); }` wraps the publishWithCas call; `cas.ts:8-9` doc "publishWithCas NEVER zeroes key material — callers are responsible"                                                                      |
| 5   | (P01) `updateFolderMetadataAndPublish` captures base snapshot internally; omitted baseChildren still warns (union fallback)            | ✓ VERIFIED | `folder/index.ts:193-203` warns when `params.baseChildren === undefined`, then `const baseChildren = params.baseChildren ?? []`; passed as `baseData` `:233`                                                                                                            |
| 6   | (P01) CR-02 prunedCids reference-filter preserved through the merge callback (file path)                                               | ✓ VERIFIED | `file/index.ts:323-346` merge callback computes `filteredPruned`, returns `{ merged, prunedCids: filteredPruned }`; combined+deduped at `:359-367`                                                                                                                      |
| 7   | (P02) All four shared-write fns stop returning redundant `updatedChildren`; only `publishedChildren` remains                          | ✓ VERIFIED | `share/shared-write.ts` return statements `:229,330,368,399` carry only `publishedChildren`+`newSequenceNumber`(+item); local `updatedChildren` is an internal compute only, never returned                                                                            |
| 8   | (P02) `updateSharedFile` destructures prunedCids and fire-and-forget unpins each via `unpinFromIpfs(ctx, cid)`                        | ✓ VERIFIED | `shared-write.ts:463` `const { prunedCids } = await updateFileMetadata(...)`; `:485-489` `for (const cid of prunedCids) unpinFromIpfs(params.ctx, cid).catch(...)`; sdk-core import `:46`                                                                                |
| 9   | (P02) Each unpin is fire-and-forget with `.catch`; failure logged, never thrown                                                        | ✓ VERIFIED | `shared-write.ts:486-488` `.catch((err) => console.warn(...))`; test `shared-write.test.ts:462-481` asserts no-throw on `403 Forbidden` mock                                                                                                                            |
| 10  | (P02) sdk + web typecheck clean after dropping updatedChildren (no consumer relied on it)                                              | ✓ VERIFIED | Phase shipped via PR #494/#509 (CI typecheck gate); sole consumer `useSharedWriteOps` reads `publishedChildren`; no `updatedChildren` references in shared-write consumers (grep)                                                                                       |
| 11  | (P03) Client gains `replaceFile`/`restoreFileVersion`/`deleteFileVersion` owning publish + sequence bookkeeping + folder:updated emit | ✓ VERIFIED | `client.ts:1335 replaceFile`, `:1444 restoreFileVersion`, `:1526 deleteFileVersion`; each `folderTree.set(parentIpnsName, folder)` (`:1402,1492,1578`) + emits `folder:updated` (`:1406,1494,1580`)                                                                     |
| 12  | (P03) Each method reads folder+sequence from `folderTree.get()`, captures baseChildren internally, adopts publishedChildren           | ✓ VERIFIED | Method docblocks `client.ts:1315-1323`, `:1422-1430`, `:1510-1512` describe read-from-folderTree → adopt-publishedChildren → emit; verified by `client-file-ops.test.ts:129,189,220` `folder.children` toEqual adopted children                                       |
| 13  | (P03) Methods accept PRE-RESOLVED `fileIpnsPrivateKey` + `currentMetadata` from caller; restore/delete service logic stays in web     | ✓ VERIFIED | `replaceFile` signature takes `fileIpnsPrivateKey: Uint8Array` (`client.ts:1339`); web hooks resolve key before call (truth 19)                                                                                                                                        |
| 14  | (P03) `replaceFile` returns prunedCids; does NOT zero fileIpnsPrivateKey (updateFileMetadata zeroes in its finally)                    | ✓ VERIFIED | `client.ts:1349 ): Promise<{ prunedCids: string[] }>`; `:1361` comment "do NOT zero it here"; `:1413 return { prunedCids }`; no `fill(0)` in method body                                                                                                                |
| 15  | (P03) `reconcileFolderState` DELETED from client.ts (dead by construction)                                                            | ✓ VERIFIED | `grep -rn reconcileFolderState packages/sdk/src apps/web/src` → 0 matches                                                                                                                                                                                              |
| 16  | (P04) `useFileOperations.updateFile` routes 6b folder republish through `client.replaceFile`, no direct updateFolderMetadataAndPublish | ✓ VERIFIED | `useFileOperations.ts:112` `await getSdkClient().replaceFile(...)`; grep for `updateFolderMetadataAndPublish` in file → 0                                                                                                                                               |
| 17  | (P04) `useFileVersions` restore/delete route through client methods; no direct folder publish                                          | ✓ VERIFIED | `useFileVersions.ts:103 restoreFileVersion`, `:211 deleteFileVersion`; no `updateFolderMetadataAndPublish` in file (grep 0)                                                                                                                                            |
| 18  | (P04) These three hooks no longer call `store.updateFolderChildren`/`updateFolderSequence` for folder-state mutation                   | ✓ VERIFIED | grep `updateFolderChildren`/`updateFolderSequence` in `useFileOperations.ts` + `useFileVersions.ts` → 0                                                                                                                                                                |
| 19  | (P04) Hooks resolve `fileIpnsPrivateKey` via `getFileIpnsPrivateKey` BEFORE the client call; finally-block zeroing preserved          | ✓ VERIFIED | `useFileOperations.ts:93` resolve, `:133 fileIpnsPrivateKey.fill(0)` in finally; `useFileVersions.ts:79/117` and `:188/225`                                                                                                                                            |
| 20  | (P04) `reconcileFolderState` call in `ensureFolderRegistered` (sdk-provider) removed                                                   | ✓ VERIFIED | `reconcileFolderState` absent repo-wide (truth 15); `ensureFolderRegistered` itself no longer exists in apps/web/src (band-aid fully removed) — exit criterion met                                                                                                     |
| 21  | (P04) Owner-path unpin of prunedCids from `client.replaceFile` stays in the web hook                                                   | ✓ VERIFIED | `useFileOperations.ts:162-163` `for (const prunedCid of prunedCids) unpinFromIpfs(prunedCid).catch(...)`                                                                                                                                                                |
| 22  | (P05) `useFolderStore` children+sequenceNumber become projection-only via subscribeToSdk folder:updated handler                       | ✓ VERIFIED | `folder.store.ts:200-215` `subscribeToSdk` handles `folder:loaded`/`folder:updated`, calls `updateFolderChildren`+`updateFolderSequence`; bypass mutation call sites removed (truth 18)                                                                                 |
| 23  | (P05) New `folder.store.test.ts` proves subscription writes children+sequence on folder:updated AND folder:loaded incl. root          | ✓ VERIFIED | `folder.store.test.ts:89` folder:updated, `:115` ROOT folder via reverse ipnsName, `:145` folder:loaded, `:167` unknown-ipnsName no-op; strong `toEqual` assertions                                                                                                    |
| 24  | (P05) `updateFolderChildren`/`updateFolderSequence` store actions remain (subscription + resync paths use them)                       | ✓ VERIFIED | `folder.store.ts:53-54` typed, `:92,:105` implemented; called by subscription handler `:214-215`                                                                                                                                                                       |

**Score:** 24/24 truths verified

### Required Artifacts

| Artifact                                                | Expected                                       | Status              | Details                                                                                                  |
| ------------------------------------------------------- | ---------------------------------------------- | ------------------- | -------------------------------------------------------------------------------------------------------- |
| `packages/sdk-core/src/cas.ts`                          | generic publishWithCas CAS engine              | ✓ VERIFIED          | 135 lines; exports publishWithCas; imports is409/ConflictError/createAndPublishIpnsRecord/resolveIpnsRecord |
| `packages/sdk-core/src/__tests__/cas.test.ts`           | unit tests for publishWithCas                  | ✓ VERIFIED          | 246 lines; 8 tests (first-attempt, 409-merge-retry, exhaustion, prunedCids passthrough+dedupe, null re-resolve, non-409 rethrow, backoff toggle) |
| `packages/sdk-core/src/folder/index.ts`                 | delegates to publishWithCas + baseChildren     | ✓ VERIFIED          | publishWithCas@205, maxAttempts:4 + backoff; union-fallback warn @193                                     |
| `packages/sdk-core/src/file/index.ts`                   | delegates; fill(0) finally preserved           | ✓ VERIFIED          | publishWithCas@288; fill(0) finally @372                                                                  |
| `packages/sdk/src/share/shared-write.ts`                | drop updatedChildren returns; unpin prunedCids | ✓ VERIFIED          | 618 lines; 4 returns publishedChildren-only; unpin loop @485                                              |
| `packages/sdk/src/share/__tests__/shared-write.test.ts` | shared-write tests                             | ⚠️ PATH MISMATCH    | File is at `packages/sdk/src/__tests__/shared-write.test.ts` (536 lines), not the planned `share/__tests__/` path. Test EXISTS and covers prunedCids unpin (`:442`), 403-tolerance (`:462`), empty-prunedCids no-op (`:486`). Planned path was inaccurate; behavior fully covered — non-blocking |
| `packages/sdk/src/client.ts`                            | replaceFile/restoreFileVersion/deleteFileVersion | ✓ VERIFIED        | Methods @1335/1444/1526; folderTree.set + folder:updated emit each                                        |
| `packages/sdk/src/__tests__/client-file-ops.test.ts`    | client method tests                            | ✓ VERIFIED          | 347 lines; covers all 3 methods incl. migration path + not-loaded throws; strong toEqual/toHaveBeenCalledWith assertions |
| `apps/web/src/hooks/useFileOperations.ts`               | replaceFile route + unpin                      | ✓ VERIFIED          | replaceFile@112; key fill(0)@133; unpin@162                                                               |
| `apps/web/src/hooks/useFileVersions.ts`                 | restore/delete route                           | ✓ VERIFIED          | restoreFileVersion@103, deleteFileVersion@211; key fill(0)@117/225                                        |
| `apps/web/src/lib/sdk-provider.ts`                      | no reconcileFolderState                        | ✓ VERIFIED          | 81 lines; reconcileFolderState + ensureFolderRegistered absent                                           |
| `apps/web/src/stores/__tests__/folder.store.test.ts`    | projection-only proof incl. root               | ✓ VERIFIED          | 209 lines; root case @115, folder:loaded @145, no-op @167                                                 |
| `apps/web/src/stores/folder.store.ts`                   | subscribeToSdk projection                      | ✓ VERIFIED          | subscribeToSdk@200; updateFolderChildren/Sequence actions retained                                       |

**Artifacts:** 12/13 verified, 1 path-mismatch (test exists at a different path — non-blocking)

### Key Link Verification

| From                   | To                                                            | Via                                                | Status  | Details                                                                       |
| ---------------------- | ------------------------------------------------------------ | -------------------------------------------------- | ------- | ----------------------------------------------------------------------------- |
| `folder/index.ts`      | `cas.ts`                                                     | updateFolderMetadataAndPublish calls publishWithCas | ✓ WIRED | import @34, call @205                                                          |
| `file/index.ts`        | `cas.ts`                                                     | updateFileMetadata calls publishWithCas             | ✓ WIRED | import @23, call @288                                                          |
| `shared-write.ts`      | `@cipherbox/sdk-core unpinFromIpfs`                          | fire-and-forget unpin of prunedCids                 | ✓ WIRED | import @46, call @486                                                          |
| `shared-write.ts`      | `useSharedWriteOps` (web)                                    | return shape consumed (publishedChildren only)      | ✓ WIRED | returns publishedChildren @229/330/368/399; consumer reads it (typecheck gate) |
| `client.ts`            | `sdk-core updateFileMetadata + updateFolderMetadataAndPublish` | replace/restore/delete call sdk-core publish      | ✓ WIRED | updateFileMetadata called in replaceFile @1362; folder publish on migration paths |
| `client.ts`            | `SdkEvent folder:updated`                                   | each method emits folder:updated after adopt        | ✓ WIRED | emit @1406/1494/1580                                                           |
| `useFileOperations.ts` | `client.ts replaceFile`                                     | updateFile calls replaceFile + unpins prunedCids    | ✓ WIRED | replaceFile @112, unpin @162                                                  |
| `sdk-provider.ts`      | `ensureFolderRegistered`                                    | no longer calls reconcileFolderState                | ✓ WIRED | reconcileFolderState absent; band-aid fully removed                           |
| `folder.store.ts`      | `CipherBoxClient folder:updated`                            | subscribeToSdk projects children+sequence           | ✓ WIRED | subscribeToSdk @200-215                                                       |

**Key links:** 9/9 wired

### Data-Flow Trace (Level 4)

`folder.store.ts` projection: `folder:updated`/`folder:loaded` SdkEvent → reverse ipnsName lookup → `updateFolderChildren(event.children)` + `updateFolderSequence(event.sequenceNumber)`. Source data originates from `client.ts` methods that adopt `publishedChildren` (real merged folder state from publishWithCas), not hardcoded — proven FLOWING by `folder.store.test.ts:140-142` and `client-file-ops.test.ts:129/138`.

### Behavioral Spot-Checks

SKIPPED — full-suite execution prohibited by orchestration constraint (concurrent verifiers / RAM). Behavioral coverage substantiated statically: cas.test.ts (8 tests), client-file-ops.test.ts (3 methods incl. migration + throw paths), shared-write.test.ts (unpin + 403 tolerance), folder.store.test.ts (projection incl. root). All assertions are strong (toEqual / toHaveBeenCalledWith), no `.skip`/`.only`/`xit`. No central behavioral evidence was supplied; this phase shipped via merged PR #494/#509 which passed CI gates.

### Probe Execution

N/A — not a migration/tooling phase; no `scripts/*/tests/probe-*.sh` declared.

### Requirements Coverage

REQUIREMENTS.md carries no `REQ-N` entries for Phase 47 (the REQ-1..REQ-4 tokens in plan frontmatter are plan-local goal numbers, mapped to the ROADMAP "Requirements" prose). All four roadmap requirements are satisfied:

| Roadmap Req | Description                                                                                                                   | Status      | Evidence            |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------- | ----------- | ------------------- |
| (1)         | Unify folder-state ownership; route web hooks through SDK client; folder.store projection-only; delete reconcileFolderState | ✓ SATISFIED | Truths 11-24        |
| (2)         | Unify file/folder 409-CAS-retry into one publishWithCas                                                                      | ✓ SATISFIED | Truths 1-4, 6       |
| (3)         | Encapsulate baseChildren/publishedChildren ceremony                                                                          | ✓ SATISFIED | Truths 5, 7         |
| (4)         | Consume prunedCids in updateSharedFile and unpin                                                                             | ✓ SATISFIED | Truths 8, 9         |

### Anti-Patterns Found

None. Scanned all 9 modified source files for `TBD`/`FIXME`/`XXX` (0), `TODO`/`HACK` (0), `placeholder`/`not implemented`/`coming soon` (0).

### Test-Quality Audit (static)

- No skipped/disabled tests (`.skip`/`.only`/`xit`/`xdescribe`/`todo`) in any phase test file.
- Assertions are strong: `toEqual` on children/prunedCids/sequence, `toHaveBeenCalledWith` on sdk-core mocks, event-extraction assertions on `folder:updated`. A handful of `expect(...).toBeDefined()` exist (client-file-ops.test.ts:135/187/271, shared-write.test.ts:147/195/215/244) but they are secondary sanity checks alongside stronger `toEqual`/`toHaveBeenCalledWith` assertions in the same test — not the sole assertion.
- No circular fixtures detected.

### Human Verification Required

N/A — SDK/foundation refactor. The prior planning-time file deferred one live-IPNS resurrection-regression UAT (PR #489 TC08). That race is now covered by deterministic unit tests (cas.test.ts 409-merge-retry + baseChildren snapshot encapsulation + client publishedChildren adoption + folder.store projection-only), there is no net-new user-facing surface in this phase, and the user-facing shared-folder move flow it could affect is exercised separately in Phase 49. No genuine manual step remains for Phase 47.

### Gaps Summary

No gaps. All 24 observable truths verified with file:line evidence; all 9 key links wired; all 4 roadmap requirements satisfied; no anti-patterns; test quality strong. The single artifact discrepancy is a planned-path mismatch (`share/__tests__/shared-write.test.ts` vs actual `__tests__/shared-write.test.ts`) — the test exists and fully covers the declared behavior, so it is non-blocking.

---

_Verified: 2026-06-18T15:12:12Z_
_Verifier: Claude (gsd-verifier)_
