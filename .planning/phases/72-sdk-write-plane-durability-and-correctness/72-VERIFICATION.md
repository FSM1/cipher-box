---
phase: 72-sdk-write-plane-durability-and-correctness
verified: 2026-07-10T18:45:00Z
status: passed
score: 6/6 must-haves verified
behavior_unverified: 0
overrides_applied: 0
human_verification:
  - test: "Upload a file in the web app, replace its content with a larger file, and confirm the folder listing row's size/date update without a manual page refresh (SC#4)."
    expected: "The updated size/modifiedAt appear in the visible listing immediately after the replace completes."
    why_human: "listingCache invalidation is proven at the unit level (maybe-republish-listing-cache.test.ts asserts the fresh size is emitted), but the end-to-end visual refresh in the running web app is a UI observation, not a pure code check. Documented as a required Manual-Only Verification in 72-VALIDATION.md and not yet exercised in the browser."
  - test: "Run the full web-e2e suite (writable-shares + move-restore-content specs) against the live docker/API stack."
    expected: "All specs pass, confirming the SC#6 client.ts consolidation (walkChildWriteKey/hasRealWriteKey/write-body-params.ts/runFileVersionOp) introduced no behavioral regression in the browser-driven write paths."
    why_human: "This is a high-blast-radius refactor across 7+ write-plane call sites. Unit tests (389 passing) and a live sdk-e2e round-trip (26 passing) already gate behavior preservation, but the phase's own plans (08, 10) explicitly deferred the full web-e2e run to the phase-final gate, and it has not been executed in this verification session (no live docker/API stack was started)."
---

# Phase 72: SDK Write-Plane Durability and Correctness Verification Report

**Phase Goal:** The SDK write plane no longer grows or corrupts the write-chain on delete/move/restore/replace, fails closed on a transient resolve miss instead of sealing an empty write-body, keeps the display listing fresh after in-place edits, and drops a latent wrong-key branch — with the duplicated write-plane helper sequences consolidated and two write-chain tests hardened.

**Verified:** 2026-07-10T18:45:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (per Success Criterion)

| # | Success Criterion | Status | Evidence |
|---|------|--------|----------|
| SC#1 | `deleteItem` drops the removed child's `WriteChildRef` by resolved UUID; write-body CAS-merge is base-aware (no resurrection under a racing writer) | VERIFIED | `client.ts` `deleteItem` (L2978-3038) resolves `removedItem.ipnsName` → `PublishedNode.id`, filters `writeChildren` by that UUID, threads the pre-trim snapshot as `baseWriteChildren`, fails open (try/catch + `console.warn`) on a resolve miss. `registration.ts` `merge()` (L332-367) implements the base-aware prune: a childId present in `baseWriteChildren` but absent from local is pruned even if remote still carries it; genuinely concurrent remote-only adds are kept. Targeted tests run and green: `registration.test.ts` Test A/B/C (8 tests) and `delete-item.test.ts` (3 tests). |
| SC#2 | Both `getWriteBodyParams` copies (client.ts, bin/index.ts) fail closed (throw) on a transient `!resolved` when a real writeKey is present; the zero-writeKey and `!writeSealed` fail-open paths are unchanged | VERIFIED | Consolidated single implementation in `packages/sdk/src/write-body-params.ts` (L65-87), imported by both `client.ts` (as `getWriteBodyParamsShared`) and `bin/index.ts`. `!hasRealWriteKey(wk)` → `{}` (unchanged fail-open). `!resolved` → throws a descriptive error naming the folder's ipnsName. `!published.writeSealed` → `{ writeKey: wk, writeChildren: [] }` (unchanged fail-open). Targeted test run and green: `get-write-body-params-fail-closed.test.ts` (6 tests). |
| SC#3 | `restoreFromBin` to a different parent re-homes the `WriteChildRef` under the destination write scope (dest-before-source publish, fail-open on unresolvable source) | VERIFIED | `bin/index.ts` `restoreFromBin` (L520-660): when `sourceFolder.ipnsName !== targetFolderIpnsName` and both sides have a real writeKey, unseals the node's `WriteChildRef` under source, reseals under target (keyed by `nodeId` + `restoredItem.generation`), publishes TARGET before SOURCE, and drops the ref from source. Any source-side failure is caught and degrades to read-plane-only restore (never throws). `permanentDeleteFromBin` (L730+) drops the lingering original-parent ref by `BinEntry.nodeRef.id`. Targeted tests run and green: `restore-from-bin-rehoming.test.ts` (9 tests), `permanent-delete-drop-write-link.test.ts` (5 tests). |
| SC#4 | An in-place file edit invalidates the folder `listingCache` (not a reintroduced `SealedChildRef` mirror) | VERIFIED | `client.ts` `maybeRepublishFolderForFileMigration` (L3902+) calls `this.listingCache.delete(folderIpnsName)` gated on a caller-computed `fileContentChanged` boolean (L3946-3948), threaded from `replaceFile`/`restoreFileVersion`/`deleteFileVersion` (L4025). Confirmed `SealedChildRef` (`packages/core/src/node/types.ts` L89-108) still has exactly `{name, ipnsName, generation, versionFloor, readKeySealed}` — no `size`/`modifiedAt` fields added (NODE-03 frozen field set preserved; no mirror reintroduced). `updateSharedSingleFile`'s two `unwrapKey` calls now live inside the `try` (L5461-5465), zeroing both keys even when the second throws. Targeted tests run and green: `maybe-republish-listing-cache.test.ts` (2 tests), `update-shared-single-file.test.ts` (6 tests). |
| SC#5 | The unreachable `moveInSharedFolder` `shareKeys.length > 0` branch and `getShareKeysFn` param are removed; a live regression gate exists | VERIFIED | `grep -c "shareKeys.length" packages/sdk/src/client.ts` = 0; `grep -c "getShareKeysFn"` = 0. `moveInSharedFolder` signature (L5642-5650) no longer accepts `getShareKeysFn`. Both `apps/web/src/hooks/useSharedWriteOps.ts` call sites updated (no removed arg). `move-in-shared-folder.test.ts` no longer `describe.skip`'d — one live `it` block exercising the reachable branch. Targeted test run and green (1 test). Web typecheck (`tsc -b`) clean. |
| SC#6 | Write-plane helpers consolidated (`walkChildWriteKey`, `hasRealWriteKey`, `wrapIpnsKeyForTee`, `write-body-params.ts`, `runFileVersionOp`); `write-chain-rotation.test.ts` identifies seeds by provenance; `upload-batch.test.ts` mocks use current `SealedChildRef` | VERIFIED | `walkChildWriteKey` (client.ts L143, 3-mode `'require'\|'skip'\|'nullable'` string-literal union) replaces 7 divergent inline hop-walk sites. Single `hasRealWriteKey` now lives only in `write-body-params.ts` (no duplicate definitions found elsewhere in `packages/sdk/src`). `wrapIpnsKeyForTee` (`packages/sdk-core/src/tee/wrap.ts`) is imported and used by all 3 sdk-core sites (`file/index.ts`, `vault/index.ts`, `folder/registration.ts`) — confirmed by grep, no residual inline TEE-wrap sequences. `write-body-params.ts` is the single shared module for `getWriteBodyParams`/`adoptPublishedFolderState`, imported by both `client.ts` and `bin/index.ts`. `runFileVersionOp` (client.ts L3988) is the shared core for `replaceFile`/`restoreFileVersion`/`deleteFileVersion`. `write-chain-rotation.test.ts` identifies rotated seeds via `vi.spyOn(cryptoModule, 'generateEd25519Keypair')` and reads back `.mock.results` (L315-335) — no fixed `capturedKeys[N]` offset lookup found. `upload-batch.test.ts`'s `SealedChildRef` mock (L100-106) uses the current 5-field shape; `fileMetaIpnsName`/`ipnsPrivateKeyEncrypted` appearing elsewhere in the file are legitimate current fields of the separate `UploadResult` type (`packages/sdk-core/src/upload/index.ts` L46-79), not retired `SealedChildRef` fields. |

**Score:** 6/6 Success Criteria verified (0 present-but-behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk-core/src/folder/registration.ts` | Base-aware write-body CAS-merge | VERIFIED | `baseWriteChildren` param + prune logic present (L161-367) |
| `packages/sdk/src/client.ts` `deleteItem` | UUID-resolve + write-chain trim | VERIFIED | L2978-3080 |
| `packages/sdk/src/__tests__/delete-item.test.ts` | New regression test | VERIFIED | 3 tests, all passing |
| `packages/sdk/src/write-body-params.ts` | Shared `getWriteBodyParams`/`adoptPublishedFolderState`/`hasRealWriteKey` | VERIFIED | Created; imported by both client.ts and bin/index.ts |
| `packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts` | Fail-closed regression | VERIFIED | 6 tests, all passing |
| `packages/sdk/src/bin/index.ts` `restoreFromBin`/`permanentDeleteFromBin` | Re-homing + drop logic | VERIFIED | L452-800 |
| `packages/sdk/src/__tests__/restore-from-bin-rehoming.test.ts` | New regression test | VERIFIED | 9 tests, all passing |
| `packages/sdk/src/__tests__/permanent-delete-drop-write-link.test.ts` | New regression test | VERIFIED | 5 tests, all passing |
| `packages/sdk/src/client.ts` `maybeRepublishFolderForFileMigration` | listingCache invalidation | VERIFIED | L3902-3953 |
| `packages/sdk/src/__tests__/maybe-republish-listing-cache.test.ts` | New regression test | VERIFIED | 2 tests, all passing |
| `packages/sdk/src/__tests__/update-shared-single-file.test.ts` | Zeroize regression | VERIFIED | 6 tests, all passing |
| `packages/sdk/src/client.ts` `moveInSharedFolder` | Dead branch removed | VERIFIED | No `shareKeys.length`/`getShareKeysFn` matches |
| `apps/web/src/hooks/useSharedWriteOps.ts` | Call sites updated | VERIFIED | Both call sites drop removed arg; web typechecks |
| `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` | Live reachable-path test | VERIFIED | No longer `describe.skip`; 1 test passing |
| `packages/sdk/src/client.ts` `walkChildWriteKey`/`hasRealWriteKey` | Consolidated primitives | VERIFIED | walkChildWriteKey at L143; hasRealWriteKey imported from write-body-params.ts |
| `packages/sdk-core/src/tee/wrap.ts` | `wrapIpnsKeyForTee` shared helper | VERIFIED | Used by 3 sdk-core sites |
| `packages/sdk/src/client.ts` `runFileVersionOp` | Shared version-op core | VERIFIED | L3988; used by replaceFile/restoreFileVersion/deleteFileVersion |
| `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` | Provenance-based seed ID | VERIFIED | `vi.spyOn` + `.mock.results`, no fixed offsets; typechecks clean |
| `packages/sdk/src/__tests__/upload-batch.test.ts` | Current `SealedChildRef` mock shape | VERIFIED | 5-field shape confirmed; other fields belong to `UploadResult`, not retired |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `deleteItem` (client.ts) | `registration.ts` merge() | `baseWriteChildren` param threaded through `updateFolderMetadataAndPublish` | WIRED | Confirmed by reading both call site and merge implementation |
| `client.ts` / `bin/index.ts` | `write-body-params.ts` | `import { getWriteBodyParams, adoptPublishedFolderState, hasRealWriteKey }` | WIRED | Both files import from the shared module; no local re-implementations remain |
| Plan 01 regression test | `moveInSharedFolder` reachable branch | Live `it` block exercises the write-chain move | WIRED | Test not skipped; passes against the post-removal code |
| `sdk-core` 3 TEE sites | `tee/wrap.ts` | `import { wrapIpnsKeyForTee }` | WIRED | Confirmed at file/index.ts, vault/index.ts, folder/registration.ts |
| `replaceFile`/`restoreFileVersion`/`deleteFileVersion` | `runFileVersionOp` | Shared private core, each public method wraps its own `withOperation` and delegates | WIRED | Confirmed by reading client.ts |

### Behavioral Spot-Checks (targeted single-file test runs, not full suites)

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Base-aware CAS-merge (SC#1) | `vitest run src/__tests__/folder/registration.test.ts` (sdk-core) | 8 passed | PASS |
| deleteItem write-chain trim (SC#1) | `vitest run src/__tests__/delete-item.test.ts` (sdk) | 3 passed | PASS |
| getWriteBodyParams fail-closed (SC#2) | `vitest run src/__tests__/get-write-body-params-fail-closed.test.ts` (sdk) | 6 passed | PASS |
| restoreFromBin re-homing + permanent-delete drop (SC#3) | `vitest run src/__tests__/restore-from-bin-rehoming.test.ts src/__tests__/permanent-delete-drop-write-link.test.ts` (sdk) | 14 passed | PASS |
| listingCache invalidation + zeroize (SC#4) | `vitest run src/__tests__/maybe-republish-listing-cache.test.ts src/__tests__/update-shared-single-file.test.ts` (sdk) | 8 passed | PASS |
| moveInSharedFolder reachable-path gate (SC#5) | `vitest run src/__tests__/move-in-shared-folder.test.ts` (sdk) | 1 passed | PASS |
| sdk-e2e write-chain-rotation typecheck (SC#6) | `pnpm --filter sdk-e2e exec tsc --noEmit` | clean, 0 errors | PASS |
| sdk build | `pnpm --filter @cipherbox/sdk build` | tsup + tsc clean | PASS |
| sdk-core build | `pnpm --filter @cipherbox/sdk-core build` | tsup clean | PASS |
| web typecheck (SC#5/SC#6 caller changes) | `pnpm --filter @cipherbox/web exec tsc -b` | clean, 0 errors | PASS |
| Debt-marker scan on modified files | `grep -n "TBD\|FIXME\|XXX\|TODO\|HACK\|PLACEHOLDER"` across all 8 phase-touched files | no matches | PASS |
| skip-count regression (sdk) | `grep -rln "describe.skip\|it.skip"` in `packages/sdk/src/__tests__` | only `integration.test.ts` (live-API) | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|--------------|------------|-------------|--------|----------|
| SC#1 | 72-03, 72-05 | deleteItem drops WriteChildRef, base-aware merge | SATISFIED | See truths table |
| SC#2 | 72-04 | getWriteBodyParams fail-closed (both copies) | SATISFIED | See truths table |
| SC#3 | 72-05 | restoreFromBin re-homing | SATISFIED | See truths table |
| SC#4 | 72-06 | listingCache invalidation + zeroize fix | SATISFIED | See truths table |
| SC#5 | 72-01, 72-07 | moveInSharedFolder dead branch removal | SATISFIED | See truths table |
| SC#6 | 72-02, 72-08, 72-09, 72-10 | Write-plane helper dedup + test hardening | SATISFIED | See truths table |

No orphaned requirements found — all 9 source todos map to the 6 Success Criteria and are covered by the 10 plans.

### Anti-Patterns Found

None. Scanned all 8 phase-touched files (`client.ts`, `bin/index.ts`, `write-body-params.ts`, `registration.ts`, `tee/wrap.ts`, `file/index.ts`, `vault/index.ts`, `useSharedWriteOps.ts`) for `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER`/stub markers — zero matches.

One pre-existing, explicitly-scoped-out item noted honestly in 72-08-SUMMARY.md and 72-10-SUMMARY.md: full-package `tsc --noEmit` (test-inclusive) surfaces unrelated, pre-existing type drift in other `__tests__` files (stale `FolderChild`/`FolderEntry` type references), tracked in an existing untracked todo. Confirmed this is NOT introduced by Phase 72 (targeted per-package `tsc --noEmit` runs used in this verification are clean; the drift is in files this phase never touched).

### Human Verification Required

1. **Manual browser check — SC#4 fresh listing (documented Manual-Only Verification in 72-VALIDATION.md)**
   - **Test:** Upload a file in the web app, replace it with larger content, confirm the folder listing row's size/date update without a manual refresh.
   - **Expected:** Updated size/modifiedAt visible immediately.
   - **Why human:** The underlying cache-invalidation logic is unit-tested and passing (confirmed above), but the end-to-end visual refresh in the running browser is outside static verification. This was already flagged as a required manual check in the phase's own validation strategy and has not been exercised in this session.

2. **Full web-e2e run (writable-shares + move-restore-content) against the live stack**
   - **Test:** Run the Playwright web-e2e suite covering shared-folder write operations and move/restore flows.
   - **Expected:** All specs green, confirming no regression from the SC#6 client.ts consolidation (7+ re-pointed call sites).
   - **Why human:** Requires a live docker/API stack not started in this verification session. The phase's own plans (08, 10) explicitly scoped this to the phase-final gate rather than per-plan. Unit tests (all targeted files re-run above, plus the previously-reported full 412-passed/3-skipped suite) and a live sdk-e2e round-trip (26 passed/0 failed, per the verification context) already gate behavioral correctness at the network-protocol level; this residual is additional browser-level confidence, not a gap in the delivered code.

## Gaps Summary

No gaps found. All 6 Success Criteria are implemented in the live codebase (not just claimed in SUMMARY.md), each backed by a targeted, freshly-re-run passing test in this verification session, plus clean typechecks and clean production builds for `sdk-core`, `sdk`, and `web`. The two items above are pre-existing, explicitly-scoped residual confidence checks (one browser-visual, one live-stack E2E) rather than evidence of incomplete or broken work — they do not block the phase goal, which is fully achieved at the code level.

---

*Verified: 2026-07-10T18:45:00Z*
*Verifier: Claude (gsd-verifier)*
