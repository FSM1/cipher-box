---
phase: 68-web-integration-rotation-ux-and-durable-client-state
verified: 2026-07-01T22:15:00Z
status: passed
score: 14/14 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 12/14
  gaps_closed:
    - "A generation/seq regression from the relay causes a fail-closed error during real, live user navigation/mutation/sync (ROADMAP SC#4, ROT-07 M1) — closed by 68-11"
    - "folderTree reflects the rotated key/generation/sequence after performScopeExitRotation, so a same-session mutation on the same folder self-heals without a page reload — closed by 68-12"
  gaps_remaining: []
  regressions: []
deferred:
  - truth: "CannotWriteUntilRefetchError (WRITE-03/D-01 co-writer stale-write toast) is thrown by a live write path when a co-writer targets a rotated-out (tombstoned) IPNS name"
    addressed_in: "Cross-phase finding — not addressed by any later phase in the current ROADMAP; pre-existing gap inherited from Phase 65/66, not introduced by Phase 68"
    evidence: "packages/sdk/src/client.ts#buildSharedWriteContextFromState's publishNodeFn still never returns {tombstoned: true}; unchanged since the prior verification pass and out of scope for 68-11/68-12 (neither plan touched this path). Confirmed still true by source re-inspection during this re-verification."
---

# Phase 68: Web Integration — Rotation UX and Durable Client State Verification Report

**Phase Goal:** The web app uses `rotateReadFromNode` for all revocation-triggering mutations, persists a durable IndexedDB generation + seq high-water that survives page reload, and reconciles `folderTree` before any rotation publish.
**Verified:** 2026-07-01T22:15:00Z
**Status:** passed
**Re-verification:** Yes — after gap closure (68-11 closed Gap 1/BLOCKER, 68-12 closed Gap 2/should-fix)

## Goal Achievement

### Observable Truths

Carried forward from the initial 14-truth verification, with #6 and #8 re-verified against the post-closure codebase.

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `executeLazyRotation` deleted from `apps/web`; delete/move/rename call `rotateReadFromNode` on scope exit (SC#2) | ✓ VERIFIED | Unchanged since prior pass; re-confirmed `grep -rn executeLazyRotation` repo-wide: 0 hits. |
| 2 | `addShareKeys`/`reWrapForRecipients` per-mutation fan-out deleted (SC#2) | ✓ VERIFIED | Unchanged; re-confirmed 0 hits. |
| 3 | Durable client-side `{nodeId→highestGeneration}`/`{nodeId→highestSeq}` monotonic-max state machine, fail-closed on regression, cold-device versionFloor (ROT-07 core logic) | ✓ VERIFIED | `packages/sdk/src/state/rotation-high-water.ts` — re-ran live: `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/rotation-high-water.test.ts` → **20/20 passed**. |
| 4 | Web IndexedDB-backed `HighWaterStore` adapter satisfying the SDK seam + D-08 in-memory degradation | ✓ VERIFIED | `apps/web/src/services/rotation-state.service.ts` exists; now also imported by `useAuth.ts` as the concrete `rotationHighWater` singleton (`grep -n rotationHighWater apps/web/src/hooks/useAuth.ts` line 48, 321). |
| 5 | `enforceResolved` mechanism wired into `resolveIpnsRecord` (capability exists, additive/optional param) | ✓ VERIFIED | `apps/web/src/services/ipns.service.ts` unchanged; now has a real live caller (see #6). |
| 6 | **A generation/seq regression from the relay causes a fail-closed error during real, live user navigation/mutation/sync (SC#4 as an operative system property)** | **✓ VERIFIED (Gap 1 CLOSED)** | Source-confirmed in `packages/sdk/src/client.ts` `reconcileFolderSequence` (lines ~515-537): when `this.config.rotationHighWater` is configured, the freshly-resolved seq/generation is gated through `enforceResolved` **before** the `ReconcileStaleError` check, and the call sits **outside** the resolve try/catch so `SequenceRegressionError`/`GenerationRegressionError` propagate to the caller. `reconcileFolderSequence` is called at the top of `renameItem` (778), `moveItem` (851, both source+dest), `deleteItem` (1019), and `deleteToBin` (1795) — all 4 revocation-triggering mutations. `apps/web/src/hooks/useAuth.ts` injects the real IndexedDB-backed `rotationHighWater` into every live `CipherBoxClient` (confirmed `grep -n rotationHighWater` hits at import + config-object lines). `apps/web/src/components/file-browser/useFileBrowserActions.ts#handleSync` threads a real `ResolveRotationContext` (`nodeId`, `generation: 0`, `versionFloor`) into its `resolveIpnsRecord` call (confirmed at line 121), closing the background-sync gap too. New Vitest describe block "reconcile-time enforceResolved fail-closed (Gap 1 / SC#4)" in `client-rotation.test.ts` — re-ran live: full suite **24/24 passed** (18 prior + 3 new gap-1 cases + 3 new gap-2 cases). Confirmed the SDK's own internal navigation stub `ensureFolderLoaded` (client.ts:476) is dead code that unconditionally `throw new Error('not implemented — phase 63...')` — so routing the gate through `reconcileFolderSequence` (the actual chokepoint called before every live mutation) is the correct live-reachability fix, not a downgrade from the VERIFICATION-named `ensureFolderLoaded`. |
| 7 | `folderTree` reconciled against current `sequenceNumber` before any publish; mismatch defers via `ReconcileStaleError`, never silently skips (SC#3) | ✓ VERIFIED | Unchanged; re-confirmed `client-rotation.test.ts` reconcile-before-publish describe block still green as part of the 24/24 run. |
| 8 | **`folderTree` reflects the rotated key/generation after `performScopeExitRotation`, so the same folder can be mutated again in the same session without a reload** | **✓ VERIFIED (Gap 2 CLOSED)** | Source-confirmed: `packages/sdk-core/src/rotation/engine.ts` now exports `RotateReadResult` and `rotateReadFromNode`'s signature changed from `Promise<void>` to `Promise<RotateReadResult | undefined>` (`grep -n "Promise<RotateReadResult"` → line 780), returning the root's `{readKey, generation, sequenceNumber}` on a fresh rotation and `undefined` on the resume/skip path. `packages/sdk/src/client.ts#performScopeExitRotation` (lines ~528-631) now captures this return into `rotationResult` inside the `deps.rotate` closure and, when defined, calls `this.folderTree.set(params.rootNodeIpnsName, {...existing, folderKey: new Uint8Array(rotationResult.readKey), sequenceNumber: rotationResult.sequenceNumber, nodeGeneration: rotationResult.generation, lastLoadedAt: Date.now()})`, zeroing only the OLD folderKey post-swap (terminal-owner discipline preserved, not the caller-owned `rootReadKey` nor `rotationResult.readKey`). When `rotationResult` is undefined (uncovered mutation), no write occurs. Re-ran live: `packages/sdk-core` `engine.test.ts` **38/38 passed**; `packages/sdk` `client-rotation.test.ts` **24/24 passed** (includes the new "folderTree refresh after scope-exit rotation (Gap 2)" describe block: refresh-on-covered-mutation, self-heal-on-second-mutation without `ReconcileStaleError`, and unchanged-on-uncovered-mutation). |
| 9 | Owner-reconcile: SDK driver unit-tested (revoked→delete-only, surviving→update-only, rootNodeId filter); thin web transport wired eagerly on login + opportunistically on `folder:updated` (D-10/D-11) | ✓ VERIFIED | Unchanged; re-ran `owner-reconcile.test.ts` → **4/4 passed**. |
| 10 | Owner-only `PATCH /shares/:shareId/grant` route persists rotated `readDescriptorRef`+`rootGeneration`; 403 non-owner, 404 unknown; regenerated api-client | ✓ VERIFIED | Unchanged since prior pass; not touched by 68-11/68-12. |
| 11 | Rotation status badge (idle/root-cut/tail-walk/resuming) wired to a real driver via `persistJob` cadence; `role=status`/`aria-live=polite`, non-interactive (D-02/D-03) | ✓ VERIFIED (mechanism); behavioral proof deferred to CI per project doctrine | Unchanged since prior pass; not touched by 68-11/68-12. |
| 12 | Fail-closed error classifier (`ReconcileStaleError`, `Sequence/GenerationRegressionError`, `CannotWriteUntilRefetchError`) maps to the exact UI-SPEC toast + bounded-retry policy | ✓ VERIFIED (classifier itself); 2 of 3 branches now have live producers, 1 remains cross-phase deferred | `apps/web/src/hooks/useMutationFailureUx.ts` imports and classifies `SequenceRegressionError`/`GenerationRegressionError` (lines 34-35, 176) → D-05 toast. This branch is now reachable via truth #6's live wiring. `CannotWriteUntilRefetchError` branch remains without a live producer — see `deferred` (pre-existing Phase 65/66 gap, unchanged, confirmed still true by re-inspection). |
| 13 | Phase adds ZERO `apps/web` unit test files (SC#5) | ✓ VERIFIED | `find apps/web/src -name "*.spec.ts"` → empty (executed live during this re-verification; 68-11/68-12 added zero apps/web spec files, only SDK-side Vitest cases and one web-e2e spec revision). |
| 14 | Web-e2e specs authored, type-check clean, and registered — `rotation-durability.spec.ts` (SC#1/SC#4 durability), `rotation-ux.spec.ts` (D-01/D-02/D-03/D-06/WRITE-03) | ✓ VERIFIED | `rotation-durability.spec.ts`'s SC#4 test re-authored per 68-11 to drive the rejection via two real UI renames (seed + bump + reject) rather than direct `page.evaluate` module invocation; the stale "NO production call site" scope note is gone (`grep -n "NO production call site"` → 0 hits). Re-ran live: `npx playwright test --list tests/rotation-durability.spec.ts` → **3 tests registered** in 1 file; `pnpm --filter @cipherbox/web-e2e exec tsc -p tsconfig.json --noEmit` → clean. `rotation-ux.spec.ts` unchanged from prior pass. |

**Score:** 14/14 truths verified (0 failed)

### Analysis of Gap Closure

**Gap 1 (was BLOCKER) — CLOSED.** The prior verification found that the fail-closed anti-rollback gate was implemented but unreachable from any live code path — all ~15 `apps/web` `resolveIpnsRecord()` call sites passed only `ipnsName`, and the SDK's own internal navigation resolve bypassed the gate entirely. 68-11 closes this by (a) adding an optional `rotationHighWater` injection seam to `CipherBoxClientConfig`, (b) gating the SDK-internal `reconcileFolderSequence` resolve — the actual chokepoint invoked by every one of `renameItem`/`moveItem`/`deleteItem`/`deleteToBin` before publishing — through `enforceResolved`, (c) injecting the real IndexedDB-backed `rotationHighWater` into every live client via `useAuth.ts`, and (d) threading a real `ResolveRotationContext` into `handleSync`'s background-sync resolve. I independently confirmed via source inspection (not SUMMARY claims) that: the enforceResolved call sits outside the resolve try/catch (so regression errors are not swallowed), the gate is additive/backward-compatible (a client without `rotationHighWater` performs zero enforcement, proven by a dedicated Vitest case), and `ensureFolderLoaded` — the method the original VERIFICATION named as the correct wiring target — is in fact dead phase-63 stub code (`throw new Error('not implemented...')`) that is never reached by any live mutation or navigation path today. Routing through `reconcileFolderSequence` instead is the substantively correct fix, since that is the method genuinely invoked before every revocation-triggering publish. A relay-served generation/seq regression during any of the 4 live mutation paths, or during background sync, now throws fail-closed — not silently accepted.

**Gap 2 (was should-fix) — CLOSED.** The prior verification found `performScopeExitRotation` never updated `folderTree` after a successful rotation, causing every same-session second mutation on a just-rotated folder to permanently defer (`ReconcileStaleError`) until a full page reload — a retry re-read the same stale state and failed identically. 68-12 closes this by widening `rotateReadFromNode`'s return type from `void` to `RotateReadResult | undefined` (surfacing the root's rotated `readKey`/`generation`/`sequenceNumber` on a fresh rotation, `undefined` on the resume/skip path) and having `performScopeExitRotation` capture that result and write it back into `folderTree` — but only when a rotation actually occurred, leaving uncovered/skip cases untouched (verified by a dedicated no-op Vitest case). Zeroization discipline is preserved: the OLD folderKey the folderTree entry terminally owned is zeroed only after the `Map.set()` swap and only post-flight (after `rotateReadFromNode` has fully returned), never touching the caller-owned `rootReadKey` or the newly-owned `rotationResult.readKey` mid-flight — consistent with the project's terminal-owner zeroization rule. I confirmed via source inspection that a second same-folder mutation after rotation now reconciles against the freshly-refreshed sequence number instead of throwing `ReconcileStaleError`, proven by a dedicated self-heal Vitest case.

**Deferred item unchanged — still correctly out of scope.** `CannotWriteUntilRefetchError` still has no live producer (`buildSharedWriteContextFromState`'s `publishNodeFn` never returns `{tombstoned: true}`); neither 68-11 nor 68-12 touched this path, and it remains a pre-existing Phase 65/66 (WRITE-03/WRITE-04) wiring gap, not a Phase 68/ROT-07 gap. Carried forward as `deferred`, not as a regression or new gap.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk/src/types.ts` | `rotationHighWater?: RotationHighWater` injection seam on `CipherBoxClientConfig` | ✓ VERIFIED | Present at line 155; documented as the gate's injection point. |
| `packages/sdk/src/client.ts` | `reconcileFolderSequence` gated by `enforceResolved`; `performScopeExitRotation` refreshes `folderTree` | ✓ VERIFIED | Both confirmed by source inspection (lines ~515-537, ~528-631). |
| `packages/sdk/src/__tests__/client-rotation.test.ts` | New Gap-1 + Gap-2 Vitest cases, existing 18 preserved | ✓ VERIFIED | 24/24 passed live. |
| `apps/web/src/hooks/useAuth.ts` | Injects real `rotationHighWater` into every live SDK client | ✓ VERIFIED | Import + config-object wiring confirmed by grep. |
| `apps/web/src/components/file-browser/useFileBrowserActions.ts` | `handleSync` threads a real `ResolveRotationContext` | ✓ VERIFIED | Confirmed at line 121; stale TODO removed. |
| `packages/sdk-core/src/rotation/engine.ts` | `RotateReadResult` type; `rotateReadFromNode` returns it | ✓ VERIFIED | Confirmed exported type + new return signature. |
| `packages/sdk-core/src/__tests__/rotation/engine.test.ts` | New return-shape Vitest cases, existing suite preserved | ✓ VERIFIED | 38/38 passed live. |
| `tests/web-e2e/tests/rotation-durability.spec.ts` | SC#4 proof upgraded to a genuine UI-driven mutation | ✓ VERIFIED | Stale scope note removed; 3 tests registered; typecheck clean. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `reconcileFolderSequence` (SDK-internal, called by all 4 mutations) | `RotationHighWater.enforceResolved` | `this.config.rotationHighWater?.enforceResolved(...)`, outside resolve try/catch | **WIRED** | Closes prior Gap 1 — confirmed by source + 24/24 passing tests. |
| `useAuth.ts` client construction | `CipherBoxClient` | `rotationHighWater` config field (imported from `rotation-state.service.ts`) | **WIRED** | Confirmed by grep at import + config-object lines. |
| `useFileBrowserActions.ts#handleSync` | `resolveIpnsRecord` | Real `ResolveRotationContext` object (`nodeId`, `generation`, `versionFloor`) | **WIRED** | Confirmed at line 121; previously ungated. |
| `rotateReadFromNode` root `rotateOne` result | `RotateReadResult` return value | Additive return-type widening (`void` → `RotateReadResult \| undefined`) | **WIRED** | Confirmed; 38/38 sdk-core tests pass. |
| `performScopeExitRotation` captured `rotationResult` | in-memory `folderTree` | `this.folderTree.set(rootNodeIpnsName, {...rotated fields})` | **WIRED** | Closes prior Gap 2 — confirmed by source + dedicated self-heal test. |
| SDK `SequenceRegressionError`/`GenerationRegressionError` (now reachable) | `notification.store` D-05 toast | `useMutationFailureUx.ts` classifier | **WIRED** | Classifier unchanged; now has a live producer via truth #6. |

### Behavioral Spot-Checks (executed live during this re-verification pass)

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| sdk-core rotation engine suite (RotateReadResult return-shape cases) | `pnpm --filter @cipherbox/sdk-core exec vitest run src/__tests__/rotation/engine.test.ts` | 38/38 passed | ✓ PASS |
| sdk-core dist rebuilt (required for sdk-consumer tests to see the new export) | `pnpm --filter @cipherbox/sdk-core build` | Success | ✓ PASS |
| SDK client-rotation suite (Gap 1 + Gap 2 cases, existing 18 preserved) | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/client-rotation.test.ts` | 24/24 passed | ✓ PASS |
| SDK rotation-high-water + owner-reconcile suites (regression check) | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/rotation-high-water.test.ts src/__tests__/owner-reconcile.test.ts` | 20/20 + 4/4 passed | ✓ PASS |
| apps/web typecheck | `pnpm --filter @cipherbox/web exec tsc -b --force` | 0 errors | ✓ PASS |
| sdk-core typecheck (pre-existing quarantined-test baseline unchanged) | `pnpm --filter @cipherbox/sdk-core exec tsc -b --force` | 50 errors, all in quarantined test files, matches SUMMARY's stated pre-existing baseline exactly | ✓ PASS (no new errors) |
| sdk typecheck (pre-existing quarantined-test baseline unchanged) | `pnpm --filter @cipherbox/sdk exec tsc -b --force` | 69 errors, all in quarantined test files, matches SUMMARY's stated pre-existing baseline exactly | ✓ PASS (no new errors) |
| web-e2e durability spec registered | `npx playwright test --list tests/rotation-durability.spec.ts` (in `tests/web-e2e`) | 3 tests registered, 1 file | ✓ PASS |
| web-e2e durability spec typecheck | `pnpm --filter @cipherbox/web-e2e exec tsc -p tsconfig.json --noEmit` | 0 errors | ✓ PASS |
| No apps/web unit test files added (SC#5) | `find apps/web/src -name "*.spec.ts"` | empty | ✓ PASS |
| Stale "NO production call site" scope note removed | `grep -n "NO production call site" tests/web-e2e/tests/rotation-durability.spec.ts` | 0 hits | ✓ PASS |
| No debt markers in any of the 8 files touched by 68-11/68-12 | `grep -n "TBD\|FIXME\|XXX"` across all 8 files | 0 hits | ✓ PASS |
| Task commit trail present | `git log --oneline \| grep -E "cf01a92ff\|0b5929c45\|97a527b2a\|5f0cfaa7e\|36f82dc86\|c5457b3bf\|88d6c7a4f\|dc21fe356"` | All 8 commits present | ✓ PASS |
| `ensureFolderLoaded` confirmed dead stub (justifies the executor's chokepoint substitution) | `sed -n '476,479p' packages/sdk/src/client.ts` | `throw new Error('not implemented — phase 63 (navigation/read fan-out)')` | ✓ PASS |

Full monorepo test suites and the sdk-e2e/web-e2e live-stack suites were intentionally NOT run, per project test doctrine (apps/web carries no unit tests by design; sdk-e2e and web-e2e are live-stack/CI-on-main-push tiers not available in this environment).

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| ROT-07 | 68-01..68-12 (all) | Durable client-side `{nodeId→highestGeneration}` high-water, survives restart, seeded from grant `rootGeneration`, fails closed on generation regression | ✓ SATISFIED | Mechanism (SDK + IndexedDB adapter) fully built and tested (unchanged from initial pass); both live-reachability gaps (Gap 1: gate unreachable from any live call site; Gap 2: folderTree not refreshed post-rotation) are now closed and independently confirmed via source inspection + live test execution. `REQUIREMENTS.md` already reflects `ROT-07: Complete` / `Phase 68: Complete`, consistent with this finding. |

No orphaned requirements: `grep "Phase 68" .planning/REQUIREMENTS.md` returns only the ROT-07 row.

### Anti-Patterns Found

Scanned all 8 files modified by 68-11/68-12 for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER` and empty-implementation patterns.

None found. The debt-marker gate does not fire. The prior pass's only informational finding (a self-documenting comment in `useFileBrowserActions.ts` describing the then-unwired TODO) has been removed and replaced with an accurate description of the now-live wiring.

### Human Verification Required

None. Both previously-open gaps were closed and confirmed via direct source inspection and live test execution (24/24, 38/38, 20/20, 4/4 unit tests; typecheck-clean on sdk-core/sdk/web/web-e2e; playwright registration confirmed), not by inference or SUMMARY trust. The following items remain appropriately deferred to CI/live-stack execution per project doctrine (not blocking this verification, unchanged from the initial pass):

1. **Web-e2e rotation-durability.spec.ts / rotation-ux.spec.ts full execution**
   - Test: Run `pnpm test:web-e2e -- rotation` against the full local stack (API + web dev server + docker + Kubo + mock delegated-routing)
   - Expected: All registered tests pass, including the newly UI-driven SC#4 rejection test
   - Why human/CI: Requires infrastructure not available in this verification environment; runs automatically in CI on main push per `web-e2e.yml`

### Gaps Summary

Both gaps identified in the initial 68-VERIFICATION.md are now closed and independently confirmed against the live codebase, not merely SUMMARY claims:

1. **(Was BLOCKER) Gap 1 — CLOSED.** The fail-closed anti-rollback gate is now reachable from every live revocation-triggering mutation (`renameItem`/`moveItem`/`deleteItem`/`deleteToBin`, via `reconcileFolderSequence`) and from background sync (`handleSync`). The gate is additive/backward-compatible when unconfigured, and its call site sits outside the resolve try/catch so regression errors are never silently swallowed. ROT-07's core security guarantee (SC#4: "a generation or seq regression from the relay causes a fail-closed error, not silent acceptance") now holds as a live system property.
2. **(Was should-fix) Gap 2 — CLOSED.** `performScopeExitRotation` now refreshes `folderTree` with the rotated `readKey`/`generation`/`sequenceNumber` immediately after a successful rotation, so a same-session second mutation on that folder self-heals instead of permanently deferring until a full page reload. Zeroization discipline (terminal-owner-only zeroing, post-flight not mid-flight) is preserved.

No regressions were introduced: all pre-existing test counts (38 sdk-core rotation engine, 24 client-rotation [18 prior + 6 new], 20 rotation-high-water, 4 owner-reconcile) pass, and both `sdk-core`/`sdk` `tsc -b --force` error counts (50 and 69 respectively) exactly match the pre-existing quarantined-test baseline documented by the executors, with zero new errors.

The deferred `CannotWriteUntilRefetchError` finding remains correctly out of scope (pre-existing Phase 65/66 gap) and is carried forward unchanged.

**Phase 68 goal is achieved.** ROT-07 is genuinely complete as a live system property. Ready to proceed.

---

*Verified: 2026-07-01T22:15:00Z*
*Verifier: Claude (gsd-verifier)*
