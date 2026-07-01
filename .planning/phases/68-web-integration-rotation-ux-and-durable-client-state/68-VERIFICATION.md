---
phase: 68-web-integration-rotation-ux-and-durable-client-state
verified: 2026-07-01T18:32:01Z
status: gaps_found
score: 12/14 must-haves verified
behavior_unverified: 0
overrides_applied: 0
gaps:
  - truth: "A generation or seq regression from the relay causes a fail-closed error during real, live user navigation/resolve actions in the running web app (ROT-07 M1 defense / ROADMAP SC#4 as literally worded: 'a generation or seq regression from the relay causes a fail-closed error, not silent acceptance')"
    status: failed
    reason: "The SDK's enforceResolved fail-closed gate (68-01) and the web IndexedDB HighWaterStore adapter (68-06) are both correctly implemented and unit/e2e-module tested, but NOTHING in the running application ever calls them with a live rotation context. Confirmed independently by exhaustive grep: all ~15 apps/web call sites of resolveIpnsRecord() pass only the ipnsName argument (no ResolveRotationContext). Additionally, the SDK client's OWN internal folder-navigation path (packages/sdk/src/client.ts ensureFolderLoaded, line 518) calls sdkCore.resolveIpnsRecord directly — bypassing apps/web's ipns.service.ts wrapper AND the enforceResolved gate entirely. Today a relay serving a rolled-back generation/sequence to any live folder-browse or navigation action is silently accepted, not rejected — the opposite of SC#4's stated guarantee. This is not a SUMMARY claim; it was verified by source inspection of both the wrapper and the SDK client's internal resolve calls."
    artifacts:
      - path: "apps/web/src/services/ipns.service.ts"
        issue: "resolveIpnsRecord's ResolveRotationContext parameter is optional and additive; zero live callers supply it"
      - path: "packages/sdk/src/client.ts"
        issue: "ensureFolderLoaded (folder navigation) calls sdkCore.resolveIpnsRecord directly, never routing through apps/web's enforceResolved-gated wrapper or an equivalent SDK-side gate"
    missing:
      - "Wire a real ResolveRotationContext (nodeId, generation, versionFloor, rootGeneration) into at least one live, frequently-exercised resolve call site — the most natural candidates are packages/sdk/src/client.ts's ensureFolderLoaded/navigation resolve (SDK-internal, would cover ALL folder browsing) and/or apps/web's useFileBrowserActions.ts#handleSync (already has an in-code TODO for exactly this)."
      - "Re-run (or re-author) the 68-10 rotation-durability.spec.ts assertion path once a live trigger exists, to upgrade the proof from direct-module-invocation to a genuine UI-driven regression rejection."
  - truth: "folderTree is updated with the newly-rotated read key/generation/sequence after performScopeExitRotation, so a subsequent same-session mutation on the same folder does not operate on stale in-memory state ('folderTree reconcile-before-rotate' as a durable invariant, not just a pre-publish check)"
    status: failed
    reason: "Confirmed via source inspection: performScopeExitRotation (packages/sdk/src/client.ts) calls sdkCore.rotateReadFromNode, which re-seals and republishes the ROOT node under a NEW readKey and a bumped sequenceNumber/generation, but never calls this.folderTree.set(...) afterward. folder.folderKey/sequenceNumber in the in-memory FolderTree remain the PRE-rotation values. This is safe from a security standpoint (68-05's reconcileFolderSequence, called at the top of the NEXT mutation on the same folder, will detect the now-stale in-memory sequenceNumber against the freshly-resolved network value and throw ReconcileStaleError rather than silently publishing with a wrong key) but it is a real functional gap: every subsequent same-session mutation on a folder that was JUST scope-exit-rotated will deterministically defer, retry ~5 times over ~30s (68-09's bounded backoff), and then surface a terminal 'Couldn't complete securely — retry.' toast to the user — and a manual Retry will fail identically, because retrying re-invokes the same SDK method which re-reads the same stale folderTree entry. The user has no way to recover except a full page reload. This was independently flagged by 68-08's own SUMMARY as an 'open follow-up, discovered but out of scope.'"
    artifacts:
      - path: "packages/sdk/src/client.ts"
        issue: "performScopeExitRotation does not update this.folderTree after rotateReadFromNode succeeds; reconcileFolderSequence does not refresh folderTree on a detected mismatch either, so a retry after a ReconcileStaleError cannot self-heal without a page reload"
    missing:
      - "After a successful performScopeExitRotation, refresh (or evict) the folderTree entry for rootNodeIpnsName with the newly-rotated readKey/generation/sequenceNumber, OR have reconcileFolderSequence's mismatch handler refresh folderTree from the resolved network state before throwing, so a same-session retry can succeed without requiring a full page reload."
deferred:
  - truth: "CannotWriteUntilRefetchError (WRITE-03/D-01 co-writer stale-write toast) is thrown by a live write path when a co-writer targets a rotated-out (tombstoned) IPNS name"
    addressed_in: "Cross-phase finding — not addressed by any later phase in the current ROADMAP; pre-existing gap inherited from Phase 65/66, not introduced by Phase 68"
    evidence: "WRITE-03/WRITE-04 are marked Complete under Phase 65/66 in REQUIREMENTS.md traceability, but source inspection shows packages/sdk/src/client.ts#buildSharedWriteContextFromState's concrete publishNodeFn implementation never returns {tombstoned: true} — createAndPublishIpnsRecord's return type ({success, sequenceNumber}) carries no tombstone signal, and a 410 GONE from the API's publish-gate (confirmed present server-side in apps/api/src/ipns/ipns.controller.ts) is never caught/translated in the SDK publish path. This means CannotWriteUntilRefetchError has zero live producers today, independently confirmed by source (not just the 68-09/68-10 SUMMARY claims). This is a Phase 65/66 wiring gap, not a Phase 68/ROT-07 gap — 68-09's classifier and toast copy are correctly implemented and will work the moment a producer exists."
---

# Phase 68: Web Integration — Rotation UX and Durable Client State Verification Report

**Phase Goal:** The web app uses `rotateReadFromNode` for all revocation-triggering mutations, persists a durable IndexedDB generation + seq high-water that survives page reload, and reconciles `folderTree` before any rotation publish.
**Verified:** 2026-07-01T18:32:01Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

Merged from ROADMAP.md Success Criteria (SC#1–SC#5) + all 10 plans' `must_haves.truths`.

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `executeLazyRotation` deleted from `apps/web`; delete/move/rename call `rotateReadFromNode` on scope exit (SC#2) | VERIFIED | `grep -rn executeLazyRotation` across repo: zero hits. `packages/sdk/src/client.ts:569` calls `sdkCore.rotateReadFromNode` inside `performScopeExitRotation`, invoked from `renameItem`/`deleteItem`/`deleteToBin`/`moveItem`. |
| 2 | `addShareKeys`/`reWrapForRecipients` per-mutation fan-out deleted (SC#2) | VERIFIED | `grep -rn reWrapForRecipients apps/web/src`: zero hits. `share.service.ts`'s `executeLazyRotation`/`addShareKeys`/`reWrapForRecipients` removed per 68-02 SUMMARY, confirmed by grep. |
| 3 | Durable client-side `{nodeId→highestGeneration}`/`{nodeId→highestSeq}` monotonic-max state machine, fail-closed on regression, cold-device versionFloor (ROT-07 core logic) | VERIFIED | `packages/sdk/src/state/rotation-high-water.ts` exists (161 lines); targeted run `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/rotation-high-water.test.ts` → **20/20 passed** (executed live during this verification, not taken from SUMMARY). |
| 4 | Web IndexedDB-backed `HighWaterStore` adapter satisfying the SDK seam + D-08 in-memory degradation | VERIFIED | `apps/web/src/services/rotation-state.service.ts` exists; `pnpm --filter @cipherbox/web exec tsc -b --force` → clean (0 errors), executed live during this verification. |
| 5 | `enforceResolved` mechanism wired into `resolveIpnsRecord` (capability exists, additive/optional param) | VERIFIED | `apps/web/src/services/ipns.service.ts` exports `resolveIpnsRecord(ipnsName, rotation?: ResolveRotationContext)`; calls SDK `enforceResolved` when `rotation` is supplied. |
| 6 | **A generation/seq regression from the relay causes a fail-closed error during real, live user navigation (SC#4 as an operative system property)** | **FAILED** | See `gaps` frontmatter — zero live call sites (of ~15 in `apps/web`, plus the SDK's own internal `ensureFolderLoaded` navigation path) ever supply a rotation context. The M1 defense is implemented but inert against any real user action today. |
| 7 | `folderTree` reconciled against current `sequenceNumber` before any publish; mismatch defers via `ReconcileStaleError`, never silently skips (SC#3) | VERIFIED | `packages/sdk/src/client.ts:515-526` (`reconcileFolderSequence`), called at the top of `renameItem`/`deleteItem`/`deleteToBin`/`moveItem` before any publish. Targeted run `vitest run src/__tests__/client-rotation.test.ts` → **18/18 passed** (executed live). |
| 8 | **`folderTree` reflects the rotated key/generation after `performScopeExitRotation`, so the same folder can be mutated again in the same session without a reload** | **FAILED (fails safe, but functionally broken)** | See `gaps` frontmatter — `folderTree.set()` is never called after a successful rotation; the next same-session mutation deterministically throws `ReconcileStaleError` and cannot self-heal via retry. |
| 9 | Owner-reconcile: SDK driver unit-tested (revoked→delete-only, surviving→update-only, rootNodeId filter); thin web transport wired eagerly on login + opportunistically on `folder:updated` (D-10/D-11) | VERIFIED | `packages/sdk/src/share/owner-reconcile.ts` + targeted run `vitest run src/__tests__/owner-reconcile.test.ts` → **4/4 passed** (executed live). `apps/web/src/hooks/useAuth.ts` calls `triggerOwnerReconcileOnLogin()` and `runOwnerReconcileForFolder()` (confirmed by grep). |
| 10 | Owner-only `PATCH /shares/:shareId/grant` route persists rotated `readDescriptorRef`+`rootGeneration`; 403 non-owner, 404 unknown; regenerated api-client | VERIFIED | Route present at `apps/api/src/shares/shares.controller.ts:251`. Targeted run `pnpm --filter @cipherbox/api exec jest shares.controller.spec.ts -t updateGrant` → **3/3 passed** (executed live). `sharesControllerUpdateGrant` + `/shares/{shareId}/grant` confirmed present in generated api-client + openapi.json. |
| 11 | Rotation status badge (idle/root-cut/tail-walk/resuming) wired to a real driver via `persistJob` cadence; `role=status`/`aria-live=polite`, non-interactive (D-02/D-03) | VERIFIED (mechanism); behavioral proof deferred to CI per project doctrine | `RotationStatusBadge.tsx` mounted in `AppHeader.tsx` (grep-confirmed); `rotation-driver.service.ts` calls `useRotationStore.getState().beginRootCut/beginTailWalk/markResuming/reset` (grep-confirmed, 8 call sites). Runtime badge-lifecycle behavior is proven by `tests/web-e2e/tests/rotation-ux.spec.ts`, registered (see row 14) but not executed in this pass, per `docs/TESTING.md` doctrine (apps/web carries no unit tests; web-e2e needs the full local stack and runs in CI on main push). |
| 12 | Fail-closed error classifier (`ReconcileStaleError`, `Sequence/GenerationRegressionError`, `CannotWriteUntilRefetchError`) maps to the exact UI-SPEC toast + bounded-retry policy | VERIFIED (classifier itself); one of its 3 branches has no live producer today | `apps/web/src/hooks/useMutationFailureUx.ts` exists, wired into `useFolderMutations.ts`/`useFileOperations.ts`/`useFileBrowserActions.ts` (grep-confirmed). The `ReconcileStaleError` and `Sequence/GenerationRegressionError` branches ARE reachable (per truths 7-8's live wiring). The `CannotWriteUntilRefetchError` branch is correctly implemented but has zero live producer — see `deferred` (cross-phase, pre-existing, not this phase's fault). |
| 13 | Phase adds ZERO `apps/web` unit test files (SC#5) | VERIFIED | `find apps/web/src -name "*.spec.ts"` → empty (executed live during this verification). |
| 14 | Web-e2e specs authored, type-check clean, and registered — `rotation-durability.spec.ts` (SC#1/SC#4 durability), `rotation-ux.spec.ts` (D-01/D-02/D-03/D-06/WRITE-03) | VERIFIED | `npx playwright test --list` (run live in `tests/web-e2e`) → **7 tests registered across 2 files**, matching the SUMMARY's claim exactly. Per explicit project instructions, the suite is NOT executed here (needs full local stack; runs in CI on main push) — spec authorship + registration is the expected Phase-68 deliverable for this tier. |

**Score:** 12/14 truths verified (2 failed — see Gaps)

### Analysis of the Three Flagged Integration Gaps

**1. Rotation context not threaded into any live resolve call site — VERDICT: genuine gap (BLOCKER), not acceptable deferred scope for this phase.**

The phase goal text explicitly names the deliverable "durable IndexedDB generation + seq high-water (**M1 defense**, survives restart)" and ROADMAP SC#4 states unconditionally: "a generation or seq regression from the relay causes a fail-closed error, not silent acceptance." This is a security property, not a UI nicety. I independently verified (not from SUMMARY claims) that:
- All ~15 `apps/web` call sites of `resolveIpnsRecord()` pass only `ipnsName` — no `ResolveRotationContext`.
- Worse: the SDK client's own internal folder-navigation resolve (`packages/sdk/src/client.ts` `ensureFolderLoaded`, line 518) calls `sdkCore.resolveIpnsRecord` **directly**, bypassing even `apps/web`'s wrapper. Ordinary folder browsing in the shipped app therefore has zero exposure to the M1 gate through any path.

The unit-tier proof (68-01, 20/20 passing) and the web-e2e module-level proof (68-10, direct `import()` of the real module) correctly demonstrate the *mechanism* works in isolation. But the phase-goal and SC#4 wording describe a live system guarantee ("causes a fail-closed error"), and today that guarantee protects no real user action. A malicious or lagging relay serving a rolled-back IPNS record to a live folder-browse today is silently accepted. I judge this insufficient for ROT-07 to be marked "Complete" (REQUIREMENTS.md correctly still shows it "Pending") without either (a) a small follow-up wiring at least one live call site, or (b) an explicit human-accepted override documenting the M1 defense is deliberately being merged as "mechanism-complete, integration-pending."

**2. FolderTree not updated with the rotated key after `performScopeExitRotation` — VERDICT: genuine functional gap, fails safe (not a security hole), recommend follow-up but does not need to block merge on its own.**

Confirmed via source: `performScopeExitRotation` never calls `folderTree.set()` after `rotateReadFromNode` succeeds. The published record IS correctly rotated (security intact) but the in-memory cache goes stale. The existing `reconcileFolderSequence` guard (68-05) catches the resulting mismatch on the *next* mutation of the same folder and defers rather than silently corrupting — so there is no silent security failure. However, the defer is currently unrecoverable without a full page reload (retry re-reads the same stale `folderTree` entry), which is a real UX/functional break for same-session bulk operations on a folder that was just rotated. This is lower severity than gap 1 because it degrades gracefully (fail closed, user-visible error, no data loss) rather than silently failing open.

**3. `CannotWriteUntilRefetchError` implemented but no live call site throws it — VERDICT: not a Phase 68/ROT-07 gap. This is a pre-existing Phase 65/66 (WRITE-03/WRITE-04) wiring gap that Phase 68 did not introduce and is not on the hook to fix.**

Independently confirmed via source (not just the SUMMARY claim): `packages/sdk/src/client.ts#buildSharedWriteContextFromState`'s concrete `publishNodeFn` never returns `{tombstoned: true}` — `createAndPublishIpnsRecord`'s return type carries no tombstone signal, and the API's genuine 410 GONE tombstone response (confirmed present server-side) is never caught/translated in the SDK publish path. This means the *trigger* for `CannotWriteUntilRefetchError` was never wired end-to-end, but that wiring belongs to WRITE-03/WRITE-04 (Phase 65/66, already marked "Complete" in REQUIREMENTS.md's traceability — this finding calls that completeness into question, but it is out of Phase 68's scope to fix). Phase 68's own deliverable — the UX classifier and exact toast copy/actions for when this error IS thrown — is correctly implemented, type-checked, and will work immediately once a producer exists. I record this as a `deferred`/cross-phase finding, not a gap against ROT-07.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk/src/state/rotation-high-water.ts` | HighWaterStore seam, createRotationHighWater, enforceResolved | ✓ VERIFIED | Exists; 20/20 unit tests pass |
| `packages/sdk/src/__tests__/rotation-high-water.test.ts` | Vitest coverage | ✓ VERIFIED | 20 tests, executed live |
| `apps/web/src/services/rotation-state.service.ts` | IndexedDB HighWaterStore adapter | ✓ VERIFIED | Exists; typecheck clean |
| `apps/web/src/services/ipns.service.ts` | resolveIpnsRecord + ResolveRotationContext + enforceResolved wiring | ⚠️ ORPHANED (capability, no live caller) | Optional param never populated by any caller |
| `apps/api/src/shares/dto/update-grant.dto.ts` + controller/service route | PATCH grant route | ✓ VERIFIED | 3/3 controller-spec tests pass |
| `packages/api-client` generated `sharesControllerUpdateGrant`/`UpdateGrantDto` | typed client | ✓ VERIFIED | Present in generated code + openapi.json |
| `apps/web/src/stores/rotation.store.ts` + `RotationStatusBadge.tsx` | badge state machine + UI | ✓ VERIFIED | Wired into AppHeader; driver calls all 4 setters |
| `apps/web/src/lib/multi-tab-lock.ts` | navigator.locks leader election | ✓ VERIFIED | Exists, used by rotation-driver.service.ts |
| `apps/web/src/services/rotation-driver.service.ts` | concrete RotationClientCallbacks + resume | ✓ VERIFIED | Wired into useAuth.ts client construction |
| `packages/sdk/src/share/owner-reconcile.ts` | SDK owner-reconcile driver | ✓ VERIFIED | 4/4 unit tests pass |
| `apps/web/src/services/owner-reconcile.service.ts` | thin web transport | ✓ VERIFIED | Wired eagerly on login + opportunistically |
| `apps/web/src/hooks/useMutationFailureUx.ts` | fail-closed error classifier | ✓ VERIFIED (classifier); ⚠️ one branch (CannotWriteUntilRefetchError) has no live producer | Wired into 3 mutation hooks |
| `tests/web-e2e/tests/rotation-durability.spec.ts` / `rotation-ux.spec.ts` | Playwright specs | ✓ VERIFIED (registered) | 7 tests confirmed via `playwright test --list`; execution deferred to CI |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| Grant fetch (`share.service.ts`) | Generation-floor seed | `rootGeneration` field on `ReceivedShare`/`SentShare` | WIRED | Confirmed by 68-02 + type extension in `share.store.ts` |
| `client.ts` mutations | `rotateReadFromNode` | `performScopeExitRotation` → `maybeRotateOnScopeExit` | WIRED | Line 569, invoked from 4 mutation methods |
| `resolveIpnsRecord` (web) | SDK `enforceResolved` | optional `ResolveRotationContext` param | **NOT WIRED at any live call site** | See Gap 1 |
| `performScopeExitRotation` | in-memory `folderTree` | *(no update path)* | **NOT WIRED** | See Gap 2 |
| `owner-reconcile.ts` driver | `sharesControllerUpdateGrant`/`GetSentShares`/`RevokeShare` | injected transport | WIRED | Unit-tested with `vi.fn()` transport; web transport is concrete |
| `client.ts` `persistJob` calls | `rotation.store` badge | `rotation-driver.service.ts` cadence inference | WIRED | 8 call sites confirmed |
| SDK errors (`ReconcileStaleError`, `Sequence/GenerationRegressionError`, `CannotWriteUntilRefetchError`) | `notification.store` toasts | `useMutationFailureUx.ts` classifier | PARTIAL | First two branches reachable; third has no live producer (deferred, cross-phase) |

### Behavioral Spot-Checks (executed live during this verification pass)

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `executeLazyRotation` fully removed | `grep -rn executeLazyRotation` (whole repo) | 0 hits | ✓ PASS |
| `rotateReadFromNode` wired in client.ts | `grep -n rotateReadFromNode packages/sdk/src/client.ts` | 2 hits (doc comment + call site) | ✓ PASS |
| SDK rotation-high-water unit tests | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/rotation-high-water.test.ts` | 20/20 passed | ✓ PASS |
| SDK owner-reconcile unit tests | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/owner-reconcile.test.ts` | 4/4 passed | ✓ PASS |
| SDK client-rotation unit tests | `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/client-rotation.test.ts` | 18/18 passed | ✓ PASS |
| API updateGrant controller tests | `pnpm --filter @cipherbox/api exec jest shares.controller.spec.ts -t updateGrant` | 3/3 passed | ✓ PASS |
| apps/web typecheck | `pnpm --filter @cipherbox/web exec tsc -b --force` | 0 errors | ✓ PASS |
| No apps/web unit test files added | `find apps/web/src -name "*.spec.ts"` | empty | ✓ PASS |
| web-e2e rotation specs registered | `npx playwright test --list` (in `tests/web-e2e`) | 7 tests, 2 files | ✓ PASS |
| Live rotation-context callers | `grep -rn "resolveIpnsRecord(" apps/web/src` (manual inspection of all call sites) | 0 of ~15 pass a 2nd arg | ✗ FAIL (Gap 1) |
| folderTree updated post-rotation | inspection of `performScopeExitRotation`/`this.folderTree.set` in client.ts | no post-rotation `folderTree.set` call | ✗ FAIL (Gap 2) |
| `CannotWriteUntilRefetchError` live producer | inspection of `publishNodeFn`/`createAndPublishIpnsRecord` return shape | no `tombstoned: true` path exists | ✗ FAIL (deferred, cross-phase, not gating) |

Full test suites (`pnpm test`, `pnpm --filter @cipherbox/sdk test` unfiltered, web-e2e execution) were intentionally NOT run per the explicit scope instructions for this verification pass (integration tests need a live stack; web-e2e needs the full local stack and is a CI-on-main-push tier by project doctrine).

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| ROT-07 | 68-01..68-10 (all) | Durable client-side `{nodeId→highestGeneration}` high-water, survives restart, seeded from grant `rootGeneration`, fails closed on generation regression | ⚠️ PARTIALLY SATISFIED | Mechanism (SDK + IndexedDB adapter) fully built and tested; live-system reachability (Gap 1) and folderTree post-rotation consistency (Gap 2) are unresolved. REQUIREMENTS.md correctly still shows ROT-07 unchecked/"Pending" — consistent with this finding. |

No orphaned requirements: `grep "Phase 68" .planning/REQUIREMENTS.md` returns only the ROT-07 row.

### Anti-Patterns Found

Scanned all ~19 phase-modified files for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER` and empty-implementation patterns.

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `apps/web/src/components/file-browser/useFileBrowserActions.ts` | 110-113 | Comment (not TBD/FIXME/XXX) documenting the exact Gap 1 limitation | ℹ️ Info | Self-documented, not a debt-marker-gate violation (no TBD/FIXME/XXX literal); corroborates Gap 1 independently |

No `TBD`/`FIXME`/`XXX` markers found in any of the 19 phase-modified files — the debt-marker gate does not fire. No empty-implementation stubs (`return null`/`return {}`/`=> {}`) introduced by this phase's own code.

### Human Verification Required

None required to determine the gaps above — both were confirmed by direct source inspection and live test execution, not by inference. The following items remain genuinely un-executable without a live stack and are appropriately deferred to CI per project doctrine (not blocking this verification):

1. **Web-e2e rotation-durability.spec.ts / rotation-ux.spec.ts full execution**
   - Test: Run `pnpm test:web-e2e -- rotation` against the full local stack (API + web dev server + docker + Kubo + mock delegated-routing)
   - Expected: All 7 registered tests pass
   - Why human/CI: Requires infrastructure not available in this verification environment; runs automatically in CI on main push per `web-e2e.yml`

### Gaps Summary

Phase 68 delivers substantial, well-tested, correctly-wired plumbing for ROT-07: `executeLazyRotation` is gone, `rotateReadFromNode` drives every revocation-triggering mutation, the durable monotonic-max high-water state machine and its IndexedDB adapter are solid and unit-proven, the owner-reconcile driver and grant-update API round-trip cleanly, and the rotation UX (badge + toasts) is correctly implemented down to the classifier level.

However, two gaps prevent the phase's own stated goal ("M1 defense") and SC#4 ("a generation or seq regression from the relay causes a fail-closed error") from being true as *live system properties* today:

1. **(Blocker)** The fail-closed anti-rollback gate has zero reachability from any real user action — confirmed independently, not just via the executors' own flags. A relay-served generation/seq rollback is silently accepted by every live resolve path in the shipped app.
2. **(Should-fix, non-blocking on its own)** `folderTree` is never refreshed with the newly-rotated key after a scope-exit rotation, causing the next same-session mutation on that folder to permanently defer until a full page reload — fails safe, but is a real functional/UX defect.

A third flagged item (`CannotWriteUntilRefetchError` has no live producer) is a genuine, source-confirmed gap, but it belongs to WRITE-03/WRITE-04 (Phase 65/66, already marked "Complete"), not to Phase 68/ROT-07 — recorded as a `deferred` cross-phase finding rather than a Phase 68 gap.

**Recommendation:** Close Gap 1 and Gap 2 with a small, targeted follow-up plan before marking ROT-07 "Complete" in REQUIREMENTS.md — both are narrow, well-understood fixes (wire one real call site; add one `folderTree.set()` after rotation) rather than a redesign. If the team prefers to ship the mechanism now and land live-wiring separately, add an explicit `overrides:` entry to this VERIFICATION.md accepting that scope split, naming an owner and a tracking issue.

---

*Verified: 2026-07-01T18:32:01Z*
*Verifier: Claude (gsd-verifier)*
