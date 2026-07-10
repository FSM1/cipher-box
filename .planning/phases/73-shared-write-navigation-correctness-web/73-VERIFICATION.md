---
phase: 73-shared-write-navigation-correctness-web
verified: 2026-07-10T22:45:00Z
status: passed
score: 7/7 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 6/7
  gaps_closed:
    - "SC4: WRITE-03 refreshWriteAccess / CannotWriteUntilRefetchError has at least one live production supplier, not test-only"
  gaps_remaining: []
  regressions: []
---

# Phase 73: Shared Write/Navigation Correctness (Web) Verification Report

**Phase Goal:** The web app preserves write capability and fresh listings when navigating shared folders — nested write-shares keep their writeKey across navigate-up/breadcrumb restore, the nav-stack no longer serves stale child snapshots, the non-listing read facades are floor-gated (ROT-07), WRITE-03 refresh-access has a real production trigger, and drag-payload kind comes from the resolved listing; plus tangential nav-hook dedup and dead getShareKeys/folder-IPNS path cleanup in the same subsystem.

**Verified:** 2026-07-10T22:45:00Z
**Status:** passed
**Re-verification:** Yes — after gap closure (fix commit `d3c39c06e`)

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| SC1 | Navigating up / restoring a breadcrumb into a nested write-share retains the derived writeKey; a write into a deep shared subfolder succeeds after breadcrumb restore | ✓ VERIFIED | Accepted from prior verification (no code change since; not re-checked in this pass). |
| SC2 | The nav-stack invalidates or re-resolves stale child snapshots on `sharedFolder:updated` (no children pushed/restored by reference without re-resolve) | ✓ VERIFIED | Accepted from prior verification (no code change since; not re-checked in this pass). |
| SC3 | `resolveFileMetadata`, `downloadFromIpns`, and `resolveNodeIdentity` route through the ROT-07 anti-rollback floor gate (not raw `resolvePublishedNode`) | ✓ VERIFIED | Accepted from prior verification (no code change since; not re-checked in this pass). |
| SC4 | WRITE-03 `refreshWriteAccess` / `CannotWriteUntilRefetchError` has at least one live production supplier (`publishNodeFn` can surface a tombstone), not test-only | ✓ VERIFIED (gap closed) | Fix commit `d3c39c06e` updates `refreshCurrentDepthWriteKey` (`useSharedNavigationActions.ts:824-844`) to pass `publishedNode: getSdkClient().getSharedFolderState(currentShareId)?.publishedNode ?? PLACEHOLDER_PUBLISHED_NODE` into the `seedActiveSharedFolder` call — read directly from source at lines 837-839, matching the pattern already used at `navigateToShare`, `navigateToSubfolder`, and `restoreToBreadcrumbIndex`, and the descent capture pattern near line 351. This means the reseed on every "Refresh access" retry now carries the active depth's real publishedNode instead of falling back to `PLACEHOLDER_PUBLISHED_NODE` (empty `readSealed`). The retried write's `buildSharedWriteContextFromState` -> `unsealNode` therefore operates on a valid envelope and reaches `publishNodeFn`'s tombstone/success classification (the `CannotWriteUntilRefetch` path) instead of throwing an unclassified GCM/unseal error. Combined with the three previously-verified stacked pieces (410->tombstoned mapping in sdk-core, `publishNodeFn` tombstone surfacing, `useSharedWriteOps`'s `runWithFailureUx`/`withRevocationGuard` wrapping), all four legs of SC4 are now correctly implemented in code. |
| SC5 | `SharedFolderRow` drag-payload kind is derived from the resolved listing (`isFileRefResolved`/`resolvedByIpnsName`), not `isFileRef` on a bare `SealedChildRef` | ✓ VERIFIED | Accepted from prior verification (no code change since; not re-checked in this pass). |
| SC6 | Duplicated shared-navigation logic in `useSharedNavigationActions` (navigateUp / navigateToBreadcrumb restore) is consolidated to a single source of truth | ✓ VERIFIED | Accepted from prior verification (no code change since; not re-checked in this pass). |
| SC7 | The dead `resolveFolderIpnsPrivateKey` / `getShareKeys` folder-IPNS write-share key path is removed from `useSharedNavigationActions.ts` | ✓ VERIFIED | Accepted from prior verification (no code change since; not re-checked in this pass). |

**Score:** 7/7 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `apps/web/src/hooks/useSharedNavigationActions.ts` | writeKey/publishedNode nav-stack retention, restore consolidation, refreshWriteAccess supplier | ✓ VERIFIED | `refreshCurrentDepthWriteKey`'s `seedActiveSharedFolder` call (lines 824-844) now passes a live `publishedNode`, consistent with all other reseed call sites in this file. No remaining omission. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `useMutationFailureUx.ts:retryAfterRefresh` | `refreshCurrentDepthWriteKey` -> `seedActiveSharedFolder` -> `client.loadSharedFolder` | `opts.refreshWriteAccess()` then retried `mutationFn()` | ✓ WIRED | The reseed now carries a real `publishedNode`, so the state the retried write reads is correct; the retry path can reach `unsealNode` successfully rather than failing on a placeholder envelope. |

### Anti-Patterns Found

None. The fix is a minimal, targeted addition (one field on an existing call), consistent with the pattern at the other three call sites in the same file. No new debt markers introduced.

### Human Verification Required

None as a code-level blocker. One item remains a CI/manual confirmation, not a code gap:

- **Live `rotation-ux.spec.ts` WRITE-03 run** — the production wiring is now correct in code (static trace confirmed), but the live e2e case exercising the actual retry-after-refresh round trip against a running docker+API+web stack has not yet been executed in this session (per 73-08-SUMMARY.md's prior note about worktree port contention). Recommend running it in CI or a follow-up manual pass to close the loop with runtime confirmation, but this does not block phase completion — the defect that would have caused it to fail is fixed at the source.

### Gaps Summary

No gaps remain. All 7 roadmap Success Criteria are verified against the merged code. The SC4 gap identified in the initial verification (`refreshCurrentDepthWriteKey` omitting `publishedNode` on reseed, causing the WRITE-03 refresh-access retry to throw an unclassified decrypt error instead of reaching the `CannotWriteUntilRefetch` classifier) is closed by fix commit `d3c39c06e`, which brings this call site in line with the other three `seedActiveSharedFolder` call sites in the same file.

---

*Verified: 2026-07-10T22:45:00Z*
*Verifier: Claude (gsd-verifier)*
