---
phase: 50-ipfs-ipns-data-integrity-fixes
plan: "04"
subsystem: api-vault-unpin
tags: [unpin-integrity, metrics, d04-findings, byo-ipfs]
dependency_graph:
  requires: [50-01, 50-02]
  provides: [d04-disposition-coverage]
  affects: [vault.service, pending-unpin.processor, CAPACITY.md]
tech_stack:
  added: []
  patterns:
    - Row-deleted flag pattern for guarded metric increment
    - Accept-with-comment disposition for WR findings
key_files:
  modified:
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.service.spec.ts
    - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts
    - docs/CAPACITY.md
decisions:
  - "IN-03: recordUnpin deleted (not deprecated) — zero production callers, cleaner than annotation"
  - "WR-07: accepted with inline comment + CAPACITY.md section 7; filtering BYO rows would break D-07 refcount invariant"
  - "WR-04: accepted with inline comment — Counter semantics correct for cumulative orphan detection"
  - "IN-05: comment-only disposition consistent with WR-07 accept"
metrics:
  duration: 12min
  completed: 2026-06-19
  tasks: 2
  files: 4
---

# Phase 50 Plan 04: D-04 Unpin Finding Dispositions Summary

One-liner: Disposed all six D-04 unpin-integrity findings in vault.service.ts and pending-unpin.processor.ts via targeted fixes and explicit accept-with-comment annotations, plus a new CAPACITY.md section documenting the WR-07 BYO retention consequence.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | IN-01/IN-06/IN-03 in vault.service.ts | eda401053 | vault.service.ts, vault.service.spec.ts |
| 2 | WR-07/WR-04/IN-05 in processor and docs | ae1dff1f3 | pending-unpin.processor.ts, docs/CAPACITY.md |

## Finding Dispositions

### IN-06 (Fixed): Misleading outboxRowInserted name

Renamed `outboxRowInserted` → `shouldAttemptPhysicalUnpin` throughout `guardedUnpin`. Pure rename; no behavior change. The old name was misleading because the flag also gates the post-commit Kubo call, not just the outbox insert.

### IN-01 (Fixed): fileUnpins inflated on no-op paths

Added a `rowDeleted` boolean, set to `true` immediately after `pinnedCidRepo.delete()` inside the transaction. `metricsService.fileUnpins.inc()` now fires only when `rowDeleted` is true — i.e., only when a `pinned_cids` row was actually removed. Previously the increment fired unconditionally at the end of `guardedUnpin`, including on cross-user attempts and unknown-CID no-ops. Added `fileUnpins.inc` assertions to four existing tests (two no-op paths asserting NOT called, two owned-row paths asserting called once).

### IN-03 (Fixed — Deleted): Dead recordUnpin method

`recordUnpin` had zero production callers. It was deleted along with its two spec tests. A comment at the deletion site documents why it was removed (IN-03) and that `guardedUnpin` is the correct path for all production unpin calls.

### WR-07 (Accepted): BYO advisory rows block physical unpin

The refcount query at vault.service.ts:287 intentionally counts ALL `pinned_cids` rows regardless of origin (D-07 design). Filtering BYO rows would change this invariant. Accepted with:

1. Inline comment at the query site citing WR-07, the D-07 design intent, and pointing to CAPACITY.md §7.
2. New CAPACITY.md section 7 "Retention Consequence of BYO Advisory Rows" documenting the scenario: hosted CIDs are retained in Kubo while any BYO advisory row references them, with operator guidance.

### WR-04 (Accepted): Counter vs Gauge for driftOrphanedPinsTotal

`driftOrphanedPinsTotal.inc()` uses a Counter. This is intentional: a Counter gives cumulative orphan detection totals useful for alerting and trend analysis. A Gauge would require resetting between runs and tracking ephemeral per-run state. Accepted per 42-REVIEW author judgement, with inline comment at the increment site.

### IN-05 (Accepted — consistent with WR-07): dbCids set includes BYO rows

The `dbCids` set in `runDriftReport` intentionally includes all `pinned_cids` rows including BYO advisory rows, mirroring the guardedUnpin refcount semantics. This ensures the drift report does not falsely report orphans for CIDs that are intentionally retained by a BYO advisory row. Comment added at the `dbCids` construction site citing IN-05 and the WR-07 consistency reason.

## WR-07 Disposition: Accepted

WR-07 was **accepted** (not fixed). Rationale: Filtering BYO rows from the hosted refcount would break the D-07 design invariant that a BYO advisory row intentionally blocks physical unpin of hosted content. The fix would require changes to both `guardedUnpin` and `runDriftReport`, rippling into IN-05. The accept path is lower risk: add a comment at the query site and document the retention consequence in CAPACITY.md.

## IN-03 Disposition: Deleted

`recordUnpin` was **deleted** (not deprecated). Rationale: There were zero production callers. A `@deprecated` annotation would imply there are callers to migrate; there are none. Deletion is cleaner.

## IN-05 + WR-07 Consistency

Both dispositions are consistent: WR-07 accepted (BYO rows count in refcount) → IN-05 accepted (dbCids includes BYO rows). If WR-07 had been fixed by filtering BYO rows, IN-05 would have required filtering BYO rows from `pinnedCidRows` in `runDriftReport` to keep the two aligned.

## Deviations from Plan

None — plan executed exactly as written. WR-07 was accepted per the plan's default recommendation.

## Verification

```
grep -n "WR-04|WR-07|IN-01|IN-03|IN-05|IN-06|shouldAttemptPhysicalUnpin" \
  apps/api/src/vault/vault.service.ts \
  apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts
```

All six finding tags present. Both spec suites pass:

- vault.service.spec: 58 tests PASS (2 recordUnpin tests intentionally removed)
- pending-unpin.processor.spec: 10 tests PASS

```
grep -in "retention" docs/CAPACITY.md
```

Section 7 present with WR-07 retention consequence documentation.

## Self-Check: PASSED

- [x] vault.service.ts modified — confirmed `shouldAttemptPhysicalUnpin`, `rowDeleted`, no `outboxRowInserted`, no `recordUnpin` method
- [x] vault.service.spec.ts modified — `recordUnpin` tests removed, IN-01 assertions added
- [x] pending-unpin.processor.ts modified — WR-04 and IN-05 comments added
- [x] docs/CAPACITY.md modified — Section 7 added
- [x] Commit eda401053 exists (Task 1)
- [x] Commit ae1dff1f3 exists (Task 2)
- [x] Both spec suites green (68 tests total)
