---
phase: 50-ipfs-ipns-data-integrity-fixes
plan: "02"
subsystem: api/ipfs/pending-unpin
tags: [data-integrity, unpin, refcount, tdd, WR-03, D-02]
dependency_graph:
  requires: []
  provides: [refcount-aware-drain]
  affects: [pending-unpin.processor.ts]
tech_stack:
  added: []
  patterns: [TypeORM repository count guard, TDD RED/GREEN]
key_files:
  created: []
  modified:
    - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts
    - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts
decisions:
  - "D-02 / WR-03: Re-check pinnedCidRepository.count before calling unpinFile; skip unpin when refs > 0 to prevent data loss via Kubo GC"
  - "Stale outbox row is always deleted (even when unpin is skipped) to prevent infinite retry of dead entries"
metrics:
  duration: "~8 minutes"
  completed: "2026-06-19"
  tasks_completed: 2
  tasks_total: 2
---

# Phase 50 Plan 02: Refcount-Aware Pending-Unpin Drain Summary

Make `drainPendingUnpins` call `pinnedCidRepository.count` before `unpinFile` so a re-pinned CID is never physically unpinned by the drain (D-02 / WR-03, HARD-01).

## What Was Built

The `drainPendingUnpins` loop in `pending-unpin.processor.ts` previously called `ipfsProvider.unpinFile(row.cid)` unconditionally. If a CID was re-uploaded or re-pinned while sitting in the `pending_unpins` outbox (drain window is at least 5 minutes, unbounded while Kubo is down), the drain would remove a live pin — triggering Kubo GC and data loss.

The fix adds a single refcount re-check at the top of the per-row `try` block:

```typescript
const refs = await this.pinnedCidRepository.count({ where: { cid: row.cid } });
if (refs > 0) {
  await this.pendingUnpinRepository.delete({ cid: row.cid });
  // log + continue (no physical unpin)
}
```

When `refs > 0` the drain deletes the stale outbox row (preventing infinite retry) and skips `unpinFile`. When `refs === 0` the existing unpin + delete path runs unchanged.

## TDD RED/GREEN/REFACTOR

### RED (Task 1)

Added `count: jest.fn()` to `mockPinnedCidRepository` (defaulted to resolve `0` in `beforeEach` so existing drain tests remain green). Added `describe('drain: skips unpin when CID is re-pinned (WR-03)')` with one `it` asserting `unpinFile` is NOT called when `mockPinnedCidRepository.count` returns `1`, but `delete` IS called.

The test failed against production code: `unpinFile` was called unconditionally (RED confirmed).

Commit: `582175059` — `test(50-02): add failing regression for WR-03 re-pin-during-drain`

### GREEN (Task 2)

Added the refcount guard in the processor drain loop (citing D-02 / WR-03 in a comment). Re-ran the full `pending-unpin.processor.spec` suite: 10/10 tests passed including WR-03.

Commit: `a85704903` — `fix(50-02): skip physical unpin in drain when CID is re-pinned`

### REFACTOR

No refactor step needed — implementation is minimal and clear.

## Commits

| Hash | Type | Description |
|------|------|-------------|
| `582175059` | test | add failing regression for WR-03 re-pin-during-drain (RED) |
| `a85704903` | fix | skip physical unpin in drain when CID is re-pinned (GREEN) |

## Verification

Full processor spec suite:

```
Tests: 10 passed, 10 total
```

Refcount guard present in processor:

```
59: const refs = await this.pinnedCidRepository.count({ where: { cid: row.cid } });
```

## Deviations from Plan

None — plan executed exactly as written. (Note: `pnpm install --frozen-lockfile` was run in the worktree to resolve missing `node_modules` for lint-staged pre-commit hook; this is standard worktree setup, not a plan deviation.)

## Known Stubs

None.

## Threat Flags

No new security-relevant surface introduced. The guard closes threat T-50-03 (DoS / data loss via unconditional unpin) and T-50-04 (tampering via stale outbox retry) as specified in the plan threat model.

## TDD Gate Compliance

- RED gate: `test(50-02)` commit `582175059` — PASS
- GREEN gate: `fix(50-02)` commit `a85704903` — PASS

## Self-Check: PASSED

- `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` — modified with refcount guard
- `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` — modified with WR-03 test
- Commit `582175059` — present (RED)
- Commit `a85704903` — present (GREEN)
