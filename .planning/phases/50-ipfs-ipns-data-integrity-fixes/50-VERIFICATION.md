---
phase: 50-ipfs-ipns-data-integrity-fixes
verified: 2026-06-19T16:15:18Z
status: passed
score: 3/3 must-haves verified
overrides_applied: 0
---

# Phase 50: IPFS/IPNS Data-Integrity Fixes Verification Report

**Phase Goal:** No data loss and no permanently-undeletable CIDs — the Phase 42 unpin-integrity
findings are resolved (INT_MIN-hash CID stays deletable; a re-pinned CID is never drained) and
deleting a folder unenrolls every descendant IPNS record even when the subtree was never loaded.

**Verified:** 2026-06-19T16:15:18Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | INT_MIN-hash CID stays deletable — `guardedUnpin` advisory lock uses `hashtext($1)::bigint` with no `abs()` | VERIFIED | `apps/api/src/vault/vault.service.ts:267` — `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`; no `abs(` present anywhere in the file; comment at :264-266 explicitly documents the INT_MIN root cause and cites D-01/WR-01 |
| 2 | A re-pinned CID is never drained — drain re-checks refcount under the advisory lock before physical unpin | VERIFIED | `pending-unpin.processor.ts:86-111` — `drainRow()` wraps the entire recheck + unpin in a transaction; `pg_advisory_xact_lock` acquired at :89 before `pinnedCidRepository.count` at :95; if `refs > 0` the outbox row is deleted and the function returns without calling `unpinFile`; WR-03 regression test at `pending-unpin.processor.spec.ts:271` |
| 3 | Deleting a folder unenrolls every descendant IPNS record even when the subtree was never loaded — `collectSubtreeIpnsNamesAsync` does on-demand fetch+decrypt with cycle guard | VERIFIED | `packages/sdk/src/client.ts:282-348` — method exists, has `visited: Set<string>` parameter, checks `visited.has()` at :293 before recursing, calls `sdkCore.loadFolderMetadata` at :303 on a folderTree miss, never writes to `this.folderTree`; all four dispatch sites (`deleteItem` :961, `emptyBin` :1973, `emptyBin loop` :2002-2005, `purgeExpired` :2043-2046) chain `.catch()` (CR-02 fix); cycle regression test at `collect-subtree-ipns-names.test.ts:288` |

**Score:** 3/3 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `apps/api/src/vault/vault.service.ts` | guardedUnpin advisory-lock without `abs()` overflow; IN-01 metric guard; IN-06 rename; IN-03 removal; WR-07 disposition | VERIFIED | `hashtext($1)::bigint` at :267; `shouldAttemptPhysicalUnpin` throughout; `rowDeleted` flag gates `fileUnpins.inc()` at :330-334; `recordUnpin` removed (comment at :338); WR-07 accept-comment at :285-289 |
| `apps/api/src/vault/vault.service.spec.ts` | WR-01 INT_MIN-CID-deletability regression test | VERIFIED | `it('WR-01: advisory lock query must not use abs(int4) form...')` at :1030 |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` | Refcount-aware drain under advisory lock; WR-04 and IN-05 dispositions | VERIFIED | `drainRow()` takes advisory lock, checks `pinnedCidRepository.count`, skips `unpinFile` when `refs > 0`; WR-04 comment at :143-149; IN-05 comment at :125-129 |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` | WR-03 re-pin-during-drain regression test | VERIFIED | `describe('drain: skips unpin when CID is re-pinned (WR-03)')` at :272 |
| `packages/sdk/src/client.ts` | `collectSubtreeIpnsNamesAsync` with on-demand fetch+decrypt and cycle guard; all four dispatch sites with `.catch()` | VERIFIED | Method at :282 with `visited` Set; `.catch(err => console.warn(...))` at :963, :1975, :2005, :2046 |
| `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts` | D-03 unloaded-subtree + per-child-failure + cycle regression tests | VERIFIED | 4 test cases: Test A (full subtree), Test B (sibling failure isolation), Test C (folderTree not mutated), Test D (A→B→A cycle terminates) at :288 |
| `apps/api/src/ipfs/ipfs.controller.ts` | WR-02 physical unpin on no-row compensation path | VERIFIED | `this.ipfsProvider.unpinFile(result.cid).catch(() => undefined)` at :133, citing WR-02 at :122 |
| `apps/api/src/ipfs/dto/unpin.dto.ts` | IN-02 CID format + length validation | VERIFIED | `@MaxLength(255)` and `@Matches(CID_REGEX)` at :19-20; `CID_REGEX` covers CIDv0 and CIDv1 at :7 |
| `scripts/backfill-pinned-cids.ts` | WR-05 age cutoff + WR-06 real `isByoUser` | VERIFIED | `AND pc.pinned_at < NOW() - INTERVAL '1 hour'` at :151; `v.is_byo_user AS "isByoUser"` at :147 |
| `docs/CAPACITY.md` | WR-07 BYO-advisory retention consequence documented | VERIFIED | Section 7 "Retention Consequence of BYO Advisory Rows" at :323-362 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `vault.service.spec.ts` WR-01 test | `vault.service.ts` guardedUnpin | Captures `mockManager.query` SQL text, asserts `toMatch(/pg_advisory_xact_lock/)` and `not.toMatch(/abs\(hashtext/)` | WIRED | Test at :1030 |
| `pending-unpin.processor.ts` drain loop | `pinnedCids` table | `pinnedCidRepository.count({ where: { cid } })` before `unpinFile` inside advisory-locked transaction | WIRED | `:95` inside `drainRow` transaction |
| `client.ts collectSubtreeIpnsNamesAsync` | `sdkCore.loadFolderMetadata` | On-demand fetch+decrypt of persisted child folder metadata on `folderTree` miss | WIRED | `:303` |
| `deleteItem / emptyBin / purgeExpired` | `fireAndForgetUnenroll` | `.then(names => this.fireAndForgetUnenroll(names)).catch(err => console.warn(...))` | WIRED | Four dispatch sites at :962, :1974, :2004, :2045 |

### Data-Flow Trace (Level 4)

Not applicable — phase delivers backend service logic and SDK library methods, not UI components rendering dynamic data. All data flows verified via code inspection above.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `abs(hashtext` absent from advisory-lock SQL | `grep -Fn "abs(hashtext" vault.service.ts pending-unpin.processor.ts` | No output, exit 1 | PASS |
| `pg_advisory_xact_lock(hashtext($1)::bigint)` present in vault.service.ts | `grep -n "pg_advisory_xact_lock"` | Found at :267, :322 | PASS |
| `pg_advisory_xact_lock(hashtext($1)::bigint)` present in pending-unpin.processor.ts | `grep -n "advisory_xact_lock"` | Found at :89 | PASS |
| `visited` cycle guard present in `collectSubtreeIpnsNamesAsync` | `grep -n "visited.has\|visited.add"` in client.ts | Found at :293-294, :328, :341 | PASS |
| All four dispatch sites have `.catch()` | `grep -n "\.catch" client.ts` (unenroll context) | Found at :963, :1975, :2005, :2046 | PASS |
| WR-01 regression test exists in vault.service.spec.ts | `grep -n "WR-01"` | Found at :1030 | PASS |
| WR-03 regression test exists in pending-unpin.processor.spec.ts | `grep -n "WR-03"` | Found at :272 | PASS |
| Cycle regression test exists in collect-subtree-ipns-names.test.ts | `grep -n "A→B→A\|cycle"` | Found at :280-330 | PASS |

### Probe Execution

No probe scripts declared or conventional (`scripts/*/tests/probe-*.sh`). Step 7c: SKIPPED.

### Requirements Coverage

| Requirement | Source Plans | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| HARD-01 | 50-01, 50-02, 50-03, 50-04, 50-05 | IPFS/IPNS data-integrity: no data loss / no permanently-undeletable CIDs / unenroll nested IPNS records under unloaded subtrees | SATISFIED | Three goal claims verified in code; all Phase 42 review findings (D-01..D-07) dispositioned: fixed or accepted-with-comment; no finding silently dropped |

Note: REQUIREMENTS.md line 221 shows HARD-01 status as "Planned" — this is a documentation staleness issue (the requirement tracker was not updated to "In Progress" or "Complete") but does not affect code correctness. The implementation satisfies the requirement text.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| — | — | No TBD/FIXME/XXX markers in any phase-modified file | — | Clean |

Scanned: `vault.service.ts`, `pending-unpin.processor.ts`, `client.ts`, `ipfs.controller.ts`, `unpin.dto.ts`, `backfill-pinned-cids.ts`. Zero debt markers found.

Two review findings (REVIEW WR-02 `RegisterCidDto` validation inconsistency and REVIEW WR-05 unescaped CID in `LocalProvider` pin URL) were explicitly deferred as tracked todos in `.planning/todos/pending/` — not dropped. They are out of phase 50 file scope and do not affect the three goal claims.

### Open Caveat (Non-Blocking)

**Lock held across Kubo network call in drain path:** The `drainRow` implementation holds `pg_advisory_xact_lock` for the duration of the `ipfsProvider.unpinFile(cid)` call (line 89-110 in `pending-unpin.processor.ts`). The Postgres transaction (and therefore the advisory lock) remains open while the Kubo HTTP request is in flight. This is intentional (the processor comment at :80-83 documents the tradeoff: it prevents a racing `guardedUnpin` from inserting a new pin between recheck and unpin) and acceptable for this low-frequency, batched drain path. However, on a slow or hung Kubo endpoint, this holds the Postgres lock for an extended period. This is noted for operational awareness; it is not a correctness defect and does not block the phase goal.

### Human Verification Required

None. All three goal claims are verifiable via static code inspection. No UI behavior, real-time logic, or external service integration requires human testing.

### Gaps Summary

No gaps. All three concrete goal claims are verified in code:

1. `vault.service.ts:267` — `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)` with no `abs()` — INT_MIN CID is deletable.
2. `pending-unpin.processor.ts:85-111` — `drainRow()` takes the advisory lock, rechecks `pinnedCidRepository.count`, and skips `unpinFile` when `refs > 0` — a re-pinned CID is never drained.
3. `client.ts:282-348` — `collectSubtreeIpnsNamesAsync` calls `sdkCore.loadFolderMetadata` on folderTree miss, carries a `visited` Set cycle guard, never writes to `folderTree`, and all four dispatch sites have `.catch()` — every descendant IPNS name is collected even for unloaded subtrees.

---

_Verified: 2026-06-19T16:15:18Z_
_Verifier: Claude (gsd-verifier)_
