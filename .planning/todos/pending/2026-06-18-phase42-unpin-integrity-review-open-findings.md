---
created: 2026-06-18T00:00:00.000Z
title: Phase 42 unpin-integrity code-review findings (WR/IN) are unresolved in current code
area: bug
severity: high
source: .planning/phases/42-api-unpin-integrity/42-REVIEW.md (no resolution section); re-verified against live code 2026-06-18
files:
  - apps/api/src/vault/vault.service.ts
  - apps/api/src/ipfs/ipfs.controller.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts
  - apps/api/src/ipfs/dto/unpin.dto.ts
  - scripts/backfill-pinned-cids.ts
---

## Problem

`42-REVIEW.md` raised 7 warnings + 6 info findings on the guarded-unpin / pending-unpins
implementation and has **no resolution section**. Each was re-checked against current code on
2026-06-18 and confirmed still present. Two are correctness risks:

- **WR-01 (high)** — `vault.service.ts:262` `SELECT abs(hashtext($1))::bigint`. For the CID whose
  `hashtext == INT_MIN (-2147483648)`, `abs(int4)` raises `ERROR: integer out of range` —
  deterministically, every unpin of that CID 500s, and its quota row is permanently stuck. The
  file becomes **permanently undeletable via the API**. (`pg_advisory_xact_lock` accepts signed
  bigint, so the `abs()` is both unnecessary and the only failure mode.)
- **WR-03 (high)** — `pending-unpin.processor.ts:53` `drainPendingUnpins` unpins every outbox CID
  unconditionally. If a CID is re-pinned/re-recorded (re-upload of identical ciphertext, or a
  pin-migration flow) while still in `pending_unpins`, the next drain pass removes a **live pin**
  → content eligible for Kubo GC → **data loss**. The D-13 "sub-second window" rationale does not
  cover the outbox path (window ≥ 5 min, unbounded while Kubo is down).

Medium/low findings: WR-02 (upload-compensation `guardedUnpin` no-op leaks the Kubo pin and can
fire the cross-user security alert on internal failures), WR-05 (backfill TOCTOU deletes in-flight
upload rows as phantoms), WR-07 (BYO advisory rows block physical unpin of hosted content
indefinitely — non-owner-controllable retention path), WR-06 (backfill hardcodes
`false::boolean AS "isByoUser"`, defeating the defensive re-assert), IN-01 (`fileUnpins.inc()` on
no-ops), IN-02 (`UnpinDto.cid` missing CID regex/MaxLength), IN-03 (`recordUnpin` dead code),
IN-04 (`IPFS_PROVIDER` factory duplicated ×3), IN-05 (drift `dbCids` includes BYO), IN-06
(`outboxRowInserted` misnamed). WR-04 (Counter vs Gauge) was reviewed and judged acceptable.

## Fix

- **WR-01:** drop `abs()` (`SELECT hashtext($1)::bigint`) or cast first (`abs(hashtext($1)::bigint)`).
- **WR-03:** in the drain loop, `count` `pinned_cids` for the CID before `unpinFile`; if `> 0`, delete
  the stale outbox row and `continue`.
- **WR-02/05/06/07 + IN-\*:** apply the per-finding fixes in `42-REVIEW.md` (each has a concrete patch).

## Acceptance

WR-01 and WR-03 fixed with regression tests (INT_MIN CID undeletability; re-pin-during-pending
drain must not unpin). Remaining WR/IN items resolved or explicitly accepted with a comment.
