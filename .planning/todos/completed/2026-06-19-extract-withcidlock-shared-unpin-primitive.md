---
created: 2026-06-19T00:00:00.000Z
title: Extract withCidLock + refcountAndMaybeUnpin shared unpin primitive
area: tech-debt
severity: low
files:
  - apps/api/src/vault/vault.service.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts
---

> **Resolved by PR #541** (merged 2026-06-22). Verified already-fixed in the 2026-06-23 pending-todo audit (independent adversarial re-check confirmed). Archived from pending.

## Problem

The `pg_advisory_xact_lock(hashtext($1)::bigint)` lock SQL plus the
"refcount-recheck then maybe-unpin then delete-outbox-row" policy is now
hand-rolled in three sites:

- `guardedUnpin` main transaction
- `guardedUnpin` post-commit delete
- `drainRow` in the pending-unpin processor

Each site re-implements the same advisory-lock acquisition, the refcount
recheck against current state, the conditional unpin, and the outbox-row
cleanup. The logic is identical in intent but copy-pasted, so a change to the
policy has to be applied in three places by hand.

Drift risk is already demonstrated: the `INT_MIN` `abs()` fix for the
`hashtext($1)::bigint` advisory-lock key had to be hand-propagated across the
sites rather than living in one shared helper.

## Fix

Extract two shared primitives so all unpin paths share one implementation:

- `withCidLock(cid, fn)` — acquires the advisory xact lock for a CID (with the
  `INT_MIN`-safe key derivation) and runs `fn` inside it.
- `refcountAndMaybeUnpin(manager, cid)` — rechecks the refcount, performs the
  unpin when zero, and deletes the outbox row.

Route `guardedUnpin` (both the main txn and the post-commit delete) and
`drainRow` through these helpers.

## Source

Surfaced by Phase 50 /simplify (reuse + altitude).
