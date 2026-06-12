---
created: 2026-06-11
title: Server quota is never decremented — deletes leak quota until lockout
area: api
severity: high
files:
  - apps/api/src/vault/vault.service.ts
  - apps/api/src/ipfs/ipfs.controller.ts
  - apps/web/src/services/delete.service.ts
---

## Problem

`recordUnpin` (`vault.service.ts:225-230`) has zero callers. `POST /ipfs/unpin`
only talks to Kubo (`ipfs.controller.ts:144-148`) and never removes the
`pinned_cids` row, so `SUM(pinned_cids.size_bytes)` only ever grows. `checkQuota`
(`vault.service.ts:188-201`) therefore monotonically approaches the limit and
eventually locks the user out permanently, even after they delete content. The web
client decrements quota only in local state (`delete.service.ts:17-21`), masking
the bug in the UI.

Severity: correctness — users get bricked by normal delete usage.

## Solution

TBD — key considerations:

- Wire `recordUnpin` into the unpin/delete path so the `pinned_cids` row is removed
  (and the quota sum drops) when content is unpinned.
- Land together with the ownership check
  (`2026-06-11-ipfs-unpin-missing-ownership-check.md`) so unpin authorization, row
  deletion, and quota update are consistent.
- Decide ordering and reconciliation between the DB row delete and the Kubo unpin
  (define which happens first and what sweeps orphans if the second fails) — there
  is currently no orphan-reconciliation job for pins whose metadata reference was
  lost.
