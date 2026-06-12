---
created: 2026-06-11
title: IPFS unpin has no ownership check — any user can delete any CID
area: api
severity: high
files:
  - apps/api/src/ipfs/ipfs.controller.ts
  - apps/api/src/ipfs/providers/local.provider.ts
  - apps/api/src/vault/entities/pinned-cid.entity.ts
---

## Problem

`POST /ipfs/unpin` calls Kubo `pin/rm` directly with no check that the caller owns
the CID (`ipfs.controller.ts:144-148`). On the shared Kubo node this lets any
authenticated user unpin (and so make eligible for GC) another user's content. The
victim's `pinned_cids` row and quota charge persist, so the content is gone but
still billed.

The upload compensation path has the same flaw: on a failed `recordPin` it issues
`unpinFile(result.cid)` (`ipfs.controller.ts:122`) which calls the global
`pin/rm` (`local.provider.ts:87`) without checking whether another user also
references that CID — content-addressed dedup means CIDs can be shared across
users.

Severity: security / cross-tenant data destruction.

## Solution

TBD — key considerations:

- Before unpinning, verify the caller owns a `pinned_cids(userId, cid)` row
  (`pinned-cid.entity.ts`) for that CID.
- Reference-count across users: only issue the global Kubo `pin/rm` when no other
  user's `pinned_cids` row still references the CID; otherwise just delete the
  caller's row.
- Pairs with the quota-decrement todo
  (`2026-06-11-server-quota-never-decremented-on-unpin.md`) — ownership check,
  row delete, and quota update should land together.
- Zero-knowledge constraint preserved: ownership is tracked purely via
  `pinned_cids(userId, cid)`, which the server already holds; no plaintext needed.
