---
created: 2026-06-19T00:00:00.000Z
title: LocalProvider interpolates CID into pin/rm and pin/add URLs without encoding
area: bug
severity: medium
source: .planning/phases/50-ipfs-ipns-data-integrity-fixes/50-REVIEW.md WR-05 (deferred — provider file outside phase 50 fix scope)
files:
  - apps/api/src/ipfs/providers/local.provider.ts
---

## Problem

`LocalProvider.unpinFile` (and the symmetric `pin/add` path) builds
`pin/rm?arg=${cid}` by raw string interpolation with no URL-encoding. CIDs
entering this path from the controller are regex-validated (`UnpinDto`), but
CIDs reaching it from the drain worker (`row.cid`) and from `guardedUnpin`
originate from `pinned_cids` / `pending_unpins` rows. Those rows are populated by
`recordPin`, whose CID for the BYO `register-cid` route is validated only by the
looser `RegisterCidDto` regex (see WR-02 todo) and for the upload route comes
from Kubo itself.

A CID containing `&` or another query-significant character would split the query
string. Today the regexes happen to exclude such characters, so this is latent
rather than exploitable — but the unpin path should not depend on every upstream
writer's validation being airtight. Phase 50 newly routes DB-sourced CIDs through
this path, which is why it surfaced now.

## Fix

`encodeURIComponent(cid)` in the `pin/rm` and `pin/add` URL construction, or use
`URLSearchParams` to build the query string. Pair with the WR-02 DTO tightening
for defense in depth.

## Why deferred

`local.provider.ts` is outside phase 50's confirmed fix scope. Captured here so
the provider hardening ships with its own review.
