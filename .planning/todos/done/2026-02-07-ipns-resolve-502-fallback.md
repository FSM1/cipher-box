---
created: 2026-02-07T09:15
title: IPNS resolve 502 — add DB-cached CID fallback
area: api
files:
  - apps/api/src/ipns/ipns.service.ts
  - apps/api/src/ipns/entities/folder-ipns.entity.ts
---

## Problem

All GET /ipns/resolve calls return 502 Bad Gateway when the delegated routing service (delegated-ipfs.dev) is unreliable or down. This causes:

- "Sync failed" status indicator shown to user
- Files uploaded successfully but don't appear after page reload (IPNS metadata not resolvable)
- Complete sync failure despite data being intact

The folder_ipns table already stores the latest CID for each IPNS name, but the resolve endpoint only queries the external delegated routing service.

Pre-existing issue discovered during Phase 7.1 UAT.

## Solution

Add a fallback to DB-cached CID in the IPNS resolve flow:

1. Try delegated routing service first (current behavior)
2. On 502/timeout/failure, fall back to the CID stored in `folder_ipns.last_cid` column
3. Return the cached CID with a flag indicating it came from cache (may be stale)
4. Consider adding `last_cid` column to folder_ipns entity if not already present
