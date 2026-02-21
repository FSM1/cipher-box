---
created: 2026-02-21T00:00
title: Investigate alternatives to delegated-ipfs.dev for IPNS resolution
area: api
files:
  - apps/api/src/ipfs/ipfs.module.ts
  - apps/api/src/ipfs/services/ipns.service.ts
  - apps/web/src/services/folder.service.ts
  - apps/web/public/recovery.html
---

## Summary

## Context

CipherBox relies on `delegated-ipfs.dev` for IPNS resolution (both server-side and in the recovery tool). This service is unreliable — known 502 errors have been observed, and there's a DB-cached CID fallback to work around it. If the rootFolderKey is moved to IPFS (see sibling todo), IPNS reliability becomes even more critical.

## What to investigate

- **Self-hosted IPFS node with DHT:** Run our own Kubo node for IPNS resolution instead of delegating to a third-party service
- **Alternative delegated routing providers:** Are there other public or paid delegated routing APIs beyond delegated-ipfs.dev?
- **Hybrid approach:** Self-hosted primary, delegated-ipfs.dev as fallback
- **IPNS over PubSub:** Faster resolution via pubsub instead of DHT, if both publisher and resolver are connected
- **Direct CID caching:** Continue the current DB-cached CID pattern but make it the primary path, with IPNS as background refresh only
- **DNSLink:** Use DNS TXT records as an alternative IPNS resolution mechanism for the root vault

## Success criteria

- Identify at least one alternative that provides sub-2s resolution latency and >99.5% availability
- Evaluate cost, maintenance burden, and infrastructure requirements
- Recommend whether to self-host, use an alternative provider, or improve the caching strategy
