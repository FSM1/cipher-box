---
created: 2026-02-14T00:00
title: Add bring-your-own IPFS node support
area: api
files:
  - apps/api/src/ipfs/ipfs.module.ts
  - apps/api/src/ipfs/providers/ipfs-provider.interface.ts
  - apps/api/src/ipfs/providers/local.provider.ts
  - apps/api/src/ipfs/providers/pinata.provider.ts
  - apps/api/.env.example
  - apps/web/src/lib/api/ipfs.ts
---

## Problem

Currently CipherBox supports two IPFS providers: Pinata (production default) and a local Kubo node (dev/testing). Both are configured server-side via environment variables (`IPFS_PROVIDER`, `IPFS_LOCAL_API_URL`). There is no way for end users to bring their own IPFS node — the choice is made by the server operator, not the individual user.

For a zero-knowledge privacy tool, users may want to:
- Pin their encrypted data to their own IPFS node (self-sovereignty)
- Use a preferred pinning service other than Pinata (e.g., web3.storage, Filebase, nft.storage)
- Run a personal Kubo/IPFS node at home and have CipherBox pin directly to it
- Avoid relying on a third-party pinning service entirely

This requires a user-level IPFS configuration (not just server-level env vars) and potentially a hybrid model where the backend can relay uploads to a user-specified IPFS endpoint, or the client uploads directly to the user's node.

## Solution

TBD — key design questions to resolve:

1. **Client-direct vs server-relay:** Should the web app upload encrypted blobs directly to the user's IPFS node (bypassing backend), or should the backend proxy to the user's configured endpoint?
   - Client-direct: simpler, no server load, but CORS/connectivity issues
   - Server-relay: consistent quota tracking, but server sees user's IPFS credentials

2. **User settings model:** Add per-user IPFS config (endpoint URL, auth token, provider type) stored in user settings. UI for configuring custom node in settings page.

3. **Provider abstraction:** The existing `IpfsProviderInterface` (pin/unpin/fetch) is already well-abstracted. A new "user-custom" provider that reads config from user settings rather than env vars would slot in cleanly.

4. **IPNS implications:** If user pins to their own node, IPNS republishing and delegated routing need to work with the user's node or be handled differently.

5. **Quota tracking:** If uploads go directly to user's node, server-side quota tracking becomes optional or advisory.

6. **Fallback/reliability:** What happens if user's node is unreachable? Fallback to default provider, or fail?
