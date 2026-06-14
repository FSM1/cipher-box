---
created: 2026-06-14T01:32:39.825Z
title: Folder writes leak baseChildren and publishedChildren bookkeeping to call sites
area: sdk
severity: low
files:
  - packages/sdk/src/client.ts
  - packages/sdk/src/bin/index.ts
  - packages/sdk/src/share/shared-write.ts
---

## Problem

`updateFolderMetadataAndPublish` (phase 44) requires every caller to (1) snapshot
`const baseChildren = [...folder.children]` BEFORE mutating, pass it in, and
(2) adopt `folder.children = publishedChildren` from the result. This ceremony is
repeated at ~14 call sites (client.ts, bin/index.ts, share/shared-write.ts, and web
hooks). A caller that forgets the base snapshot silently hits the union-fallback
`console.warn` path where deletes can resurrect — e.g. useFileVersions.ts calls
without baseChildren. The shared-write functions also still return a now-redundant
`updatedChildren` (the stale pre-merge set) alongside `publishedChildren`, a foot-gun
that invites callers to consume the wrong one.

Surfaced by `/simplify` (2026-06-14, altitude finding); deferred as architectural,
out of scope for a quality-only pass.

## Solution

TBD — key considerations:

- Give folder writes a stateful wrapper that owns the base/result bookkeeping — e.g.
  `updateFolderChildren({ folder, nextChildren, ctx })` that internally captures
  `folder.children` as the base, publishes, and writes back `publishedChildren` +
  `sequenceNumber`. Callers stop threading baseChildren/publishedChildren by hand.
- Make the union-fallback path unreachable by construction (base always supplied).
- Drop `updatedChildren` from the shared-write return shapes; callers consume only
  the merged/published set.
