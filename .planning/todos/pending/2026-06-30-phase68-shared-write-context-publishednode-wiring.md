---
created: 2026-06-30
title: Wire real writeKey + publishedNode into the client/web shared-write context (Phase 68)
area: web
severity: medium
source: CodeRabbit review of phase 65 PR (findings on client.ts:1728-1757 and shared-folder-projection.ts:42-55)
resolves_phase: 68
files:
  - packages/sdk/src/client.ts
  - apps/web/src/hooks/shared-folder-projection.ts
---

## Problem

Phase 65 reshaped `SharedWriteContext` onto the write-body model (needs `readKey`, `writeKey`,
`publishedNode`, and the publish/IPFS seams). The SDK helpers are fully implemented and unit/e2e
tested, but the **client/web wiring** that feeds real values into that context is deferred to
Phase 68 (Web Integration). Two CodeRabbit findings flag the current bridge state:

1. **`apps/web/src/hooks/shared-folder-projection.ts:42-55`** — `seedSharedFolder` seeds a
   `PLACEHOLDER_PUBLISHED_NODE` + zero `writeKey` when the caller doesn't supply them. These
   placeholders cannot support real write-body unsealing; a live shared write would fail. The
   placeholder is clearly marked, and the web shared-write path is not live pre-Phase-68, so this
   is a known bridge, not a regression — but Phase 68 must replace it with the real resolved node
   + the co-writer's real `writeKey` (from the claim/grant).

2. **`packages/sdk/src/client.ts:1728-1757`** — `buildSharedWriteContextFromState` reads
   `state.publishedNode`, but `adoptSharedFolderResult` does not write the freshly-published
   envelope back into `SharedFolderState.publishedNode` after a shared write. Consecutive real
   writes would therefore reuse a stale `publishedNode`. Dormant until Phase 68 supplies real
   `publishedNode` values, but must be fixed when the path goes live.

## Solution (Phase 68)

- In the web seed path, supply the real resolved `PublishedNode` and the co-writer's real
  `writeKey` (derived from the claimed grant) instead of placeholders.
- In `client.ts`, persist the published envelope back into `SharedFolderState.publishedNode`
  inside `adoptSharedFolderResult` (alongside `children` + `sequenceNumber`) so consecutive
  shared writes see the current node.
- SDK-side enablers (CodeRabbit PR #583 threads #15, #17): have the shared-write ops /
  `resealAndPublishParent` **return the updated parent `PublishedNode` envelope**, and have
  `bin` delete/restore **propagate the published folder snapshot back to the caller**, so the
  client has the fresh envelope to persist (above) instead of re-resolving.
