---
created: 2026-06-29
title: SDK client move/publish ordering durability — CodeRabbit findings (Phase 64/68)
area: sdk
resolves_phase: 64
files:
  - packages/sdk/src/client.ts
---

## Problem

Phase-63 CodeRabbit review flagged two durability/ordering issues in the SDK client folder-move/traversal flow (introduced/touched when `moveItem` and the read-chain consumers were un-stubbed). Deferred because correct cross-folder transactional ordering interacts with the move re-seal + scope-exit rotation work owned by Phase 64, and with `folderTree` reconcile (Phase 68).

- **[MAJOR] Source removal committed before destination publish succeeds** (`client.ts` ~L556-600): the move/publish flow publishes the source-folder removal before the destination publish succeeds. If the destination publish fails, the item is lost from both folders. Reorder so the destination publish is confirmed before the source removal is committed (or make the pair atomic / recoverable). Ties into the [[move-within-scope-reseal-child-readkey]] re-seal work and the known `folderTree`/sequence-number reconcile discipline (web #489/#494).
- **[MAJOR] Descendant pushed to result before readability confirmed** (`client.ts` ~L1958-1981): the child/descendant traversal pushes entries to `result` before `sdkCore.loadFolderMetadata` confirms the descendant is actually readable, so an unreadable descendant can appear in enumeration. Move the `result.push` so it only happens after a successful load.

## Solution

Address alongside Phase 64's move/rotation hardening (and Phase 68 `folderTree` reconcile for the durable web path). Add tests covering: a failed destination publish must not lose the item from the source; an unreadable descendant must not appear in traversal results.

## References

- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-SECURITY.md` (move re-seal context, FLAG-63-U2)
- [[move-within-scope-reseal-child-readkey]]
- ROADMAP Phase 64; Phase 68 (web rotation UX + folderTree reconcile)
