---
created: 2026-07-04T00:00:00Z
title: Delete paths retain the removed child's WriteChildRef (write-chain growth)
area: sdk
files:
  - packages/sdk/src/client.ts
  - packages/sdk-core/src/folder/registration.ts
source: ship-phase 68.1 CodeRabbit finding 24 (deep write-plane verification); relates to plan 68.1-02
---

## Problem

Delete paths preserve the folder write-body verbatim by design (68.1-02), so a
DELETED child's `WriteChildRef` is RETAINED in the parent's write chain rather than
dropped. This is not data loss and not a mis-traversal risk (DFS only consults
write refs for children whose read-body is still present, so a stale ref is dead
weight), but the write chain accumulates orphaned entries indefinitely as items are
deleted — unbounded growth of the sealed write-body over a vault's lifetime.

Confirmed during ship-phase 68.1 as INTENTIONAL-for-now (write-link removal was
deferred to plan 68.1-02), not a shipping blocker.

## Solution

Land the 68.1-02 write-link removal: when an item is deleted (or moved out — see
[[restore-to-different-parent-write-rehoming]] for the sibling move/restore case),
drop its `WriteChildRef` from the parent's write chain in the same CAS publish that
removes its read-plane SealedChildRef, keyed by node UUID (childId). Verify the
sealed write-body shrinks after delete with a sdk-e2e assertion.
