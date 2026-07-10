---
created: 2026-07-02
title: WRITE-03 Refresh-access UX path has no live production trigger
area: web/sdk
files:
  - apps/web/src/hooks/useMutationFailureUx.ts
  - packages/sdk/src/client.ts
---

## Problem

Carried from Phase 68 verification (deferred item) + ship simplify pass:

- `useMutationFailureUx`'s D-01/WRITE-03 branch (`refreshWriteAccess` / `retryAfterRefresh` / `dispatchWriteDescriptorStale`) has no production call site that passes a `refreshWriteAccess` supplier.
- `CannotWriteUntilRefetchError` itself has no live throw site: `packages/sdk/src/client.ts#buildSharedWriteContextFromState`'s `publishNodeFn` never returns `{tombstoned: true}` — a documented Phase-66 mock seam. The classifier is correct but unreachable; the rotation-ux e2e spec injects the toast directly instead of exercising the classifier.
- Pre-existing gap inherited from Phase 65/66, not introduced by Phase 68; no later ROADMAP phase currently addresses it.

## Solution

Wire the co-writer stale-write trigger end-to-end: make the shared-write publish path surface the API's tombstone signal as `{tombstoned: true}` from `publishNodeFn`, and pass a real `refreshWriteAccess` supplier from the shared-write hooks. Then upgrade the rotation-ux e2e case from direct toast injection to a genuine classifier-driven flow. Alternatively, if the co-writer flow lands differently, trim the unreachable branch.
