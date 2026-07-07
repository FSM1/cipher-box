---
created: 2026-06-30T00:00:00.000Z
title: Gate web UI paths that call Phase-68-deferred share stubs so they cannot throw at runtime
area: web
severity: medium
files:
  - apps/web/src/services/share.service.ts
  - apps/web/src/components/ShareDialog.tsx
---

> Deferred from the Phase 66 ship (CodeRabbit major finding, web share.service.ts:215).
> Out of the API-cutover domain (web) and tied to the intentional Phase 68
> deferral of the descriptor-ref rotation/grant path, so wiring it is its own piece
> of work, not a low-risk in-scope fix. Target: Phase 68.

## Problem

The Phase 66 cutover replaced several `apps/web/src/services/share.service.ts`
exports with `throw new Error('deferred to Phase 68 — descriptor-ref
rotation/grant path not yet wired')`: `createShare`, `fetchShareKeys`,
`updateShareKey`, `completeShareRotation`, and the permission/rotation helpers.

Some of these are still reachable from live UI paths: `ShareDialog` calls
`updateSharePermission(...)`, and `executeLazyRotation()` calls
`fetchPendingRotations()` / `updateShareKey()` / `completeShareRotation()`. As
written, exercising those flows is a guaranteed runtime crash, not just a
compile-time placeholder.

## Proposed fix (Phase 68, or a small interim guard now)

- Phase 68: wire the descriptor-ref rotation/grant path and remove the throws.
- Interim (if these UI paths are user-reachable before Phase 68): disable/hide
  the permission-change and lazy-rotation controls in `ShareDialog` and skip
  `executeLazyRotation()` so users cannot trigger the deferred throws, with a
  clear "coming soon"/disabled affordance. Do NOT convert the throws to silent
  no-ops — a no-op permission change would mislead the user into thinking access
  changed when it did not.

## Specific symptom — ShareDialog fake empty state (CodeRabbit OD3)

`ShareDialog.tsx` (~line 104-119) fetches sent shares in an async effect that now
`throw`s (deferred to Phase 68). The `.catch` only logs, but the `.finally` still
runs `setRecipientsFetched(true)` (and clears loading), so the dialog renders the
"no recipients yet" empty state on every open — hiding the fact that recipient
management is unavailable. Fix as part of the gating: on failure, set an explicit
unavailable/error state and do NOT mark `recipientsFetched = true`, so the UI shows
"unavailable" rather than a misleading empty list.

## Before doing this

Confirm whether the permission-downgrade and lazy-rotation entry points are
actually reachable in the current web build (routes/feature flags). If they are
already behind a disabled flag, this is purely a Phase 68 wiring task.
