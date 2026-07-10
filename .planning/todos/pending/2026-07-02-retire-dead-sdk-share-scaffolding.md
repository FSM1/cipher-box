---
created: 2026-07-02
title: Retire dead share scaffolding — SDK ShareCallbacks API and web pre-phase-68 stubs
area: sdk/web
files:
  - packages/sdk/src/types.ts
  - packages/sdk/src/shared.ts
  - apps/web/src/services/share.service.ts
  - apps/web/src/hooks/useSharedNavigation.ts
  - apps/web/src/services/owner-reconcile.service.ts
resolves_phase: 77
---

## Problem

Found during Phase 68 ship (simplify pass) — dead or superseded code that is public API or pre-existing, so it was deferred rather than removed on the phase branch:

1. `packages/sdk/src/types.ts` `ShareCallbacks` type + `CipherBoxClientConfig.shareCallbacks?` — the SDK never consumed it, and Phase 68 removed the last producer (useAuth). Public SDK API, so retiring it is a breaking cutover (grep whole repo + full typecheck per the type-retirement gotcha).
2. `seedSharedFolder`'s `addShareKeysFn` config field ("retained for Phase 68") is now permanently superseded by descriptor refs; web passes a no-op at `useSharedNavigation.ts` (~line 560).
3. `apps/web/src/services/share.service.ts` pre-existing dead block: `checkPendingRotation`, `fetchPendingRotations`, `PendingRotation`, `hasActiveShares` — already dead on origin/main; the fetch stubs still throw stale `'deferred to Phase 68'` errors that are now misleading.
4. Perf nit: `owner-reconcile.service.ts` issues `GET /shares/sent` twice per reconcile (once in `decodeSentGrants`, again via `buildGrantRemintCallbacks.queryGrantsFn`); thread the already-fetched rows through instead.
5. Perf nit (greptile PR `#587` thread): `runOwnerReconcileForFolder` fires `GET /shares/sent` on EVERY `folder:updated` event before checking whether the folder is even a grant root. Short-circuit against the in-memory `useShareStore` sent-shares first (mirroring `getActiveGrantRootIpnsNames` in `rotation-driver.service.ts`) — but reason about store staleness (a grant created in another tab) before relying on it; the eager login sweep is the fallback either way.

## Solution

One small cleanup plan: delete the dead web block and stale stubs, retire `ShareCallbacks`/`shareCallbacks` and `addShareKeysFn` from the SDK public surface (major-ish SDK change — run full repo typecheck + sdk-e2e), and dedupe the sent-grants fetch in owner-reconcile.
