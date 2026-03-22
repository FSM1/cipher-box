---
created: 2026-03-22T17:34:27.311Z
title: Refactor api-client from singleton to instance-scoped axios
area: api-client
files:
  - packages/api-client/src/instance.ts
  - packages/api-client/orval.config.ts
  - packages/sdk-core/src/ipns/index.ts
  - packages/sdk-core/src/folder/index.ts
  - packages/sdk-core/src/file/index.ts
  - packages/sdk/src/client.ts
  - packages/sdk/src/types.ts
  - apps/web/src/lib/api-config.ts
  - tests/sdk-e2e/src/fixtures/test-harness.ts
  - tests/sdk-e2e/src/fixtures/multi-account.ts
  - tests/load/src/harness/client-pool.ts
---

## Problem

`@cipherbox/api-client` uses a module-level singleton (`setApiClientConfig` / `customInstance`) that all orval-generated API functions import. This means every consumer in the process shares one global axios config — there's no way for two `CipherBoxClient` instances to use different tokens simultaneously.

**Consequences:**

- Multi-account SDK E2E tests require a `switchTo()` hack that swaps the global singleton before each operation
- Load test client pools can't truly run in parallel — the singleton's `getAccessToken` always returns client[0]'s token for any code path through sdk-core
- Cross-suite test contamination: if a multi-account suite runs before a single-account suite, the singleton may still point to the wrong account's token (caused a real 401 bug during initial SDK E2E testing)
- The desktop app (which may need multiple vault sessions in future) would hit the same limitation

**Root cause:** Orval generates standalone functions (`ipnsControllerPublishRecord()`, etc.) that import `customInstance` directly. There's no class or DI — the config has to live somewhere global. This was a pragmatic choice during initial extraction from the web app (single-user browser context), not a deliberate architecture decision.

**Call chain showing the singleton dependency:**

```text
CipherBoxClient.createFolder()
  → sdk-core.updateFolderMetadataAndPublish()
    → sdk-core.createAndPublishIpnsRecord()
      → api-client.ipnsControllerPublishRecord()    ← generated, imports customInstance
        → customInstance()                           ← reads module-level _config
```

## Solution

### Phase 1: Orval config — generate instance-accepting functions

Configure orval to generate functions that accept an axios instance parameter instead of importing the singleton. Orval supports a `mutator` option that can inject a custom instance. The generated functions would accept `(config, options?)` where `options` can include a custom axios instance.

### Phase 2: Thread axios instance through SdkContext

Extend `SdkContext` (in `packages/sdk-core/src/index.ts`) to include an `axiosInstance` (or a factory function). All sdk-core functions already accept `ctx: SdkContext` — they'd pass `ctx.axiosInstance` through to the generated API functions.

### Phase 3: CipherBoxClient owns its axios instance

`CipherBoxClient` constructor creates its own axios instance (via `createAxiosInstance()` which already exists in `instance.ts`). It passes this into `SdkContext`, which flows through to all API calls. Each client is fully self-contained.

### Phase 4: Backward compatibility for web app

Keep `setApiClientConfig()` and the module-level singleton working for the web app (single-user browser context). The web app calls it once at module load time and never changes it — this pattern is fine. The singleton becomes the "default" instance; instance-scoped usage is opt-in via `SdkContext.axiosInstance`.

### Phase 5: Simplify test infrastructure

- Remove `switchTo()` from `multi-account.ts` — each test context's client uses its own instance
- Remove `setApiClientConfig` calls from test harness — each `CipherBoxClient` creates its own
- Load test client pool gets true parallel operation for free

**Packages touched:**

- `packages/api-client` — orval config, instance.ts (add instance parameter to customInstance)
- `packages/sdk-core` — SdkContext type, all functions that call generated API functions (~6 files)
- `packages/sdk` — CipherBoxClient constructor (create own axios instance)
- `apps/web` — api-config.ts (no change needed if backward-compatible)
- `tests/sdk-e2e` — test-harness.ts, multi-account.ts (simplify)
- `tests/load` — client-pool.ts (simplify)

## Additional cleanup enabled by this refactor

Once the singleton is eliminated, the following workarounds added in PR #318 can be removed:

- **`testFetch()` helper** (`tests/sdk-e2e/src/fixtures/test-harness.ts`) — raw fetch calls in test suites (vault-lifecycle, share-operations, invite-link) should be replaced with the generated API client functions. The generated client would use the instance-scoped axios automatically, removing the need for manual header injection. The raw fetch calls exist because the original tests were written before the bypass header was added; the generated client is the proper approach.
- **`fetchHeaders()` helper** — same file, only needed because raw fetch doesn't go through the axios instance. Goes away when raw fetch is replaced with generated client.
- **`setApiClientConfig` re-set in error-cases.test.ts** (line 106) — the event emission test re-sets the singleton because multi-account suites overwrite it. With instance-scoped axios, each client owns its config and this workaround is unnecessary.
- **`defaultHeaders` on `ApiClientConfig`** (`packages/api-client/src/instance.ts`) — added to inject the throttle bypass header into the singleton axios instance. Still useful for backward compatibility, but instance-scoped clients would receive it via constructor config instead.
- **`BypassableThrottlerGuard`** (`apps/api/src/common/guards/throttler-bypass.guard.ts`) — this stays regardless of the refactor; it's the proper server-side mechanism for throttle bypass.
