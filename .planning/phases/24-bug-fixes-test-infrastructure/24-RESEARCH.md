# Phase 24: Bug Fixes & Test Infrastructure - Research

**Researched:** 2026-03-25
**Domain:** Bug fixes (IPNS/metadata), test infrastructure (load tests, E2E, token refresh)
**Confidence:** HIGH

## Summary

Phase 24 addresses two known bugs and three test infrastructure improvements. Both bugs have clear root causes identified through code analysis: the bin IPNS 404 occurs because `loadBin()` returns empty state when IPNS resolution fails (no initial publish verification or auto-repair), and the device registry format error occurs because `ipHash: ''` is stored during registration (line 338 of `useAuth.ts`) but the validator requires exactly 64 hex characters on read.

The test infrastructure work is straightforward: headless load tests reuse the existing Vitest + MetricsCollector + ThresholdConfig harness but call `sdk-core` functions directly instead of going through `CipherBoxClient`; recovery E2E tests use Playwright with the existing `createTestAccount` pattern to seed a vault then navigate to `recovery.html`; and the 401 interceptor follows the exact pattern already implemented in `@cipherbox/api-client`'s `createAxiosInstance` (shared promise for concurrent 401s, retry failed request).

**Primary recommendation:** Fix bugs first (they are independent and quick), then layer test infrastructure improvements using existing patterns and harness code.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **Bug 1 (Bin IPNS 404):** Both robust initial publish AND auto-repair on load. Initial publish: retry + verify after first bin IPNS publish. Auto-repair: if `loadBin()` gets IPNS 404, re-derive bin keypair and publish empty bin record. Silent repair, no toast.
- **Bug 2 (Device registry format error):** Version bump to v2 following METADATA_EVOLUTION_PROTOCOL.md. Add `version` field, write v1->v2 migration with sensible defaults, lenient parsing on read (accept v1), strict v2 on write. Follow Section 4 checklist.
- **Headless load tests:** Bottleneck isolation at function level. Test IPNS publish/resolve contention, upload pipeline (encrypt + pin + publish), folder metadata read path. Reuse MetricsCollector + checkThresholds/expectThresholdsPassed. Same reporting format and CI integration.
- **Recovery tool cleanup:** Remove export file recovery mode entirely. Simplify to IPFS-direct v2 blob recovery only. Test data seeding via SDK E2E harness. Tests require API + IPFS running.
- **401 interceptor:** Reactive Axios interceptor catches 401, re-authenticates via `/auth/test-login`, retries failed request only. No proactive refresh, no folder state reload.

### Claude's Discretion

- Exact retry count and backoff strategy for bin IPNS initial publish
- How to structure headless load test scenarios (file organization within tests/load/src/)
- Recovery tool UI simplification details (layout changes after removing export mode)
- Axios interceptor implementation pattern (queue concurrent 401s to avoid multiple simultaneous refreshes)

### Deferred Ideas (OUT OF SCOPE)

- Error cases for recovery tool (invalid key, unreachable gateway)
- Export file recovery mode restoration
- Proactive token refresh in load tests

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID        | Description                                                                     | Research Support                                                                                                             |
| --------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| BUGFIX-01 | Bin IPNS name resolves correctly (no 404 errors on recycle bin operations)      | Root cause identified: no initial publish verification + no auto-repair. Fix location: `packages/sdk/src/bin/index.ts`       |
| BUGFIX-02 | Device registry parses without crypto format errors                             | Root cause identified: `ipHash: ''` stored at `useAuth.ts:338`. Fix: v2 migration + lenient validator per evolution protocol |
| TEST-01   | Headless Node.js load tests call sdk-core functions directly                    | Existing harness (MetricsCollector, ThresholdConfig, vitest) fully reusable. New workloads call sdk-core directly.           |
| TEST-02   | Vault v2 recovery tool has automated E2E test coverage                          | Playwright config and pattern established. Seed via createTestAccount, navigate to /recovery.html, verify file download.     |
| TEST-03   | Load tests handle 401 responses with automatic token refresh instead of failing | Exact pattern exists in `@cipherbox/api-client` instance.ts. Adapt for load test `/auth/test-login` re-auth.                 |

</phase_requirements>

## Standard Stack

### Core

| Library             | Version      | Purpose                       | Why Standard                                        |
| ------------------- | ------------ | ----------------------------- | --------------------------------------------------- |
| vitest              | ^3.0.5       | Load test runner              | Already used by `@cipherbox/load-tests`             |
| @playwright/test    | ^1.48.0      | E2E test runner               | Already used by `@cipherbox/web-e2e`                |
| axios               | (workspace)  | HTTP client with interceptors | Already used via `@cipherbox/api-client`            |
| @cipherbox/sdk-core | workspace:\* | Stateless SDK functions       | Direct function calls for headless load tests       |
| @cipherbox/sdk      | workspace:\* | Stateful client               | Existing load test client pool uses CipherBoxClient |
| @cipherbox/core     | workspace:\* | Domain types + validation     | Registry schema, bin crypto, metadata validation    |
| @cipherbox/crypto   | workspace:\* | Crypto primitives             | ECIES, HKDF, Ed25519 for test setup                 |

### Supporting

| Library               | Version      | Purpose           | When to Use                           |
| --------------------- | ------------ | ----------------- | ------------------------------------- |
| @cipherbox/api-client | workspace:\* | Typed HTTP client | Reference for 401 interceptor pattern |

No new dependencies needed. All work uses existing workspace packages.

## Architecture Patterns

### Recommended Project Structure

```
packages/sdk/src/bin/index.ts           # BUGFIX-01: Add retry/verify + auto-repair to loadBin
packages/core/src/registry/schema.ts    # BUGFIX-02: Lenient v1/v2 validator
packages/core/src/registry/types.ts     # BUGFIX-02: v2 type definition
apps/web/src/hooks/useAuth.ts           # BUGFIX-02: Fix ipHash: '' to proper value
tests/load/src/scenarios/               # TEST-01: New headless sdk-core scenarios
tests/load/src/workloads/               # TEST-01: New sdk-core workloads (no CipherBoxClient)
tests/web-e2e/tests/recovery.spec.ts    # TEST-02: Recovery tool E2E
apps/web/public/recovery.html           # TEST-02: Simplified (export mode removed)
tests/load/src/harness/client-pool.ts   # TEST-03: Add 401 interceptor
```

### Pattern 1: IPNS Publish with Retry + Verify

**What:** After publishing an IPNS record, resolve it back to verify it propagated, with retry on failure.
**When to use:** First-time IPNS publishes where the record may not yet be cached in DB or delegated routing.
**Example:**

```typescript
// In packages/sdk/src/bin/index.ts, after saveBinMetadata:
async function publishWithVerify(params: {
  ipnsName: string;
  ipnsPrivateKey: Uint8Array;
  cid: string;
  sequenceNumber: bigint;
  ctx: SdkContext;
  maxRetries?: number;
}): Promise<void> {
  const maxRetries = params.maxRetries ?? 3;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    await sdkCore.createAndPublishIpnsRecord({...});
    // Verify: resolve back to check DB cache was written
    const resolved = await sdkCore.resolveIpnsRecord(params.ipnsName, params.ctx);
    if (resolved) return; // Success
    // Exponential backoff: 500ms, 1s, 2s
    if (attempt < maxRetries - 1) {
      await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt)));
    }
  }
}
```

### Pattern 2: Lenient Read / Strict Write (Metadata Evolution)

**What:** Accept both v1 and v2 on read with transparent migration; always write v2.
**When to use:** Any metadata schema version bump per METADATA_EVOLUTION_PROTOCOL.md.
**Example:**

```typescript
// In packages/core/src/registry/schema.ts
export function validateDeviceRegistry(data: unknown): DeviceRegistry {
  const obj = data as Record<string, unknown>;
  const version = obj.version;
  if (version === 'v1') {
    return migrateV1ToV2(obj); // Fill defaults, return v2
  }
  if (version === 'v2') {
    return validateV2(obj); // Strict v2 validation
  }
  throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
}
```

### Pattern 3: Headless SDK-Core Load Test (No CipherBoxClient)

**What:** Call sdk-core functions directly with explicit parameters instead of through CipherBoxClient.
**When to use:** When testing specific IPFS/IPNS operations in isolation for bottleneck identification.
**Example:**

```typescript
// tests/load/src/workloads/sdk-ipns-workload.ts
import * as sdkCore from '@cipherbox/sdk-core';

export async function runIpnsPublishWorkload(
  pc: PoolClient,
  opts: { cycles: number }
): Promise<void> {
  const ctx: SdkContext = {
    apiUrl: API_URL,
    getAccessToken: async () => pc.accessToken,
    axiosInstance: pc.client['ctx'].axiosInstance, // Access internal ctx
  };
  for (let i = 0; i < opts.cycles; i++) {
    await pc.metrics.measure('ipnsPublish', () =>
      sdkCore.createAndPublishIpnsRecord({
        ipnsPrivateKey: pc.rootIpnsKeypair.privateKey,
        ipnsName: pc.rootIpnsName,
        metadataCid: someCid,
        sequenceNumber: BigInt(i + 1),
        ctx,
      })
    );
  }
}
```

### Pattern 4: Reactive 401 Interceptor for Load Tests

**What:** Axios response interceptor catches 401, re-authenticates via test-login, retries failed request.
**When to use:** Load test client pool to handle JWT expiry during long-running suites.
**Example:**

```typescript
// Adapt from @cipherbox/api-client instance.ts pattern
// Key: shared promise for concurrent 401s (avoid N simultaneous re-auths)
let refreshPromise: Promise<string> | null = null;

instance.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      if (!refreshPromise) {
        refreshPromise = reAuthenticate(email, secret).finally(() => {
          refreshPromise = null;
        });
      }
      const newToken = await refreshPromise;
      originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
      return instance.request(originalRequest);
    }
    throw error;
  }
);
```

### Anti-Patterns to Avoid

- **Hand-rolling IPNS verify logic in multiple places:** The retry+verify pattern for bin IPNS should be localized to the bin module. Don't duplicate it across other IPNS publishers.
- **Modifying the v1 validator directly:** The v1 path must remain as-is for backward compatibility. Add a v2 code path, not modify v1 checks.
- **Proactive token refresh:** The context decision locks this as reactive-only. Do not add timer-based token refresh.
- **Using CipherBoxClient in headless load tests:** The whole point is bypassing it. Headless tests must call sdk-core directly.
- **Seeding recovery test data via IPFS directly:** Use SDK E2E harness (createTestAccount + client.uploadFile) to create real vault data. This ensures the recovery tool exercises the real data format.

## Don't Hand-Roll

| Problem                 | Don't Build           | Use Instead                                 | Why                                          |
| ----------------------- | --------------------- | ------------------------------------------- | -------------------------------------------- |
| 401 retry logic         | Custom retry wrapper  | Axios interceptor pattern from api-client   | Already battle-tested, handles concurrency   |
| Metrics collection      | Custom timing code    | MetricsCollector.measure()                  | Already exists in load test harness          |
| Threshold checking      | Manual assertion code | expectThresholdsPassed()                    | Already exists with console violation output |
| Test account creation   | Manual API calls      | createTestAccount() from test-harness.ts    | Already handles full 5-step provisioning     |
| IPNS keypair derivation | Manual HKDF           | deriveBinIpnsKeypair() from @cipherbox/core | Deterministic, tested                        |
| Registry encryption     | Manual ECIES calls    | encryptRegistry/decryptRegistry from core   | Handles JSON serialization + validation      |

**Key insight:** Every test infrastructure component already exists in reusable form. The headless load tests just need new workload functions that call sdk-core instead of CipherBoxClient methods.

## Common Pitfalls

### Pitfall 1: Registry v2 Migration Without Following Protocol

**What goes wrong:** Schema change causes cross-device data corruption (TypeScript writes v2, older code can't read it).
**Why it happens:** DeviceRegistry is TypeScript-only (no Rust implementation), so cross-platform isn't a concern, but older web clients may still have v1 cached.
**How to avoid:** Follow METADATA_EVOLUTION_PROTOCOL.md Section 4 checklist exactly. Lenient read (accept v1+v2), strict write (always v2). Update docs/METADATA_SCHEMAS.md version history.
**Warning signs:** `CryptoError: Invalid registry format` in browser console after deploy.

### Pitfall 2: Bin Auto-Repair Creates Race with Concurrent loadBin Calls

**What goes wrong:** Two tabs or the periodic sync both call `loadBin()` simultaneously, both detect 404, both publish empty bin records with conflicting sequence numbers.
**Why it happens:** IPNS publish is not atomic. Two concurrent empty-bin publishes clobber each other.
**How to avoid:** The bin is only loaded once on login (fire-and-forget from useAuth). The SDK `loadBin()` is called once per session. Auto-repair should set a "repair in progress" flag and skip if already repairing.
**Warning signs:** Bin entries disappearing after repair.

### Pitfall 3: Headless Tests Still Need SdkContext with Valid Auth

**What goes wrong:** Calling sdk-core functions without a properly configured SdkContext (apiUrl + getAccessToken + axiosInstance) causes auth failures.
**Why it happens:** sdk-core functions are "stateless" but still need an authenticated HTTP client to talk to the CipherBox API.
**How to avoid:** Construct SdkContext from the PoolClient's existing auth state. The CipherBoxClient internally creates an axiosInstance -- either expose it or create a parallel one for headless tests.
**Warning signs:** 401 errors in headless tests that aren't related to token expiry.

### Pitfall 4: Recovery Tool E2E Tests Depend on External IPFS Resolution

**What goes wrong:** Tests pass locally but fail in CI because IPNS resolution via gateway is slow or flaky.
**Why it happens:** recovery.html resolves IPNS via gateway HEAD requests, which depend on DHT propagation.
**How to avoid:** The test seeds data via SDK (which publishes to local Kubo via API), so IPNS resolution should hit the DB cache via the CipherBox API. But recovery.html uses gateway resolution, not API resolution. Need to either: (a) point recovery.html's gateway to localhost Kubo, or (b) wait for IPNS propagation after seeding.
**Warning signs:** Flaky E2E test failures with "IPNS resolution failed" in recovery.html.

### Pitfall 5: ipHash Fix Must Not Break Existing Registries

**What goes wrong:** Fixing `ipHash: ''` for new writes is necessary, but existing registries on IPFS already have `ipHash: ''` entries.
**Why it happens:** v1 registries were written with empty ipHash.
**How to avoid:** The v1->v2 migration must accept `ipHash: ''` in v1 data and either fill a placeholder (e.g., hash of "0.0.0.0") or make ipHash optional in v2. The strict v2 validator can then enforce 64-hex-or-empty.
**Warning signs:** v1 registries failing validation even after "lenient" parsing.

## Code Examples

### BUGFIX-01: Bin loadBin Auto-Repair

```typescript
// In packages/sdk/src/bin/index.ts, modify loadBin()
export async function loadBin(params: { binCtx: BinOperationContext }): Promise<BinState> {
  const loaded = await loadBinMetadataInternal({
    userPrivateKey: params.binCtx.userPrivateKey,
    ctx: params.binCtx.ctx,
  });

  if (!loaded) {
    // No bin IPNS record exists — auto-repair by publishing empty bin
    const binIpns = await deriveBinIpnsKeypair(params.binCtx.userPrivateKey);
    const emptyMetadata: RecycleBinMetadata = {
      version: BIN_METADATA_VERSION,
      sequenceNumber: 1,
      entries: [],
    };
    // Publish empty bin to establish the IPNS record
    await saveBinMetadata({ metadata: emptyMetadata, binCtx: params.binCtx });
    return { entries: [], sequenceNumber: 1, ipnsName: binIpns.ipnsName };
  }

  return {
    entries: loaded.metadata.entries,
    sequenceNumber: loaded.metadata.sequenceNumber,
    ipnsName: loaded.ipnsName,
  };
}
```

### BUGFIX-02: Registry V2 Migration Pattern

```typescript
// In packages/core/src/registry/schema.ts
export function validateDeviceRegistry(data: unknown): DeviceRegistry {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
  const obj = data as Record<string, unknown>;

  // Accept both v1 and v2
  if (obj.version === 'v1') {
    return migrateV1ToV2(obj);
  }
  if (obj.version === 'v2') {
    return validateV2Registry(obj);
  }
  throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
}

function migrateV1ToV2(obj: Record<string, unknown>): DeviceRegistry {
  // Validate basic structure
  if (!Array.isArray(obj.devices)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
  // Migrate devices: fill sensible defaults for v1 fields that may be missing/invalid
  const devices = (obj.devices as Record<string, unknown>[]).map((d) => ({
    ...d,
    // Accept empty ipHash from v1 (known bug)
    ipHash:
      typeof d.ipHash === 'string' && d.ipHash.length === 64 && HEX_REGEX.test(d.ipHash)
        ? d.ipHash
        : '0'.repeat(64), // Placeholder for invalid/empty v1 values
  }));
  return {
    version: 'v2',
    sequenceNumber: obj.sequenceNumber as number,
    devices: devices as DeviceEntry[],
  };
}
```

### TEST-01: Headless SDK-Core Upload Pipeline Test

```typescript
// tests/load/src/scenarios/sdk-upload-pipeline.test.ts
import { describe, it, afterAll } from 'vitest';
import * as sdkCore from '@cipherbox/sdk-core';
import { createClientPool, destroyClientPool, aggregateAndReport } from '../harness/client-pool';
import { expectThresholdsPassed } from '../harness/thresholds';

describe('SDK Upload Pipeline (Headless)', () => {
  let pool;
  afterAll(async () => {
    await destroyClientPool(pool);
  });

  it('measures encrypt + pin + IPNS publish without client overhead', async () => {
    pool = await createClientPool({ clientCount: 10, label: 'sdk-upload' });

    await Promise.allSettled(
      pool.map(async (pc) => {
        pc.metrics.start();
        const ctx = { apiUrl, getAccessToken: async () => pc.accessToken, axiosInstance };
        for (let i = 0; i < 20; i++) {
          const data = new Uint8Array(10_000);
          crypto.getRandomValues(data);
          // Direct sdk-core call — no CipherBoxClient folder tree
          await pc.metrics.measure('sdkUploadFile', () =>
            sdkCore.uploadFile({
              ctx,
              folderKey,
              ipnsName,
              data,
              fileName: `f-${i}`,
              mimeType: 'application/octet-stream',
            })
          );
        }
        pc.metrics.stop();
      })
    );

    const metrics = await aggregateAndReport('SDK Upload Pipeline', pool);
    expectThresholdsPassed(metrics, [
      { operation: 'sdkUploadFile', p95MaxMs: 8_000, errorRateMax: 0.05 },
    ]);
  });
});
```

### TEST-03: 401 Interceptor in Client Pool

```typescript
// In tests/load/src/harness/client-pool.ts, modify createTestAccount integration
// The CipherBoxClient already accepts getAccessToken -- make it return a mutable token
// that gets updated on 401 re-auth.

// Adapt from @cipherbox/api-client instance.ts lines 48-88
// Key addition: refreshAccessToken calls /auth/test-login with stored email+secret
```

## State of the Art

| Old Approach                          | Current Approach                                | When Changed | Impact                                               |
| ------------------------------------- | ----------------------------------------------- | ------------ | ---------------------------------------------------- |
| loadBin returns empty on 404          | loadBin auto-repairs by publishing empty bin    | Phase 24     | Bin always works, even on first login                |
| Registry v1 strict validation         | v1/v2 dual-read, strict v2 write                | Phase 24     | Backward-compatible registry migration               |
| Load tests use CipherBoxClient only   | Headless sdk-core tests supplement client tests | Phase 24     | Bottleneck isolation without browser/client overhead |
| Recovery tool has export + IPFS modes | IPFS-direct only (export removed)               | Phase 24     | Simpler tool, all vaults are v2                      |
| Load tests fail on 401                | Reactive 401 interceptor with retry             | Phase 24     | Clean data at high concurrency                       |

## Open Questions

1. **SdkContext for headless tests: expose or reconstruct?**
   - What we know: CipherBoxClient creates an internal SdkContext with axiosInstance. Headless tests need the same.
   - What's unclear: Whether to expose the client's internal ctx or construct a parallel one from test account data.
   - Recommendation: Construct a parallel SdkContext in the headless workload. The PoolClient has all needed data (accessToken, apiUrl). Creating a new axiosInstance avoids coupling to CipherBoxClient internals. Add a utility `createSdkContext(pc: PoolClient): SdkContext` helper.

2. **Recovery tool gateway URL for E2E tests**
   - What we know: recovery.html uses `https://ipfs.io` and `https://delegated-ipfs.dev` as default gateways.
   - What's unclear: Whether localhost Kubo supports the gateway API paths that recovery.html uses for IPNS resolution.
   - Recommendation: In the E2E test, inject localhost URLs into the recovery.html input fields before clicking Continue. The API is running locally, and Kubo gateway supports `/ipns/` resolution. If that doesn't work, use the API's IPNS resolve endpoint.

## Validation Architecture

### Test Framework

| Property           | Value                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------- |
| Framework          | Vitest 3.x (load tests) + Playwright 1.48+ (E2E)                                      |
| Config file        | `tests/load/vitest.config.ts`, `tests/web-e2e/playwright.config.ts`                   |
| Quick run command  | `cd tests/load && pnpm test -- --run src/scenarios/<file>.test.ts`                    |
| Full suite command | `cd tests/load && pnpm test` + `cd tests/web-e2e && pnpm test tests/recovery.spec.ts` |

### Phase Requirements to Test Map

| Req ID    | Behavior                        | Test Type  | Automated Command                                                                              | File Exists?                   |
| --------- | ------------------------------- | ---------- | ---------------------------------------------------------------------------------------------- | ------------------------------ |
| BUGFIX-01 | Bin IPNS auto-repair on 404     | unit + E2E | `pnpm --filter @cipherbox/sdk test -- --run src/__tests__/bin.test.ts`                         | Exists (unit, needs new cases) |
| BUGFIX-02 | Registry v1->v2 migration       | unit       | `pnpm --filter @cipherbox/core test -- --run src/__tests__/registry.test.ts`                   | Needs new cases                |
| TEST-01   | Headless sdk-core load tests    | load       | `cd tests/load && pnpm test -- --run src/scenarios/sdk-*.test.ts`                              | Wave 0                         |
| TEST-02   | Recovery tool E2E               | e2e        | `cd tests/web-e2e && pnpm test tests/recovery.spec.ts`                                         | Wave 0                         |
| TEST-03   | 401 token refresh in load tests | load       | `cd tests/load && LOAD_TEST_CLIENTS=5 pnpm test -- --run src/scenarios/sustained-load.test.ts` | Exists (needs interceptor)     |

### Sampling Rate

- **Per task commit:** Run unit tests for modified packages (`pnpm --filter @cipherbox/core test`, `pnpm --filter @cipherbox/sdk test`)
- **Per wave merge:** Full load test suite + recovery E2E
- **Phase gate:** All load test thresholds green, recovery E2E passes, registry migration unit tests pass

### Wave 0 Gaps

- [ ] `tests/load/src/scenarios/sdk-upload-pipeline.test.ts` -- covers TEST-01
- [ ] `tests/load/src/scenarios/sdk-ipns-contention.test.ts` -- covers TEST-01
- [ ] `tests/load/src/scenarios/sdk-folder-read.test.ts` -- covers TEST-01
- [ ] `tests/load/src/workloads/sdk-core-workload.ts` -- shared headless workload helpers
- [ ] `tests/web-e2e/tests/recovery.spec.ts` -- covers TEST-02
- [ ] Unit tests for registry v2 migration in `packages/core/src/__tests__/registry.test.ts` -- covers BUGFIX-02
- [ ] Unit tests for bin auto-repair in `packages/sdk/src/__tests__/bin.test.ts` -- covers BUGFIX-01

## Sources

### Primary (HIGH confidence)

- `packages/sdk/src/bin/index.ts` -- Current loadBin implementation, saveBinMetadata pattern
- `packages/core/src/registry/schema.ts` -- Current validateDeviceRegistry, validateDeviceEntry (line 94: publicKey.length !== 64; line 99: ipHash.length !== 64)
- `packages/core/dist/index.mjs:360` -- Confirmed error at ipHash validation in bundled output
- `apps/web/src/hooks/useAuth.ts:338` -- Root cause: `ipHash: ''` passed to initializeOrSyncRegistry
- `docs/METADATA_EVOLUTION_PROTOCOL.md` -- Section 4 checklist for schema evolution
- `docs/METADATA_SCHEMAS.md` -- DeviceRegistry v1 schema, Section 12
- `tests/load/src/harness/` -- MetricsCollector, ThresholdConfig, client-pool, reporter
- `tests/sdk-e2e/src/fixtures/test-harness.ts` -- createTestAccount pattern
- `@cipherbox/api-client` `instance.ts` -- 401 interceptor with shared refresh promise pattern
- `.planning/todos/pending/` -- Original bug reports for all 5 issues

### Secondary (MEDIUM confidence)

- `apps/web/src/services/device-registry.service.ts` -- initializeOrSyncRegistry flow, createEmptyDeviceEntry
- `apps/web/public/recovery.html` -- Current dual-mode recovery tool (export + IPFS-direct)
- `tests/web-e2e/playwright.config.ts` -- Playwright config, webServer setup
- `tests/load/vitest.config.ts` -- 10-minute test timeout, sequential execution

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - All packages are existing workspace dependencies, no new libraries needed
- Architecture: HIGH - All patterns derived from existing codebase implementations
- Pitfalls: HIGH - Root causes verified by reading actual source code and dist bundles
- Bug root causes: HIGH - Traced to exact lines of code (useAuth.ts:338, core/dist:360)

**Research date:** 2026-03-25
**Valid until:** 2026-04-25 (stable -- internal codebase patterns unlikely to change)
