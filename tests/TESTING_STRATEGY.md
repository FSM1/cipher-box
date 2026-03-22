# CipherBox Testing Strategy

## Test Suite Overview

| Package          | Type                       | Tests       | Runtime  | Trigger           |
| ---------------- | -------------------------- | ----------- | -------- | ----------------- |
| `tests/sdk-e2e/` | SDK E2E (correctness)      | 83          | ~11s     | PR + push to main |
| `tests/load/`    | Load testing (performance) | 5 scenarios | variable | Manual dispatch   |
| `tests/web-e2e/` | Playwright Web E2E         | 9 suites    | ~2-5min  | Push to main      |

## SDK E2E Tests (`@cipherbox/sdk-e2e`)

Drives `CipherBoxClient` directly against the API — no browser, no Playwright, no UI selectors. Each test suite creates real user accounts via `/auth/test-login`, initializes vaults, and exercises the full encrypt → IPFS → IPNS → resolve → decrypt pipeline.

### Running locally

```bash
# Prerequisites: PostgreSQL, IPFS, Redis on host; API .env must have NODE_ENV=test
node tools/mock-ipns-routing/dist/index.js &
pnpm --filter @cipherbox/api dev &

# Wait for API health check, then run
pnpm --filter @cipherbox/sdk-e2e test
```

### Test suites

- **vault-lifecycle** — Init, duplicate 409, GET vault/export/config/quota, auth errors
- **folder-crud** — Create, nested, rename, move, delete, 20-folder stress
- **file-operations** — Upload (text, 50KB, 500KB), download round-trip, rename, delete
- **data-integrity** — 8 sizes (100B–500KB) byte-for-byte round-trip, unicode, nested
- **bin-operations** — loadBin, deleteToBin, restore, permanentDelete, emptyBin, IPNS persistence
- **error-cases** — Unloaded folder ops, BinNotLoadedError, event emission, post-destroy
- **share-operations** — Alice→Bob share, received/sent lists, key unwrap, self-share 409, revoke
- **invite-link** — Create, public status, claim, double-claim prevention, revoke
- **ipns-consistency** — Sequence monotonicity, persist through IPNS publish/resolve/reload
- **concurrent-operations** — Rapid creation, interleaved uploads, create+upload-into, rapid move

## Load Tests (`@cipherbox/load-tests`)

Node.js-native load testing using concurrent `CipherBoxClient` instances. Each "virtual user" is a real test account with its own vault.

### Scenarios

| Scenario             | Default Clients | Focus                            |
| -------------------- | --------------- | -------------------------------- |
| `upload-throughput`  | 10 × 20 files   | Upload pipeline + IPNS publish   |
| `ipns-publish-storm` | 20 × 50 cycles  | IPNS publish contention          |
| `mixed-workload`     | 5 × 45 ops      | Realistic weighted operation mix |
| `sustained-load`     | 5 × 5 min       | Latency stability over time      |
| `spike-test`         | 2→20 burst      | Recovery time measurement        |

### Running locally

```bash
# Same prerequisites as SDK E2E, then:
LOAD_TEST_CLIENTS=5 pnpm --filter @cipherbox/load-tests test -- --testPathPattern=mixed-workload
```

### Running against staging

Trigger via GitHub Actions → `load-test.yml` → select environment, client count, and scenario.

## Rate Limiting Strategy

### The problem

The API has global rate limiting (10 req/s, 100 req/min) to prevent abuse. SDK tests generate hundreds of requests per suite — a single test file exceeds the minute limit within seconds.

### Design decision: tiered throttle handling

The throttler serves **two distinct purposes**:

1. **Abuse protection** — preventing anonymous/malicious clients from hammering the API
2. **Backpressure signal** — indicating when a node is genuinely overloaded

For correctness tests (SDK E2E), we want to remove (1) entirely. For performance tests (load), we want to remove (1) but preserve (2) — otherwise load tests can't detect real overload.

### Implementation

| Environment    | Mechanism                                             | Throttle behavior                                                  |
| -------------- | ----------------------------------------------------- | ------------------------------------------------------------------ |
| **Local/CI**   | `NODE_ENV=test`                                       | Limits relaxed to 200 req/s, 10k req/min                           |
| **Staging**    | `X-Throttle-Bypass` header + `THROTTLE_BYPASS_SECRET` | Bypassed for throughput tests; real limits for throttle validation |
| **Production** | No bypass secret configured                           | Real limits always enforced                                        |

The bypass header approach ensures:

- Production never has a bypass path (secret is simply not set)
- Staging can selectively bypass for performance measurement
- A dedicated "throttle validation" scenario can test with real limits

### Horizontal scaling implications

Staging is always single-node. Production will horizontally scale. These answer different questions:

- **Staging load tests**: "Does a single node handle its expected per-node share of traffic?"
- **Production load tests**: "Does the cluster handle peak aggregate traffic?"

When production scales horizontally:

- Load tests should distribute across multiple source IPs
- Per-user throttle keying may replace per-IP to allow higher aggregate throughput
- The `sustained-load` and `spike-test` scenarios are designed to measure per-node behavior and will remain relevant for single-node staging

## Instance-Scoped Axios (Singleton Eliminated)

Each `CipherBoxClient` creates its own axios instance via `createAxiosInstance()` and threads it through `SdkContext.axiosInstance` to all API calls (including orval-generated IPNS functions). This eliminates the previous module-level singleton constraint:

- **Multi-account tests**: Each client uses its own token automatically — no `switchTo()` needed
- **Load tests**: True parallel operation — each pool client has isolated auth
- **Cross-suite contamination**: Eliminated — no shared global state

The `setApiClientConfig()` singleton still exists for backward compatibility (web app single-user context) but is no longer required for SDK consumers.

## Why Node.js for load tests (not k6)

k6 uses a custom Go-based JS runtime that doesn't support the full Node.js crypto ecosystem (Web Crypto API, `@noble/*`, `eciesjs`). The SDK packages are pure TypeScript/ESM. Porting them to k6 would require significant effort. Node.js with concurrent `CipherBoxClient` instances and `Promise.allSettled` is the natural fit — the bottleneck is network I/O, not CPU.
