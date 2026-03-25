# Phase 22: Performance Baselines Completion - Research

**Researched:** 2026-03-25
**Domain:** Client-side performance instrumentation, E2E journey timing, load test thresholds, capacity modeling
**Confidence:** HIGH

## Summary

Phase 22 completes the performance picture by adding four layers: (1) client-side timing instrumentation in the SDK packages using the browser Performance API, (2) end-to-end user journey timing via Playwright E2E tests, (3) automated pass/fail thresholds in the existing vitest/SDK load test harness, and (4) a comprehensive capacity model document. The project already has substantial performance infrastructure from Phases 18, 19, and 19.2 -- server-side Prometheus histograms, 5 load test scenarios with MetricsCollector, and detailed baseline documents. This phase extends that foundation to the client side and adds the automation/documentation layer.

The SDK already has a `withOperation()` wrapper in `CipherBoxClient` that emits `operation:start` and `operation:end` events with `durationMs`. The new Performance API instrumentation goes one level deeper -- into `sdk-core` -- to capture individual crypto operations (encrypt/decrypt), IPFS operations (upload/download), and IPNS operations (publish/resolve) that compose those higher-level SDK operations. This gives DevTools-visible timing without requiring SDK event subscription.

**Primary recommendation:** Add Performance API marks/measures to `sdk-core` functions (gated by env check), create 3 Playwright journey-timing specs, add threshold assertions to the existing `aggregateAndReport` flow, and write `docs/CAPACITY.md` consolidating all baseline data into projections.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **Client-side timing in SDK packages**: Instrumentation lives in `@cipherbox/sdk-core` and `@cipherbox/sdk`, not web app hooks. Uses browser Performance API (`performance.mark`/`performance.measure`). Dev/debug only -- gated behind environment check or feature flag, zero overhead in production.
- **End-to-end journey timing via Playwright**: Three journeys -- login-to-vault, upload-to-visible, share-to-accessible. Results captured in `.planning/baselines/22-journey-baselines.md`.
- **Enhance existing vitest/SDK harness** (NOT k6): Add automated pass/fail thresholds to the existing 5-scenario harness. CI fails if thresholds breached.
- **Capacity document**: Full capacity model in `docs/CAPACITY.md` with observed limits, scaling recommendations, projections and formulas.

### Claude's Discretion

- Specific Performance API mark/measure naming conventions
- Which SDK methods get instrumented (beyond the core encrypt/decrypt/upload/download/IPNS set)
- Environment check mechanism for gating dev-only instrumentation
- Exact pass/fail threshold values (based on existing baseline data from 19.2)
- Playwright journey test implementation details (selectors, wait strategies)
- Capacity model formula methodology and presentation format

### Deferred Ideas (OUT OF SCOPE)

None -- discussion stayed within phase scope.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                                               | Research Support                                                                              |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| PERF-05 | Client-side timing instrumentation for encrypt/decrypt, upload/download, IPNS operations                                                  | Performance API mark/measure pattern, sdk-core function targets, environment gating strategy  |
| PERF-06 | End-to-end user journey timing captured (login-to-vault, upload-to-visible, share-to-accessible)                                          | Playwright wall-clock timing pattern, existing E2E page objects, journey timing output format |
| PERF-07 | k6 load testing scripts simulating concurrent users (upload, download, publish, resolve) -- user chose to enhance existing vitest instead | Existing harness architecture, threshold assertion pattern, MetricsCollector integration      |
| PERF-08 | Capacity thresholds documented with scaling recommendations                                                                               | Existing baseline data from 18/19/19.2, capacity model structure, formulas for projections    |

</phase_requirements>

## Standard Stack

### Core

| Library                   | Version | Purpose                                | Why Standard                                                       |
| ------------------------- | ------- | -------------------------------------- | ------------------------------------------------------------------ |
| Performance API (browser) | W3C     | Client-side timing marks and measures  | Native API, shows in DevTools, zero-dependency, universal support  |
| `performance` (Node.js)   | v22+    | Same API in Node.js via perf_hooks     | `globalThis.performance` available since Node 16, same API surface |
| Playwright                | latest  | E2E journey timing with real browser   | Already used in 9 test suites, page objects exist                  |
| Vitest                    | ^3.0.5  | Load test framework with assertions    | Already used by all 5 load test scenarios                          |
| MetricsCollector          | custom  | Percentile calculation and aggregation | Already built in `tests/load/src/harness/metrics.ts`               |

### Supporting

| Library | Version | Purpose        | When to Use                           |
| ------- | ------- | -------------- | ------------------------------------- |
| Vitest  | ^3.0.5  | SDK unit tests | Testing instrumentation doesn't break |

### Alternatives Considered

| Instead of              | Could Use                           | Tradeoff                                                                                             |
| ----------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Performance API         | Custom `performance.now()` wrappers | Performance API provides DevTools integration for free; custom wrappers need manual visualization    |
| Vitest load thresholds  | k6 with built-in thresholds         | User explicitly chose to keep existing vitest harness; k6 would add new tool for a tech demo         |
| Playwright for journeys | SDK-level programmatic timing       | Playwright captures real browser wall-clock time including rendering; SDK timing misses paint delays |

**Installation:**
No new dependencies needed. All tools are already in the project.

## Architecture Patterns

### Performance API Instrumentation in sdk-core

The instrumentation layer wraps existing `sdk-core` functions with `performance.mark()` and `performance.measure()` calls. The key design decision is where this wrapping happens.

**Pattern: Module-level wrapper functions with environment gating**

```typescript
// packages/sdk-core/src/perf.ts

/**
 * Performance instrumentation namespace.
 * All marks use "cipherbox:" prefix for easy filtering.
 */
const PERF_ENABLED =
  typeof performance !== 'undefined' &&
  (typeof process !== 'undefined'
    ? process.env.NODE_ENV === 'development' || process.env.CIPHERBOX_PERF === '1'
    : true); // In browser, always enabled in dev builds (Vite strips in prod)

export function markStart(operation: string): string {
  if (!PERF_ENABLED) return '';
  const markName = `cipherbox:${operation}:start`;
  performance.mark(markName);
  return markName;
}

export function markEnd(operation: string, startMark: string): PerformanceMeasure | null {
  if (!PERF_ENABLED || !startMark) return null;
  const endMark = `cipherbox:${operation}:end`;
  performance.mark(endMark);
  const measure = performance.measure(`cipherbox:${operation}`, startMark, endMark);
  // Clean up marks to prevent memory accumulation
  performance.clearMarks(startMark);
  performance.clearMarks(endMark);
  return measure;
}

/** Convenience: wrap an async function with automatic marks/measures */
export async function withPerf<T>(operation: string, fn: () => Promise<T>): Promise<T> {
  const start = markStart(operation);
  try {
    return await fn();
  } finally {
    markEnd(operation, start);
  }
}
```

**Rationale:**

- `performance.mark()` and `performance.measure()` are available in both browser (`globalThis.performance`) and Node.js 16+ (`globalThis.performance`).
- The `cipherbox:` namespace prefix prevents collision with other marks and enables easy filtering in DevTools (filter by "cipherbox").
- Marks are cleared after measurement to prevent unbounded memory growth.
- The `PERF_ENABLED` check is evaluated once at module load -- zero overhead per-call in production (dead code path).

### Mark/Measure Naming Convention

Use colon-separated hierarchy: `cipherbox:{domain}:{operation}`

| Domain     | Operations                                  | Example Mark                      |
| ---------- | ------------------------------------------- | --------------------------------- |
| `encrypt`  | `aes-gcm`, `ecies-wrap`                     | `cipherbox:encrypt:aes-gcm:start` |
| `decrypt`  | `aes-gcm`, `ecies-unwrap`                   | `cipherbox:decrypt:aes-gcm:start` |
| `ipfs`     | `upload`, `download`, `unpin`               | `cipherbox:ipfs:upload:start`     |
| `ipns`     | `publish`, `batch-publish`, `resolve`       | `cipherbox:ipns:publish:start`    |
| `upload`   | `full` (entire uploadFile pipeline)         | `cipherbox:upload:full:start`     |
| `download` | `full` (entire downloadAndDecrypt pipeline) | `cipherbox:download:full:start`   |
| `folder`   | `load`, `update-publish`                    | `cipherbox:folder:load:start`     |

### SDK-Core Instrumentation Targets

Functions in `packages/sdk-core/src/` that should be instrumented:

| Module      | Function                         | What It Measures                                  |
| ----------- | -------------------------------- | ------------------------------------------------- |
| `upload/`   | `uploadFile`                     | Full upload pipeline (encrypt + IPFS + file meta) |
| `download/` | `downloadAndDecrypt`             | Full download pipeline (fetch + decrypt)          |
| `ipfs/`     | `addToIpfs`                      | IPFS upload via API relay                         |
| `ipfs/`     | `fetchFromIpfs`                  | IPFS download via API relay                       |
| `ipns/`     | `createAndPublishIpnsRecord`     | Single IPNS publish round-trip                    |
| `ipns/`     | `batchPublishIpnsRecords`        | Batch IPNS publish round-trip                     |
| `ipns/`     | `resolveIpnsRecord`              | IPNS resolve round-trip                           |
| `folder/`   | `fetchAndDecryptMetadata`        | Fetch + decrypt folder metadata                   |
| `folder/`   | `loadFolderMetadata`             | Resolve IPNS + fetch + decrypt (full load)        |
| `folder/`   | `updateFolderMetadataAndPublish` | Encrypt + upload + publish (full update)          |

The stateful `CipherBoxClient` in `@cipherbox/sdk` already has `withOperation()` which emits `operation:end` with `durationMs`. The Performance API instrumentation at the `sdk-core` level provides finer granularity (sub-operations within a single SDK client call) and DevTools visibility.

### Environment Gating Strategy

For browser builds (Vite):

- Vite replaces `import.meta.env.MODE` at build time -- `'production'` in prod, `'development'` in dev
- Use `import.meta.env.DEV` (boolean) as the gate, which Vite tree-shakes entirely in production
- However, sdk-core is a library package built with tsup, not Vite -- it doesn't have `import.meta.env`

For sdk-core (library package built with tsup):

- Check `typeof process !== 'undefined' && process.env.NODE_ENV !== 'production'` for Node.js
- In browser context, `process` is undefined -- rely on the consuming app's bundler to define `process.env.NODE_ENV`
- Alternative: Check for a custom `globalThis.__CIPHERBOX_PERF__` flag that consuming apps can set
- Best approach: Environment variable check that bundlers dead-code-eliminate in production

**Recommended gating:**

```typescript
const PERF_ENABLED =
  typeof performance !== 'undefined' &&
  typeof performance.mark === 'function' &&
  // Opt-in: set globalThis.__CIPHERBOX_PERF__ = true in dev builds
  // or NODE_ENV !== 'production' in Node.js
  ((typeof globalThis !== 'undefined' && (globalThis as any).__CIPHERBOX_PERF__) ||
    (typeof process !== 'undefined' && process.env.NODE_ENV !== 'production'));
```

This ensures:

1. Zero overhead when `performance` API doesn't exist (SSR edge cases)
2. Disabled in production browser builds (NODE_ENV=production, no `__CIPHERBOX_PERF__`)
3. Enabled in Node.js test/dev environments (NODE_ENV=test or development)
4. Explicitly opt-in via `__CIPHERBOX_PERF__` for prod debugging

### Playwright Journey Timing Pattern

```typescript
// tests/web-e2e/tests/journey-timing.spec.ts

test('login-to-vault journey timing', async ({ page }) => {
  const journeyStart = performance.now();

  // Phase 1: Login
  const loginPage = new LoginPage(page);
  await loginPage.goto();

  const loginStart = performance.now();
  await loginPage.loginWithEmail(email, otp);
  const loginDuration = performance.now() - loginStart;

  // Phase 2: Vault load (wait for file list to appear)
  const vaultLoadStart = performance.now();
  await page.waitForSelector('[data-testid="file-list"]', { timeout: 30000 });
  const vaultLoadDuration = performance.now() - vaultLoadStart;

  const totalDuration = performance.now() - journeyStart;

  // Record results
  console.log(
    JSON.stringify({
      journey: 'login-to-vault',
      totalMs: Math.round(totalDuration),
      phases: {
        loginMs: Math.round(loginDuration),
        vaultLoadMs: Math.round(vaultLoadDuration),
      },
    })
  );
});
```

**Key points:**

- Use `performance.now()` in the Node.js test process (Playwright test runner), NOT `Date.now()` -- higher resolution
- Measure wall-clock time from user action to visible result (includes network, crypto, rendering)
- Output structured JSON for capture in baselines document
- Three journeys per CONTEXT.md: login-to-vault, upload-to-visible, share-to-accessible

### Load Test Threshold Assertion Pattern

Add threshold checking to `aggregateAndReport` or as a post-processing step in each scenario:

```typescript
// tests/load/src/harness/thresholds.ts

export interface ThresholdConfig {
  operation: string;
  p95MaxMs: number;
  errorRateMax: number; // 0.0 to 1.0
}

export function checkThresholds(
  metrics: OperationMetrics[],
  thresholds: ThresholdConfig[]
): { passed: boolean; violations: string[] } {
  const violations: string[] = [];
  for (const t of thresholds) {
    const m = metrics.find((m) => m.operation === t.operation);
    if (!m) continue;

    if (m.latency.p95 > t.p95MaxMs) {
      violations.push(
        `${t.operation} p95 ${Math.round(m.latency.p95)}ms exceeds threshold ${t.p95MaxMs}ms`
      );
    }
    const errorRate = m.count > 0 ? m.errors / m.count : 0;
    if (errorRate > t.errorRateMax) {
      violations.push(
        `${t.operation} error rate ${(errorRate * 100).toFixed(1)}% exceeds threshold ${(t.errorRateMax * 100).toFixed(1)}%`
      );
    }
  }
  return { passed: violations.length === 0, violations };
}
```

**Threshold values** (derived from 19.2 post-optimization baselines at 50 clients on staging):

| Scenario           | Operation    | p95 Threshold | Error Rate Threshold | Basis                                        |
| ------------------ | ------------ | ------------- | -------------------- | -------------------------------------------- |
| upload-throughput  | uploadFile   | 10,000ms      | 5%                   | Staging 50-client p95 was 4,615ms; 2x margin |
| mixed-workload     | uploadFile   | 10,000ms      | 10%                  | Mixed workload has higher error rate         |
| mixed-workload     | createFolder | 5,000ms       | 10%                  | Based on 936ms p95 at 5 clients              |
| ipns-publish-storm | createFolder | 10,000ms      | 5%                   | IPNS publish contention scenario             |
| sustained-load     | uploadFile   | 10,000ms      | 5%                   | Same as upload-throughput                    |
| sustained-load     | createFolder | 5,000ms       | 5%                   | Folder ops should be fast                    |

Thresholds are intentionally generous (2x-3x observed values) to catch regressions without flaking on normal variance.

### Capacity Document Structure

`docs/CAPACITY.md` should follow the pattern of existing docs (see `docs/METADATA_SCHEMAS.md` for style):

```markdown
# CipherBox Capacity Model

## Observed Limits

### Single-User Performance

### Concurrent User Scaling

### IPNS Publish Throughput

## Infrastructure Bottlenecks

### Kubo IPFS Node

### PostgreSQL

### API Server

## Scaling Recommendations

### When to Scale

### How to Scale

## Growth Projections

### Storage Growth

### IPNS Name Growth

### Cost Estimates
```

### Anti-Patterns to Avoid

- **Instrumenting in the web app layer:** Locks timing to React lifecycle. Put it in sdk-core where desktop and CLI get it free.
- **Always-on instrumentation in production:** Performance API calls have non-zero cost. Gate behind environment check.
- **Not clearing marks:** `performance.mark()` entries accumulate in the Performance Timeline. Call `performance.clearMarks()` after measuring to prevent memory growth.
- **Using `Date.now()` for micro-benchmarks:** Resolution is 1ms. Use `performance.now()` for sub-millisecond precision in the Playwright test runner.
- **Hard-coding exact thresholds:** Network conditions vary. Thresholds should be 2-3x observed baselines to catch regressions without false positives.

## Don't Hand-Roll

| Problem                 | Don't Build                | Use Instead                                    | Why                                                           |
| ----------------------- | -------------------------- | ---------------------------------------------- | ------------------------------------------------------------- |
| Operation timing        | Custom timer wrappers      | `performance.mark()` / `performance.measure()` | Native API, DevTools integration, cross-platform              |
| Percentile calculation  | Manual sorting/indexing    | Existing `MetricsCollector`                    | Already built, tested, used by all 5 scenarios                |
| Load test reporting     | Custom JSON/console output | Existing `reporter.ts`                         | Already formats tables and JSON, used by `aggregateAndReport` |
| CI threshold checking   | Manual grep/parse          | Vitest `expect()` assertions                   | Already the test framework, produces clear failure messages   |
| E2E test infrastructure | Custom browser automation  | Playwright with existing page objects          | 9 test suites already working, login flows proven             |

**Key insight:** This phase is about extending existing infrastructure, not building new tools. The MetricsCollector, reporter, client-pool, page objects, and CI workflow are all in place.

## Common Pitfalls

### Pitfall 1: Performance API Not Available

**What goes wrong:** `performance.mark()` throws in environments where the Performance API doesn't exist (e.g., some SSR contexts, older Node.js).
**Why it happens:** sdk-core is a library that could be imported anywhere.
**How to avoid:** Guard all Performance API calls behind a `typeof performance !== 'undefined' && typeof performance.mark === 'function'` check, evaluated once at module load.
**Warning signs:** `ReferenceError: performance is not defined` in test output.

### Pitfall 2: Mark Memory Accumulation

**What goes wrong:** Thousands of `performance.mark()` entries accumulate during load tests, causing memory pressure.
**Why it happens:** Marks persist in the Performance Timeline until explicitly cleared.
**How to avoid:** Call `performance.clearMarks()` and `performance.clearMeasures()` after each measurement. The `withPerf` wrapper should handle this automatically.
**Warning signs:** Increasing memory usage during sustained load tests.

### Pitfall 3: Threshold Flakiness in CI

**What goes wrong:** Load test thresholds pass locally but fail in CI due to different hardware characteristics.
**Why it happens:** CI runners have less CPU/RAM/disk throughput than dev machines. Network latency to external services varies.
**How to avoid:** Set thresholds at 2-3x observed values. Use error rate thresholds alongside latency thresholds. Load tests run on `workflow_dispatch` (manual trigger), not on every push.
**Warning signs:** Intermittent CI failures on the same code.

### Pitfall 4: Playwright Timing Includes Rendering

**What goes wrong:** Journey timings seem high because they include browser rendering, paint, and layout.
**Why it happens:** Playwright measures from action to visible result, which includes all browser work.
**How to avoid:** This is intentional -- journey timing should capture the user experience, not just API latency. Document that timings include rendering. Compare to SDK-level timings separately.
**Warning signs:** Upload-to-visible time is much higher than SDK upload time.

### Pitfall 5: Share-to-Accessible Journey May Not Be Testable

**What goes wrong:** The "share-to-accessible" journey requires two accounts and cross-account verification.
**Why it happens:** Sharing features require a second user to accept and access the shared folder.
**How to avoid:** Use the existing `sharing-workflow.spec.ts` E2E test as a reference for the multi-account pattern. The wallet-login helpers support creating multiple test accounts.
**Warning signs:** Single-account test patterns don't cover the share recipient flow.

## Code Examples

### Instrumenting an sdk-core Function

```typescript
// packages/sdk-core/src/upload/index.ts (modified)
import { withPerf } from '../perf';

export async function uploadFile(params: { ... }): Promise<UploadResult> {
  return withPerf('upload:full', async () => {
    const fileKey = generateFileKey();
    const iv = generateIv();

    try {
      // Wrap individual sub-operations
      const ciphertext = await withPerf('encrypt:aes-gcm', () =>
        encryptAesGcm(params.data, fileKey, iv)
      );

      const wrappedKey = await withPerf('encrypt:ecies-wrap', () =>
        wrapKey(fileKey, params.userPublicKey)
      );

      const { cid, size: encryptedSize } = await withPerf('ipfs:upload', () =>
        addToIpfs(params.ctx, ciphertext, params.onProgress)
      );

      const fileMetaResult = await withPerf('ipns:file-meta-create', () =>
        createFileMetadata({ ... })
      );

      return { cid, encryptedSize, ... };
    } finally {
      clearBytes(fileKey);
    }
  });
}
```

Source: Derived from existing `packages/sdk-core/src/upload/index.ts` structure.

### Reading Performance Measures Programmatically

```typescript
// In browser DevTools console or test code:
const measures = performance
  .getEntriesByType('measure')
  .filter((e) => e.name.startsWith('cipherbox:'));

for (const m of measures) {
  console.log(`${m.name}: ${m.duration.toFixed(2)}ms`);
}
// Output:
// cipherbox:encrypt:aes-gcm: 12.45ms
// cipherbox:ipfs:upload: 1502.30ms
// cipherbox:upload:full: 1623.80ms
```

Source: [MDN Performance API](https://developer.mozilla.org/en-US/docs/Web/API/Performance/measure)

### Threshold-Gated Load Test

```typescript
// tests/load/src/scenarios/upload-throughput.test.ts (enhanced)
import { expect } from 'vitest';
import { checkThresholds, type ThresholdConfig } from '../harness/thresholds';

const THRESHOLDS: ThresholdConfig[] = [
  { operation: 'uploadFile', p95MaxMs: 10_000, errorRateMax: 0.05 },
];

// After aggregateAndReport:
const metrics = await aggregateAndReport('Upload Throughput', pool);
const result = checkThresholds(metrics, THRESHOLDS);

if (!result.passed) {
  console.warn('THRESHOLD VIOLATIONS:');
  result.violations.forEach((v) => console.warn(`  - ${v}`));
}
expect(result.passed, `Thresholds breached:\n${result.violations.join('\n')}`).toBe(true);
```

### Playwright Journey Timing Output

```typescript
// tests/web-e2e/tests/journey-timing.spec.ts

import { test, expect } from '@playwright/test';
import { LoginPage } from '../page-objects/login.page';
import { setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';

test.describe.serial('Journey Timing', () => {
  test('login-to-vault', async ({ page, context }) => {
    const account = createTestAccount();
    await setupMockWallet(context, account);

    const start = performance.now();

    // Login phase
    const loginStart = performance.now();
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginViaWallet(page);
    const loginMs = performance.now() - loginStart;

    // Vault load phase
    const vaultStart = performance.now();
    await page.waitForSelector('[data-testid="file-list"]', { timeout: 30000 });
    const vaultLoadMs = performance.now() - vaultStart;

    const totalMs = performance.now() - start;

    // Output for baseline capture
    console.log(
      `JOURNEY_TIMING: ${JSON.stringify({
        journey: 'login-to-vault',
        totalMs: Math.round(totalMs),
        loginMs: Math.round(loginMs),
        vaultLoadMs: Math.round(vaultLoadMs),
      })}`
    );

    // Sanity check -- should complete within 60s
    expect(totalMs).toBeLessThan(60_000);
  });
});
```

## State of the Art

| Old Approach                        | Current Approach                             | When Changed | Impact                                                  |
| ----------------------------------- | -------------------------------------------- | ------------ | ------------------------------------------------------- |
| `Date.now()` for SDK timing         | `performance.now()` (existing withOperation) | Phase 19.1   | Sub-ms resolution but no DevTools integration           |
| Manual baseline comparison          | Automated threshold checking in CI           | Phase 22     | Regressions caught automatically instead of manually    |
| Server-side only Prometheus metrics | Client + server instrumentation              | Phase 22     | Full pipeline visibility (encrypt -> upload -> publish) |
| Ad-hoc load test runs               | Threshold-gated CI workflow                  | Phase 22     | Pass/fail automation prevents regression merges         |

**Deprecated/outdated:**

- Phase 18 `scripts/baseline-benchmark.sh` (curl-based): Replaced by SDK-level load tests which capture the full client pipeline including crypto. The curl script only tested HTTP round-trips.

## Open Questions

1. **Wallet login timing variability**
   - What we know: Wallet login via mock wallet completes quickly in tests; real Web3Auth login takes 5-15s
   - What's unclear: Should journey timing use mock wallet (fast, repeatable) or real auth (realistic but slow/flaky)?
   - Recommendation: Use mock wallet for consistent timing. Document that real-world login adds 5-15s on top.

2. **Share-to-accessible journey scope**
   - What we know: Sharing E2E tests exist (`sharing-workflow.spec.ts`), multi-account helpers exist
   - What's unclear: Whether the full share flow (create share -> recipient logs in -> accesses shared folder) is reliably testable in automated E2E
   - Recommendation: Implement the journey, but if it proves flaky, document the manual steps and capture timings from a single manual run instead.

3. **CI threshold calibration**
   - What we know: Existing baselines captured on local and staging (different hardware characteristics)
   - What's unclear: What thresholds will be stable across CI runner hardware variance
   - Recommendation: Start with generous thresholds (2-3x observed), tighten after 5-10 CI runs establish the CI-specific baseline.

## Validation Architecture

### Test Framework

| Property           | Value                                                                   |
| ------------------ | ----------------------------------------------------------------------- |
| Framework          | Vitest 3.0.5 (load tests, SDK unit tests) + Playwright                  |
| Config file        | `tests/load/vitest.config.ts`, `tests/web-e2e/playwright.config.ts`     |
| Quick run command  | `cd tests/load && pnpm exec vitest run --no-coverage upload-throughput` |
| Full suite command | `cd tests/load && pnpm exec vitest run --no-coverage`                   |

### Phase Requirements -> Test Map

| Req ID  | Behavior                           | Test Type | Automated Command                                                            | File Exists?     |
| ------- | ---------------------------------- | --------- | ---------------------------------------------------------------------------- | ---------------- |
| PERF-05 | Performance marks created          | unit      | `cd packages/sdk-core && pnpm test -- --run perf`                            | Wave 0           |
| PERF-05 | Marks disabled in production       | unit      | `cd packages/sdk-core && pnpm test -- --run perf`                            | Wave 0           |
| PERF-06 | Login-to-vault journey timing      | e2e       | `cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts` | Wave 0           |
| PERF-06 | Upload-to-visible journey timing   | e2e       | `cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts` | Wave 0           |
| PERF-06 | Share-to-accessible journey timing | e2e       | `cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts` | Wave 0           |
| PERF-07 | Upload threshold passes            | load      | `cd tests/load && pnpm exec vitest run --no-coverage upload-throughput`      | Exists (enhance) |
| PERF-07 | Mixed workload threshold passes    | load      | `cd tests/load && pnpm exec vitest run --no-coverage mixed-workload`         | Exists (enhance) |
| PERF-08 | Capacity document exists           | manual    | `test -f docs/CAPACITY.md`                                                   | Wave 0           |

### Sampling Rate

- **Per task commit:** Quick check: `cd packages/sdk-core && pnpm test -- --run`
- **Per wave merge:** Full load test suite: `cd tests/load && pnpm exec vitest run --no-coverage`
- **Phase gate:** All E2E journey tests pass + load test thresholds green

### Wave 0 Gaps

- [ ] `packages/sdk-core/src/perf.ts` -- Performance API wrapper module
- [ ] `packages/sdk-core/src/__tests__/perf.test.ts` -- Unit tests for perf instrumentation
- [ ] `tests/web-e2e/tests/journey-timing.spec.ts` -- Playwright journey timing tests
- [ ] `tests/load/src/harness/thresholds.ts` -- Threshold checking module
- [ ] `docs/CAPACITY.md` -- Capacity model document
- [ ] `.planning/baselines/22-journey-baselines.md` -- Journey timing baseline results

## Sources

### Primary (HIGH confidence)

- [MDN Performance.mark()](https://developer.mozilla.org/en-US/docs/Web/API/Performance/mark) -- Full API reference for mark() method
- [MDN Performance.measure()](https://developer.mozilla.org/en-US/docs/Web/API/Performance/measure) -- Full API reference for measure() method, retrieval patterns
- [Node.js perf_hooks](https://nodejs.org/api/perf_hooks.html) -- Node.js Performance API (same interface as browser)
- Project codebase -- `tests/load/src/harness/` (MetricsCollector, reporter, client-pool), `packages/sdk-core/src/` (all instrumentation targets), `packages/sdk/src/client.ts` (withOperation pattern), `tests/web-e2e/` (Playwright page objects and test patterns)
- `.planning/baselines/19.2-post-optimization-baselines.md` -- Comprehensive baseline data for threshold derivation

### Secondary (MEDIUM confidence)

- [Vitest API](https://vitest.dev/api/test) -- Test assertions and configuration
- [Playwright docs](https://playwright.dev/) -- E2E testing framework

### Tertiary (LOW confidence)

- None -- all findings verified against project codebase and official documentation.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- all tools already in project, Performance API is a stable W3C standard
- Architecture: HIGH -- patterns derived from existing codebase (withOperation, MetricsCollector, page objects)
- Pitfalls: HIGH -- identified from actual project experience (Phase 18/19/19.2 baseline work) and well-documented API behavior

**Research date:** 2026-03-25
**Valid until:** 2026-04-25 (stable domain -- Performance API and testing tools change slowly)
