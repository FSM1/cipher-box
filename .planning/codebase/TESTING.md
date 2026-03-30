# Testing Patterns

**Analysis Date:** 2026-03-30

## Test Framework

**Runners:**

| Package               | Framework                       | Config                                 |
| --------------------- | ------------------------------- | -------------------------------------- |
| `apps/api`            | Jest 29 (NestJS default)        | `apps/api/jest.config.js`              |
| `apps/web`            | Vitest 3                        | `apps/web/vitest.config.ts`            |
| `packages/crypto`     | Vitest 3                        | `packages/crypto/vitest.config.ts`     |
| `packages/core`       | Vitest 3                        | `packages/core/vitest.config.ts`       |
| `packages/sdk`        | Vitest 3                        | `packages/sdk/vitest.config.ts`        |
| `packages/sdk-core`   | Vitest 3                        | `packages/sdk-core/vitest.config.ts`   |
| `packages/api-client` | Vitest 3                        | `packages/api-client/vitest.config.ts` |
| `tests/web-e2e`       | Playwright 1.48                 | `tests/web-e2e/playwright.config.ts`   |
| `tests/sdk-e2e`       | Vitest 3                        | `tests/sdk-e2e/vitest.config.ts`       |
| `tests/load`          | Vitest 3                        | `tests/load/vitest.config.ts`          |
| `tests/desktop-e2e`   | Shell scripts (bash/PowerShell) | `tests/desktop-e2e/scripts/run-all.sh` |
| `crates/*` (Rust)     | cargo test                      | `Cargo.toml` workspace                 |
| `tee-worker`          | Vitest 3                        | Inline (single test file)              |

**Assertion Libraries:**

- **Jest:** Built-in `expect()` with `jest.fn()` mocks
- **Vitest:** Built-in `expect()` with `vi.fn()` / `vi.mock()` mocks
- **Playwright:** `expect()` from `@playwright/test` with web-first assertions
- **Rust:** `assert!()`, `assert_eq!()` standard macros

**Run Commands:**

```bash
pnpm test                              # Run all unit tests (parallel across workspaces)
pnpm test:web-e2e                      # Playwright Web E2E tests
pnpm test:web-e2e:headed               # E2E with visible browser
pnpm --filter @cipherbox/api test      # API unit tests only
pnpm --filter @cipherbox/api test:cov  # API tests with coverage
pnpm --filter @cipherbox/crypto test   # Crypto unit tests only
pnpm --filter @cipherbox/sdk-e2e test  # SDK E2E tests
pnpm typecheck                         # TypeScript type checking across all workspaces
cargo test --workspace                 # Rust workspace tests (requires FUSE dev libs)
cargo test -p cipherbox-crypto --test cross_language --no-default-features  # Cross-language vector parity
```

## Test File Organization

**Location:** Co-located `__tests__/` directories for packages; co-located `.spec.ts` for API; separate `tests/` directory for E2E.

**Naming Conventions:**

| Context                | Pattern                  | Example                                                |
| ---------------------- | ------------------------ | ------------------------------------------------------ |
| API unit tests         | `*.spec.ts` (co-located) | `apps/api/src/auth/auth.service.spec.ts`               |
| API integration tests  | `__tests__/*.spec.ts`    | `apps/api/src/ipns/__tests__/ipns.integration.spec.ts` |
| Package unit tests     | `__tests__/*.test.ts`    | `packages/crypto/src/__tests__/aes.test.ts`            |
| Web E2E tests          | `tests/*.spec.ts`        | `tests/web-e2e/tests/full-workflow.spec.ts`            |
| SDK E2E tests          | `suites/*.test.ts`       | `tests/sdk-e2e/src/suites/vault-lifecycle.test.ts`     |
| Load tests             | `scenarios/*.test.ts`    | `tests/load/src/scenarios/mixed-workload.test.ts`      |
| Desktop E2E            | `scripts/test-*.sh`      | `tests/desktop-e2e/scripts/test-fuse-operations.sh`    |
| Rust inline tests      | `#[cfg(test)] mod tests` | `crates/crypto/src/aes.rs`                             |
| Rust integration tests | `tests/*.rs`             | `crates/crypto/tests/cross_language.rs`                |

**Directory Structure:**

```text
tests/
  web-e2e/
    playwright.config.ts         # 3 webServers: mock-ipns, API, web
    tests/                       # 14 Playwright spec files
    page-objects/                # Page Object Model classes
      dialogs/                   # Dialog-specific POs
      file-browser/              # File browser POs
      pages/                     # Full page POs
    utils/                       # Test helpers (wallet-login, test-files, etc.)
    fixtures/files/              # Binary test fixtures (PDF, MP4, MP3, small MP4)
  sdk-e2e/
    vitest.config.ts             # 120s timeout, sequential
    src/fixtures/test-harness.ts # Account provisioning + cleanup
    src/fixtures/multi-account.ts # Multi-user fixture for sharing tests
    src/helpers/                  # Assertion + data generator helpers
    src/suites/                  # 11 test suites
  load/
    vitest.config.ts             # 600s timeout (10 min), sequential
    src/harness/                 # Client pool, metrics, reporter, thresholds
    src/scenarios/               # Load test scenarios
    src/workloads/               # Reusable workload definitions
    metrics-*.json               # Baseline metrics snapshots
  desktop-e2e/
    scripts/run-all.sh           # Orchestrator (5 steps)
    scripts/test-fuse-operations.sh
    scripts/test-round-trip.sh
    scripts/test-conflict-detection.sh
    scripts/test-recycle-bin.sh
    scripts/wait-for-mount.sh
    fixtures/crypto/             # Cross-language test vectors for desktop
  vectors/
    crypto/                      # Shared cross-language test vectors (JSON)
    core/                        # Core metadata test vectors (JSON)
tools/
  mock-ipns-routing/             # Fastify-based mock delegated routing service
```

## Test Structure

### API Unit Tests (Jest)

Use NestJS `Test.createTestingModule()` with mocked repositories:

```typescript
// apps/api/src/auth/auth.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: Record<string, jest.Mock>;

  beforeEach(async () => {
    const mockUserRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        // ... other mocked providers
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get(getRepositoryToken(User));
  });

  it('should reject duplicate vault init (409)', async () => {
    // arrange, act, assert
  });
});
```

### Package Unit Tests (Vitest)

Use `vi.fn()` for mocking, direct imports:

```typescript
// packages/sdk/src/__tests__/client.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('CipherBoxClient', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create folder and emit event', async () => {
    // ...
  });
});
```

### SDK E2E Tests (Vitest + Real API)

Use shared test harness for account provisioning:

```typescript
// tests/sdk-e2e/src/suites/vault-lifecycle.test.ts
import { describe, it, expect, afterAll } from 'vitest';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';

describe('Vault Lifecycle', () => {
  let ctx: TestContext;

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  it('should create a test context with valid client', async () => {
    ctx = await createTestContext('vault-lifecycle');
    expect(ctx.client).toBeTruthy();
    expect(ctx.rootIpnsName).toMatch(/^(k51|bafz)/);
  });
});
```

### Web E2E Tests (Playwright)

Use Page Object Model with serial test execution:

```typescript
// tests/web-e2e/tests/full-workflow.spec.ts
import { test, expect } from '@playwright/test';
import { FileListPage } from '../page-objects/file-browser/file-list.page';

test.describe.serial('Full Workflow', () => {
  let fileList: FileListPage;

  test('should log in and see file browser', async ({ page }) => {
    // Uses wallet mock for deterministic auth
    fileList = new FileListPage(page);
    await expect(fileList.emptyState).toBeVisible();
  });
});
```

## Test Harness & Fixtures

### SDK E2E Test Harness (`tests/sdk-e2e/src/fixtures/test-harness.ts`)

Central account provisioning used by both SDK E2E and load tests:

- **`createTestAccount(opts)`**: Authenticates via `POST /auth/test-login`, initializes vault, publishes vault key blob, registers vault on server, returns `CipherBoxClient` instance.
- **`createTestContext(label)`**: Convenience wrapper adding cleanup function.
- **`deleteTestAccount(ctx)`**: Calls `DELETE /auth/account` for cleanup.
- **`testFetch(url, init)`**: Wrapper injecting `X-Throttle-Bypass` header.
- **Throttle bypass**: All test requests include `X-Throttle-Bypass` header when `THROTTLE_BYPASS_SECRET` env var is set. This bypasses NestJS rate limiting in CI.

### Multi-Account Fixture (`tests/sdk-e2e/src/fixtures/multi-account.ts`)

Creates N test accounts for sharing/collaboration tests:

```typescript
const fixture = await createMultiAccountFixture(['alice', 'bob']);
const alice = fixture.accounts.get('alice')!;
const bob = fixture.accounts.get('bob')!;
// ... test sharing between alice and bob
await fixture.cleanupAll();
```

### Load Test Client Pool (`tests/load/src/harness/client-pool.ts`)

Manages N `CipherBoxClient` instances for load testing. Reuses `createTestAccount` from SDK E2E harness. Includes metrics collection, threshold checking, and JSON report generation.

### Wallet Login Helpers (`tests/web-e2e/utils/wallet-login-helpers.ts`)

Uses `@johanneskares/wallet-mock` to inject a mock Ethereum wallet into the browser context. Creates deterministic `viem` accounts for reproducible auth. Includes a custom local-only transport that avoids real RPC calls.

### Mock IPNS Routing (`tools/mock-ipns-routing/src/index.ts`)

A Fastify HTTP server implementing the IPFS delegated routing API:

- `GET /routing/v1/ipns/:name` -- Retrieve stored IPNS record
- `PUT /routing/v1/ipns/:name` -- Store IPNS record (in-memory)
- `POST /reset` -- Clear all stored records
- `GET /health` -- Health check

Records are stored in-memory (reset on restart). Eliminates dependence on public IPFS DHT during testing. Used by all E2E suites (web, SDK, desktop, load).

## Mocking

### API (Jest)

**Pattern:** Mock TypeORM repositories and NestJS providers via `useValue`:

```typescript
const mockRepo = {
  findOne: jest.fn(),
  save: jest.fn(),
  delete: jest.fn(),
};

// In module providers:
{ provide: getRepositoryToken(Entity), useValue: mockRepo }
```

**ESM module mocking:** `jose` ESM package is mapped to a CJS mock at `apps/api/test/__mocks__/jose.ts` via `moduleNameMapper` in Jest config.

**What to mock:**

- TypeORM repositories (always in unit tests)
- External HTTP clients (IPFS, delegated routing)
- BullMQ job processors
- JWT signing/verification (via JwtIssuerService mock)

**What NOT to mock:**

- Cryptographic operations (test real encryption/decryption)
- Data conversion utilities (hexToBytes, bytesToHex)
- Validation/DTO logic

### Packages (Vitest)

**Pattern:** Use `vi.mock()` for module-level mocks, `vi.fn()` for individual functions:

```typescript
vi.mock('@cipherbox/sdk-core', () => ({
  loadFolder: vi.fn().mockResolvedValue({ metadata: { version: 'v2', children: [] } }),
}));
```

**Partial module mocking** (`importOriginal`) is used in `packages/sdk/src/__tests__/upload-batch.test.ts` to preserve non-mocked exports:

```typescript
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    uploadFile: vi.fn(),
    // ... other specific overrides
  };
});
```

### Web E2E (Playwright)

**No mocking of backend.** Tests run against a real API + Postgres + IPFS + Redis stack. Authentication is mocked via:

- `@johanneskares/wallet-mock` for browser wallet injection
- `/auth/test-login` endpoint for deterministic keypair auth in CI

## Coverage

### Coverage Targets (Enforced in CI)

| Package               | Lines                | Branches   | Functions  | Config                                                    |
| --------------------- | -------------------- | ---------- | ---------- | --------------------------------------------------------- |
| `apps/api`            | 85% global           | 78% global | 85% global | `apps/api/jest.config.js` (per-file thresholds)           |
| `packages/crypto`     | 80%                  | 80%        | 80%        | `packages/crypto/vitest.config.ts`                        |
| `packages/core`       | 75%                  | 75%        | 80%        | `packages/core/vitest.config.ts`                          |
| `packages/sdk-core`   | 80%                  | 80%        | 80%        | `packages/sdk-core/vitest.config.ts`                      |
| `packages/sdk`        | 65%                  | 80%        | 60%        | `packages/sdk/vitest.config.ts`                           |
| `packages/api-client` | 0% (informational)   | 0%         | 0%         | `packages/api-client/vitest.config.ts` (mostly generated) |
| Rust (`crates/*`)     | auto (informational) | --         | --         | `codecov.yml` (desktop flag)                              |

### Codecov Integration

**Config:** `codecov.yml` at project root

**Coverage flags:** `api`, `crypto`, `core`, `sdk-core`, `sdk`, `api-client`, `desktop`

**Coverage upload:** CI uploads lcov files after test runs. Base branch coverage uploaded via `codecov-base.yml` workflow on push to `main`.

**Per-flag Codecov targets:**

| Flag       | Target               | Threshold |
| ---------- | -------------------- | --------- |
| api        | 85%                  | 2%        |
| crypto     | 80%                  | 2%        |
| core       | 75%                  | 3%        |
| sdk-core   | 80%                  | 2%        |
| sdk        | 68%                  | 3%        |
| api-client | 70% (informational)  | 5%        |
| desktop    | auto (informational) | 5%        |

**Commands:**

```bash
pnpm --filter @cipherbox/api test:cov       # API coverage (Jest)
pnpm --filter @cipherbox/crypto test:coverage # Crypto coverage (Vitest)
pnpm --filter @cipherbox/core test:coverage   # Core coverage (Vitest)
pnpm --filter @cipherbox/sdk-core test:coverage # SDK-Core coverage (Vitest)
pnpm --filter @cipherbox/sdk test:coverage     # SDK coverage (Vitest)
cargo llvm-cov --workspace --lcov             # Rust coverage (cargo-llvm-cov)
```

## CI Workflows

### `ci.yml` -- Main CI (runs on PRs to `main`)

**Change detection:** Uses `dorny/paths-filter` to skip jobs when only docs/planning changed.

**Jobs (in order):**

1. **Lint** -- ESLint across all workspaces
2. **Typecheck** -- Full TypeScript build chain (conditional on `src` changes)
3. **API Spec Verification** -- Regenerates OpenAPI spec + client, fails if uncommitted changes
4. **Migration Drift Check** -- Runs migrations, generates drift migration, fails on structural drift
5. **Test** -- Unit tests with coverage for api, crypto, core, sdk-core, sdk, api-client. Uploads to Codecov.
6. **SDK E2E** -- Full SDK E2E suite against real API with Postgres + IPFS + Redis + mock-ipns-routing
7. **Build** -- Production build verification (all packages except desktop)
8. **Cargo Windows/macOS/Linux** -- Rust cargo check + cargo test on 3 platforms (conditional on desktop changes)
9. **Vector Parity** -- Verifies Rust and TypeScript crypto implementations produce identical output from shared test vectors (`tests/vectors/`)

**Services:** PostgreSQL 16, Kubo IPFS v0.40.0, Redis 7

### `e2e.yml` -- Web E2E Tests (runs on push to `main`)

Runs Playwright tests against full stack. Uploads trace/screenshot artifacts on failure.

### `desktop-e2e.yml` -- Desktop E2E Tests (runs on push to `main`)

Matrix build on macOS/Windows/Linux. Builds debug Tauri binary, starts full backend, runs shell-script test suite (FUSE operations, API round-trip, conflict detection, recycle bin).

### `load-test.yml` -- Load Tests (manual dispatch only)

Configurable scenarios: `upload-throughput`, `ipns-publish-storm`, `mixed-workload`, `sustained-load`, `spike-test`. Supports `local` or `staging` targets with variable client count. Uploads metrics JSON artifacts.

### `release-gate.yml` -- Release Gate (on release PRs)

Verifies that Web E2E and Desktop E2E (if desktop changed) passed on `main` before allowing release-please PR to merge.

### `codecov-base.yml` -- Base Coverage Upload (push to `main`)

Downloads coverage artifacts from latest successful CI run, re-uploads tagged to `main` commit for PR diff comparison.

## Test Types

### Unit Tests

- **API:** 40 `.spec.ts` files covering all services, controllers, guards, strategies, and pipes. Uses NestJS testing module with mocked repositories.
- **Crypto:** 7 test files covering AES-GCM, AES-CTR, ECIES, Ed25519, HKDF, key hierarchy, vault IPNS.
- **Core:** 10 test files covering folder metadata, IPNS records, vault blob, bin metadata, file IPNS, registry.
- **SDK-Core:** 13 test files covering download, encryption-mode, folder, IPFS, IPNS, performance, pinning (5 providers), upload, vault. `upload.test.ts` covers `uploadFile()` including `encryptFn` injection, buffer-detachment safety, and `teeKeys` propagation.
- **SDK:** 13 test files covering client operations, bin operations, context, error handling, events, integration, key-cache, share operations, shared-write, pinning, upload concurrency, and batch upload. `upload-batch.test.ts` (Phase 37) covers the `uploadFiles()` orchestration: p-limit concurrency pool, single-publish, partial failure, per-file callbacks, event emission, key cleanup, BYO pinFn, and share re-wrap.
- **API Client:** 1 test file (`instance.test.ts`).
- **Web:** 3 test files (sync store, upload error recovery, logout security).
- **TEE Worker:** 1 test file (`ssrf-validation.test.ts`).
- **Rust (inline):** 19 Rust source files with `#[cfg(test)]` modules containing 158+ tests total across crypto, core, fuse, and sdk crates.

**Coverage intentional gaps:**

- FUSE write operations (`crates/fuse/`) have no unit tests by design — covered by Desktop E2E instead. This is a documented won't-fix.

### Integration Tests

- **API IPNS:** `apps/api/src/ipns/__tests__/ipns.integration.spec.ts` (502 lines) -- tests IPNS service composition
- **API IPNS Security:** `apps/api/src/ipns/__tests__/ipns.security.spec.ts` (509 lines) -- security-focused integration tests
- **API E2E:** `apps/api/test/ipfs.e2e-spec.ts` -- Jest E2E test with full app bootstrap

### SDK E2E Tests

Full API-backed tests running against real Postgres + IPFS + Redis. 11 suites total.

| Suite            | File                                                     | Coverage                                                                                          |
| ---------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Vault Lifecycle  | `tests/sdk-e2e/src/suites/vault-lifecycle.test.ts`       | Init, duplicate, get, export, config, quota                                                       |
| Folder CRUD      | `tests/sdk-e2e/src/suites/folder-crud.test.ts`           | Create, rename, move, delete folders                                                              |
| File Operations  | `tests/sdk-e2e/src/suites/file-operations.test.ts`       | Upload, download, rename, move, delete files                                                      |
| Data Integrity   | `tests/sdk-e2e/src/suites/data-integrity.test.ts`        | Roundtrip verification, content checksums                                                         |
| IPNS Consistency | `tests/sdk-e2e/src/suites/ipns-consistency.test.ts`      | IPNS publish/resolve, sequence numbers                                                            |
| Error Cases      | `tests/sdk-e2e/src/suites/error-cases.test.ts`           | Invalid inputs, 404s, auth failures                                                               |
| Concurrent Ops   | `tests/sdk-e2e/src/suites/concurrent-operations.test.ts` | Parallel uploads, race conditions                                                                 |
| Bin Operations   | `tests/sdk-e2e/src/suites/bin-operations.test.ts`        | Soft delete, restore, permanent delete                                                            |
| Share Operations | `tests/sdk-e2e/src/suites/share-operations.test.ts`      | Create share, accept, revoke (multi-account)                                                      |
| Invite Link      | `tests/sdk-e2e/src/suites/invite-link.test.ts`           | Invite link creation and claiming                                                                 |
| Batch Upload     | `tests/sdk-e2e/src/suites/batch-upload.test.ts`          | `uploadFiles()` batch: 3-file batch, mixed sizes, progress callbacks, `files:batchUploaded` event |

**Config:** 120s test timeout, 60s hook timeout, sequential execution, no file parallelism.

### Web E2E Tests (Playwright)

14 suites total. All use `test.describe.serial` and manage their own browser context + account lifecycle.

| Spec               | File                                               | Coverage                                                                                    |
| ------------------ | -------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Full Workflow      | `tests/web-e2e/tests/full-workflow.spec.ts`        | Login, folder hierarchy, upload 12+ files, batch actions, move, edit, rename, cleanup       |
| Recycle Bin        | `tests/web-e2e/tests/recycle-bin.spec.ts`          | Soft delete, restore, permanent delete, empty bin                                           |
| Recovery           | `tests/web-e2e/tests/recovery.spec.ts`             | Account recovery with browser-based IPFS                                                    |
| MFA Flows          | `tests/web-e2e/tests/mfa-flows.spec.ts`            | MFA enrollment, device approval                                                             |
| Wallet Login       | `tests/web-e2e/tests/wallet-login.spec.ts`         | Ethereum wallet authentication                                                              |
| Sharing            | `tests/web-e2e/tests/sharing-workflow.spec.ts`     | Share folder, accept share, view shared items                                               |
| Writable Shares    | `tests/web-e2e/tests/writable-shares.spec.ts`      | Write permissions, recipient uploads, permission changes                                    |
| Invite Link        | `tests/web-e2e/tests/invite-link-workflow.spec.ts` | Invite link creation and claiming                                                           |
| Search             | `tests/web-e2e/tests/search-workflow.spec.ts`      | Client-side search                                                                          |
| Conflict Detection | `tests/web-e2e/tests/conflict-detection.spec.ts`   | Concurrent edit conflict detection                                                          |
| Journey Timing     | `tests/web-e2e/tests/journey-timing.spec.ts`       | Performance timing metrics                                                                  |
| Batch Download     | `tests/web-e2e/tests/batch-download.spec.ts`       | Multi-select, SelectionActionBar download button, batch context menu (Phase 34)             |
| Media Preview      | `tests/web-e2e/tests/media-preview.spec.ts`        | PDF canvas viewer, video player, audio player, corrupt file error state (Phase 34)          |
| AES-CTR Streaming  | `tests/web-e2e/tests/streaming-playback.spec.ts`   | Large video CTR mode via service worker, small video GCM blob URL, decrypt badge (Phase 34) |

**Playwright Config highlights:**

- Single Chromium browser project
- Sequential execution (`fullyParallel: false`, `workers: 1`)
- No retries (`retries: 0` -- fix flakiness immediately)
- 3 web servers auto-started: mock-ipns-routing (port 3001), API (port 3000), web app (port 5173)
- Artifacts: screenshots, video, traces on failure only
- Suite-level timeouts set via `test.setTimeout()` in `beforeAll` (90-180s depending on suite)

**Media test fixtures** (`tests/web-e2e/fixtures/files/`):

- `test-document.pdf` -- PDF for preview tests
- `test-video.mp4` -- Large video (>256KB) for AES-CTR streaming path
- `test-video-small.mp4` -- Small video (<256KB) for AES-GCM blob URL path
- `test-audio.mp3` -- Audio for audio player preview

### Desktop E2E Tests

Shell-script-based test suite orchestrated by `tests/desktop-e2e/scripts/run-all.sh`:

1. **Wait for mount** -- Polls `~/CipherBox` until FUSE mount appears
2. **FUSE file operations** -- Create, write, read, rename, delete via filesystem
3. **API round-trip** -- Write via FUSE, verify via API; write via API, verify via FUSE
4. **Conflict detection** -- Concurrent modification detection
5. **Recycle bin** -- Delete via FUSE, verify in bin, restore

Runs on macOS (FUSE-T/SMB), Linux (FUSE3), Windows (WinFSP). Windows variant uses `run-all.ps1`.

**Note:** FUSE write operations have no unit tests by design. Desktop E2E is the sole test coverage for this layer.

### Load Tests

| Scenario            | File                                                     | Description                    |
| ------------------- | -------------------------------------------------------- | ------------------------------ |
| Upload Throughput   | `tests/load/src/scenarios/upload-throughput.test.ts`     | Pure upload bandwidth          |
| IPNS Publish Storm  | `tests/load/src/scenarios/ipns-publish-storm.test.ts`    | Concurrent IPNS publishing     |
| Mixed Workload      | `tests/load/src/scenarios/mixed-workload.test.ts`        | Weighted mix of all operations |
| Sustained Load      | `tests/load/src/scenarios/sustained-load.test.ts`        | Extended duration              |
| Spike Test          | `tests/load/src/scenarios/spike-test.test.ts`            | Sudden burst                   |
| SDK Folder Read     | `tests/load/src/scenarios/sdk-folder-read.test.ts`       | Folder loading performance     |
| SDK IPNS Contention | `tests/load/src/scenarios/sdk-ipns-contention.test.ts`   | IPNS publish contention        |
| SDK Upload Pipeline | `tests/load/src/scenarios/sdk-upload-pipeline.test.ts`   | Upload pipeline throughput     |
| BYO Upload          | `tests/load/src/scenarios/byo-upload-throughput.test.ts` | BYO-IPFS upload                |
| BYO Mixed           | `tests/load/src/scenarios/byo-mixed-workload.test.ts`    | BYO-IPFS mixed workload        |
| BYO Capacity        | `tests/load/src/scenarios/byo-capacity-ceiling.test.ts`  | BYO-IPFS capacity limits       |

**Config:** 600s test timeout, sequential, uses threshold assertions for p95 latency and error rate.

### Cross-Language Vector Parity

Shared JSON test vectors in `tests/vectors/` ensure byte-level parity between TypeScript and Rust crypto implementations:

- **Crypto vectors:** `tests/vectors/crypto/aes-gcm.json`, `ecies.json`, `ed25519.json`, `hkdf.json`, `ipns-name.json`
- **Core vectors:** `tests/vectors/core/vault-blob.json`, `folder-metadata.json`, `ipns-record.json`, `bin-metadata.json`

Both `crates/crypto/tests/cross_language.rs` (Rust) and `packages/crypto/src/__tests__/*.test.ts` (TypeScript) load the same vectors. The `scripts/check-vector-parity.sh` meta-script verifies all vector files exist and are valid JSON.

## Common Patterns

### Async Testing (Vitest)

```typescript
it('should upload file', async () => {
  const result = await client.uploadFile(ipnsName, 'test.txt', content);
  expect(result.cid).toBeTruthy();
});
```

### Error Testing (Vitest)

```typescript
it('should reject duplicate vault init (409)', async () => {
  const res = await testFetch(`${API_URL}/vault/init`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ctx.accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ownerPublicKey: bytesToHex(ctx.publicKey), rootIpnsName }),
  });
  expect(res.status).toBe(409);
});
```

### Account Cleanup Pattern

All E2E tests use `afterAll` to clean up test accounts:

```typescript
afterAll(async () => {
  if (ctx) {
    ctx.cleanup(); // Destroy CipherBoxClient, zero key material
    await deleteTestAccount(ctx); // DELETE /auth/account
  }
});
```

### Batch Upload Unit Test Pattern

Tests for `uploadFiles()` use `setupBatchMocks()` + `setupFolder()` helpers and a `makeUploadResult()` factory:

```typescript
describe('CipherBoxClient.uploadFiles - batch upload orchestration', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('publishes only successful files on partial failure (D-09)', async () => {
    setupFolder(client);
    setupBatchMocks(5, [1, 3]); // files at index 1 and 3 fail
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

    const result = await client.uploadFiles('folder-ipns', makeTestFiles(5));

    expect(result.successes).toHaveLength(3);
    expect(result.failures).toHaveLength(2);
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });
});
```

### Page Object Model (Playwright)

```typescript
// tests/web-e2e/page-objects/file-browser/file-list.page.ts
export class FileListPage {
  constructor(private page: Page) {}
  get emptyState() {
    return this.page.locator('[data-testid="empty-state"]');
  }
  async getItemByName(name: string) {
    /* ... */
  }
}
```

---

<!-- Testing analysis: 2026-03-30 -->
