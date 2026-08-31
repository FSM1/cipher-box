<!-- generated-by: gsd-doc-writer -->

# Testing

CipherBox uses a multi-layer testing strategy documented in full in
[tests/TESTING_STRATEGY.md](../tests/TESTING_STRATEGY.md). This page summarises
the test landscape, shows how to run each suite, and maps tests to CI gates.

## Test Landscape

| Suite                        | Location               | Framework        | Trigger         |
| ---------------------------- | ---------------------- | ---------------- | --------------- |
| API unit tests               | `apps/api/`            | Jest             | PR to `main`    |
| `@cipherbox/crypto` unit     | `packages/crypto/`     | Vitest           | PR to `main`    |
| `@cipherbox/core` unit       | `packages/core/`       | Vitest           | PR to `main`    |
| `@cipherbox/sdk-core` unit   | `packages/sdk-core/`   | Vitest           | PR to `main`    |
| `@cipherbox/sdk` unit        | `packages/sdk/`        | Vitest           | PR to `main`    |
| `@cipherbox/api-client` unit | `packages/api-client/` | Vitest           | PR to `main`    |
| SDK E2E                      | `tests/sdk-e2e/`       | Vitest           | PR to `main`    |
| Web E2E                      | `tests/web-e2e/`       | Playwright       | Push to `main`  |
| Desktop mounted E2E          | `tests/desktop-e2e/`   | tsx orchestrator | Push to `main`  |
| Load tests                   | `tests/load/`          | Vitest (Node.js) | Manual dispatch |
| Cross-language vectors       | `tests/vectors/`       | JSON fixtures    | PR to `main`    |
| Rust crate tests             | `crates/`              | `cargo test`     | PR to `main`    |

## Running Unit Tests

### All workspace unit tests

```bash
pnpm test
```

This runs `test` in every workspace in parallel. It does not run E2E, load, or
desktop tests.

### Per-package unit tests

```bash
# API (Jest)
pnpm --filter @cipherbox/api test
pnpm --filter @cipherbox/api test:cov     # with coverage

# TypeScript packages (Vitest)
pnpm --filter @cipherbox/crypto test
pnpm --filter @cipherbox/crypto test:coverage

pnpm --filter @cipherbox/core test
pnpm --filter @cipherbox/core test:coverage

pnpm --filter @cipherbox/sdk-core test
pnpm --filter @cipherbox/sdk-core test:coverage

pnpm --filter @cipherbox/sdk test
pnpm --filter @cipherbox/sdk test:coverage

pnpm --filter @cipherbox/api-client test
pnpm --filter @cipherbox/api-client test:coverage
```

Watch mode is available on all Vitest packages:

```bash
pnpm --filter @cipherbox/crypto test:watch
```

### Rust crate tests

```bash
# macOS / Linux (FUSE)
cargo test --workspace --no-default-features --features fuse

# Windows (WinFsp)
cargo test --workspace --no-default-features --features winfsp
```

## Running SDK E2E Tests

SDK E2E tests (`@cipherbox/sdk-e2e`) drive `CipherBoxClient` directly against a
real API instance — no browser, no Playwright. See
[tests/TESTING_STRATEGY.md](../tests/TESTING_STRATEGY.md) for the full suite list
and rate-limit strategy.

### Prerequisites

- PostgreSQL, IPFS (Kubo), and Redis running locally
- `apps/api/.env` configured with `NODE_ENV=test` and the required database/IPFS
  variables (see `docs/CONFIGURATION.md`)
- `tools/mock-ipns-routing` built and running

```bash
# Build and start mock IPNS routing (npm, not pnpm — it is not a workspace member)
cd tools/mock-ipns-routing && npm ci && npm run build
node dist/index.js &

# Start the API in dev mode
pnpm --filter @cipherbox/api dev &

# Run the full SDK E2E suite
pnpm --filter @cipherbox/sdk-e2e test
```

Run a single suite by test-path pattern:

```bash
pnpm --filter @cipherbox/sdk-e2e test:single -- --testPathPattern=file-operations
```

## Running Web E2E Tests

Web E2E tests (`@cipherbox/web-e2e`) use Playwright against the full web app stack.
See [tests/web-e2e/README.md](../tests/web-e2e/README.md) for setup details.

```bash
# Full suite (headless Chromium)
pnpm test:web-e2e

# Headed mode
pnpm test:web-e2e:headed

# Inside the package directly
pnpm --filter @cipherbox/web-e2e test
pnpm --filter @cipherbox/web-e2e test:headed
pnpm --filter @cipherbox/web-e2e test:debug
```

The web-e2e suite requires all services running (PostgreSQL, IPFS, Redis, API,
mock-ipns-routing) and the web app built. The `CI=true` flag switches the reporter
to HTML, disallows `.only`, and always starts a fresh dev server.

## Running Desktop E2E Tests

The desktop mounted suite drives the real Tauri binary through the mount it
projects. One TypeScript orchestrator serves every platform; the v1 pair of
shell and PowerShell scripts is gone.

The binary must carry the `e2e-hook` cargo feature. That feature adds the
dev-key headless entry and a loopback control endpoint, and a shipping build
compiles neither.

```bash
pnpm --filter @cipherbox/desktop-e2e run test:e2e
```

The orchestrator starts the API and the desktop instances itself, so the
offline-replay scenario can take the API away and give it back. Postgres, Kubo
and the mock `/routing/v1` record store must already run. See
`tests/desktop-e2e/README.md` for the full local recipe.

The suite needs no test credential. A dev key is a fresh 32-byte scalar, and
challenge-signature login mints the account on first contact. The key crosses
on standard input, never in a process argument.

The unit suite over the orchestrator's pure helpers runs under `pnpm test` and
needs no stack.

## Running Load Tests

Load tests are managed by the `load-test.yml` workflow and are not meant to run
against production. See [tests/TESTING_STRATEGY.md](../tests/TESTING_STRATEGY.md)
for scenario descriptions and the rate-limit bypass design.

```bash
# Run a specific scenario locally (same prerequisites as SDK E2E)
LOAD_TEST_CLIENTS=5 pnpm --filter @cipherbox/load-tests test -- --testPathPattern=mixed-workload
```

Against staging, trigger via GitHub Actions → **Load Tests** workflow dispatch,
selecting the environment, client count, and scenario.

## Cross-Language Vector Parity

The `tests/vectors/` directory contains JSON test fixtures shared between the
TypeScript and Rust crypto implementations. The `vector-parity` CI job verifies
that both sides agree on the same inputs and outputs.

```bash
# Rust side
cargo test -p cipherbox-crypto --test cross_language --no-default-features

# TypeScript side
pnpm --filter @cipherbox/crypto test -- --reporter=verbose

# Meta-check (vector files exist, are valid JSON, and are referenced by both sides)
bash scripts/check-vector-parity.sh
```

Vector files: `crypto/aes-gcm.json`, `crypto/ecies.json`, `crypto/ed25519.json`,
`crypto/hkdf.json`, `crypto/ipns-name.json`, `core/vault-blob.json`,
`core/folder-metadata.json`, `core/ipns-record.json`, `core/bin-metadata.json`.

## Coverage

Coverage is collected on every CI run and uploaded to Codecov. The lcov files from
all covered packages are combined under separate flags (`api`, `crypto`, `core`,
`sdk-core`, `sdk`, `api-client`, `desktop`).

### Thresholds

| Package               | Lines | Branches | Functions | Statements          |
| --------------------- | ----- | -------- | --------- | ------------------- |
| `apps/api`            | 85%   | 78%      | 85%       | 85%                 |
| `packages/crypto`     | 80%   | 80%      | 80%       | 80%                 |
| `packages/core`       | 75%   | 75%      | 80%       | 75%                 |
| `packages/sdk-core`   | 80%   | 80%      | 80%       | 80%                 |
| `packages/sdk`        | 65%   | 80%      | 60%       | 65%                 |
| `packages/api-client` | 0%    | 0%       | 0%        | 0% (generated code) |

Rust coverage uses `cargo-llvm-cov` on the Linux CI runner and is uploaded under
the `desktop` flag. No numeric threshold is enforced for Rust.

## CI Gates

### `ci.yml` (pull requests to `main`)

Runs on every PR when `apps/`, `packages/`, `tests/`, or workflow files change.

- **lint** — ESLint across all TypeScript
- **typecheck** — full TypeScript build check
- **api-spec** — verifies the committed OpenAPI spec and generated client are current
- **migration-check** — detects entity/migration drift using TypeORM
- **test** — unit tests with coverage for all packages; uploads lcov to Codecov
- **sdk-e2e** — full SDK E2E suite against a live API instance
- **build** — production build of all packages and the web app
- **cargo-linux / cargo-macos / cargo-windows** — Rust check + test on all platforms
  (triggered only when Rust sources or `tests/vectors/` change)
- **vector-parity** — cross-language vector parity check (depends on `cargo-linux`
  and `test`)

### `ci-e2e.yml` (push to `main`)

Runs after merge to `main`. Detects which surface areas changed and invokes:

- `web-e2e.yml` — if `apps/web/`, `apps/api/`, `packages/`, or `tests/web-e2e/`
  changed
- `desktop-e2e.yml` — if `apps/desktop/`, `crates/` or `tests/desktop-e2e/` changed

### `web-e2e.yml`

Can also be triggered via `workflow_dispatch` or called from the staging release
pipeline. Runs the Playwright suite against a full stack on Ubuntu (headless
Chromium, 20-minute timeout). Uploads the Playwright report as an artifact on
failure.

### `desktop-e2e.yml`

A matrix over macOS and Linux, 45 minutes per leg. Each leg builds the debug
Tauri binary with the `e2e-hook` feature, provisions the stack, and runs the
mounted suite. The job name is `Desktop E2E (<platform>)`, and that name is the
branch-protection contract.

Windows joins the matrix once the Tauri shell projects the vault through the
WinFsp adapter. `apps/desktop/src-tauri/src/mount` builds the detached
projection on Windows today, so a Windows build makes no mount.

### `load-test.yml`

Manual dispatch only. Select target environment (`local` or `staging`), client
count, and scenario. Runs against the `staging` GitHub environment when staging is
selected; no numeric pass/fail threshold — results are interpreted manually.
