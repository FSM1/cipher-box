# Phase 8: TEE Integration Learnings

**Date:** 2026-02-07

## Original Prompt

> /gsd:discuss-phase 8
> /gsd:plan-phase 8
> /gsd:execute-phase 8

Phase 8 was executed across multiple GSD sessions. The discuss phase gathered context on TEE integration (auto-republishing IPNS records via Phala Cloud), the plan phase produced 4 plans (08-01 through 08-04), and the execute phase built all 4 plans. Afterwards, `/security:review TEE implementation` identified critical integration bugs, and the user requested all findings be resolved along with CI failures on PR #61.

## What I Learned

### Security Review Findings

- **Encoding mismatches are silent killers.** The TEE worker returned public keys as hex, but the API decoded them with `atob()` (base64). This produced garbled bytes — no error thrown, just wrong data stored in DB. All downstream ECIES operations would fail. Always grep for `atob`/`btoa` and verify the source encoding matches.
- **Interface mismatches between services don't surface until runtime.** The API's `RepublishEntry` was missing `currentEpoch`/`previousEpoch` fields that the TEE worker expected. TypeScript can't catch this across HTTP boundaries. Integration tests or shared DTOs are essential.
- **Health endpoint response shape mismatches break initialization chains.** The TEE worker returned `{ status, mode, uptime }` but the API expected `{ healthy, epoch }`. `data.healthy` silently evaluated to `undefined` (falsy).
- **Private key zeroing needs try/finally, not just sequential code.** If an exception occurs between key use and `.fill(0)`, the key stays in memory. Always wrap in try/finally.
- **`crypto.timingSafeEqual` > custom XOR loop.** Node's stdlib is C-level constant-time; custom JS implementations can be optimized away by the JIT compiler.
- **Simulator mode with hardcoded seed is a deployment landmine.** `TEE_MODE` defaulted to `'simulator'` with no production guard. Anyone reading the source code could derive all keys.

### CI / Build Issues

- **NestJS projects need `tsconfig.build.json` to exclude spec files from `nest build`.** Without it, `nest build` compiles `.spec.ts` files, and Jest mock types (`mockResolvedValue`, `jest.Mock`) cause TS2339 errors. This is the default NestJS scaffold convention but was missing from this project.
- **`nest-cli.json` must reference `tsconfig.build.json`** via `compilerOptions.tsConfigPath`. Without this, `nest build` uses the default `tsconfig.json` which includes everything.
- **Jest mock typing approach matters for build vs test.** Using `jest.Mocked<Partial<Service>>` works fine under ts-jest (which has relaxed type checking) but fails under strict `tsc` compilation. The solution isn't to fix the types — it's to exclude spec files from the production build.
- **Coverage thresholds need to account for DI phantom branches.** NestJS constructor parameter assignments create Istanbul branch markers that can't be covered by tests. Lower per-file branch thresholds (e.g., 77% for vault.service.ts) rather than fighting uncoverable branches.

### Docker / Infrastructure

- **`127.0.0.1:port:port` in docker-compose only allows localhost access.** When the dev machine connects to a remote docker host over the network, Redis/services must bind to `0.0.0.0` (or omit the host binding). Use `${REDIS_PORT:-6380}:6379` for configurable external port.
- **Port conflicts with host services are common.** Using a non-default port (6380 vs 6379) for the project's Redis avoids conflicts with existing Redis servers. Make it configurable via env var.

### Testing Patterns

- **Mocking TypeORM repositories:** Use `getRepositoryToken(Entity)` with `useValue: { find: jest.fn(), save: jest.fn(), create: jest.fn() }`. For transactional tests, mock `DataSource.transaction` to call the callback with a mock manager whose `getRepository` returns entity-specific mocks.
- **Mocking `global.fetch`:** `jest.spyOn(global, 'fetch').mockResolvedValue(new Response(JSON.stringify(data)))`. Don't forget `signal` handling for timeout tests with `AbortController`.
- **`Date.now()` mocking for time-dependent tests:** `jest.spyOn(Date, 'now').mockReturnValue(timestamp)` — always restore in `afterEach`.
- **BullMQ processor testing:** Mock the Job object with `{ data: {...}, id: 'test', log: jest.fn() }`. Test the `process()` method directly.

## What Would Have Helped

- **A shared types package between API and TEE worker.** The `RepublishEntry` interface was defined independently in both codebases, leading to C1 (missing epoch fields). A `@cipherbox/shared-types` package would catch these at compile time.
- **Integration test that actually sends a republish batch from API to TEE worker.** Unit tests for each side passed independently, but the encoding mismatch (C2) and missing fields (C1) would only surface in an integration test.
- **`tsconfig.build.json` should have been created when first adding spec files.** This is standard NestJS practice but was missed during initial project setup.
- **The security review command (`/security:review`) should be run early in development**, not after CI is set up. Several critical bugs (C1, C2) were pure logic errors, not security issues per se — they just prevented the feature from working at all.

## Key Files

### TEE Worker

- `tee-worker/src/services/tee-keys.ts` — Key derivation (HKDF/CVM), epoch keypairs
- `tee-worker/src/services/key-manager.ts` — ECIES decrypt with epoch fallback
- `tee-worker/src/services/ipns-signer.ts` — Ed25519 IPNS record signing
- `tee-worker/src/routes/republish.ts` — Batch orchestration
- `tee-worker/src/routes/health.ts` — Health endpoint (must return `healthy` + `epoch`)
- `tee-worker/src/routes/public-key.ts` — Public key endpoint (returns hex)
- `tee-worker/src/middleware/auth.ts` — Bearer token auth (use `crypto.timingSafeEqual`)

### API TEE Module

- `apps/api/src/tee/tee.service.ts` — HTTP client for TEE worker
- `apps/api/src/tee/tee-key-state.service.ts` — Epoch state management (singleton row)
- `apps/api/src/tee/tee-key-state.entity.ts` — TeeKeyState entity
- `apps/api/src/tee/tee-key-rotation-log.entity.ts` — Rotation audit log

### API Republish Module

- `apps/api/src/republish/republish.service.ts` — 6-hour IPNS republish cycle
- `apps/api/src/republish/republish.processor.ts` — BullMQ job processor
- `apps/api/src/republish/republish-health.controller.ts` — Admin health stats

### Build Config

- `apps/api/tsconfig.build.json` — Excludes spec files from `nest build`
- `apps/api/nest-cli.json` — Must reference `tsconfig.build.json`
- `apps/api/jest.config.js` — Coverage thresholds (global + per-file overrides)

### Docker

- `docker/docker-compose.yml` — Redis on port 6380, bind to all interfaces for remote dev
