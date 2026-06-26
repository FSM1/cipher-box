---
phase: 54-e2e-test-infra-typing
plan: 01
subsystem: test-infra
tags: [tsconfig, typecheck, e2e, tooling, shared-helper]
requires: []
provides:
  - tsconfig.scripts.json (dedicated scripts typecheck config)
  - tests/e2e-helpers/auth.ts (authenticate, buildSdkContext, parseCliArgs)
  - tests/e2e-helpers/types.ts (AuthPayload)
  - root package.json typecheck step for E2E helper scripts
affects:
  - all Wave 2 .mjs->.ts script migrations consume the shared helper + tsconfig gate
tech-stack:
  added: []
  patterns:
    - tsx as runtime for .ts helpers (no build step; tsconfig is noEmit)
    - entrypoint imports (@cipherbox/*) resolved to built dist .d.ts via paths map
key-files:
  created:
    - tsconfig.scripts.json
    - tests/e2e-helpers/auth.ts
    - tests/e2e-helpers/types.ts
  modified:
    - package.json
decisions:
  - "Shared helper lives at tests/e2e-helpers/ as a bare directory (no package.json); Wave 2 imports via relative paths"
  - "AuthPayload.publicKeyHex kept optional so verify-filepointer's auth flow is preserved (D-07)"
  - "authenticate() validates only accessToken + privateKeyHex (publicKeyHex optional), matching the union of all 4 consumers"
metrics:
  duration: ~12m
  completed: 2026-06-20
requirements: [HARD-05]
---

# Phase 54 Plan 01: E2E Test-Infra Typing Foundation Summary

Established the typecheck gate and typed shared auth/ctx helper module that
unblock the Wave 2 `.mjs` to `.ts` E2E helper-script migrations: a dedicated
`tsconfig.scripts.json` wired last into the root `typecheck` chain (so consumed
dist is built before the helpers are checked), and a `tests/e2e-helpers/`
module exporting `authenticate`, `buildSdkContext`, and `parseCliArgs`.

## What Was Built

### Task 1: tsconfig.scripts.json + root typecheck wiring (D-03, D-02 companion)

- Created `tsconfig.scripts.json` at the repo root. It `extends`
  `./tsconfig.base.json`, sets `noEmit: true` and `moduleResolution: "bundler"`,
  and maps the four consumed entrypoints (`@cipherbox/sdk-core`,
  `@cipherbox/crypto`, `@cipherbox/api-client`, `@cipherbox/core`) to their built
  `dist/index.d.ts` via `paths` — this is the dist-staleness mechanism that
  surfaces entrypoint drift at tsc time.
- `include` covers all 5 helper-script locations plus the shared helper dir:
  `packages/sdk-core/scripts/*.ts`, `tests/desktop-e2e/scripts/*.ts`,
  `tests/web-e2e/staging-perf-wallet.ts`,
  `apps/desktop/src-tauri/generate-test-vectors.ts`, `tests/e2e-helpers/**/*.ts`.
- Appended ` && tsc -p tsconfig.scripts.json --noEmit` as the LAST step of the
  root `package.json` `typecheck` script, after the existing crypto -> core ->
  api-client -> sdk-core -> sdk -> web build chain (D-02 ordering preserved; no
  existing step reordered or removed).

### Task 2: Typed shared auth/ctx/arg helper (D-04)

- `tests/e2e-helpers/types.ts` exports `AuthPayload` with `accessToken: string`,
  `privateKeyHex: string`, and OPTIONAL `publicKeyHex?: string`.
- `tests/e2e-helpers/auth.ts` exports three functions, importing
  `createAxiosInstance` from `@cipherbox/api-client` and `type SdkContext` from
  `@cipherbox/sdk-core` (entrypoint imports, no dist-relative paths):
  - `authenticate(apiUrl, email, secret): Promise<AuthPayload>` — POSTs to
    `${apiUrl}/auth/test-login`, throws on non-ok with status+body, throws if
    `accessToken`/`privateKeyHex` missing. Endpoint path, method, header, body
    shape and error messages preserved verbatim.
  - `buildSdkContext(apiUrl, accessToken): SdkContext` — constructs an
    instance-scoped axios via `createAxiosInstance` and returns the ctx triple.
  - `parseCliArgs(argv): Record<string, string>` — Map-based `--key value`
    parser; throws on unexpected non-`--` tokens and missing values; throws if
    `--secret` is passed (TEST_SECRET must come from env). Security guard
    preserved verbatim.
- No `accessToken` or `privateKeyHex` is ever logged (T-54-01 mitigation).

### Task 3: eslint scope confirmation + foundation gate (D-03)

- Confirmed `eslint.config.js` already lints `**/*.{js,mjs,cjs,ts,tsx}`
  globally with no type-aware `parserOptions.project` wiring, so the new
  `tests/e2e-helpers/*.ts` are in scope automatically. NO eslint change was
  needed — D-03's "wire into eslint scope" is satisfied by the global glob.
- Built crypto -> core -> api-client -> sdk-core dist, then ran
  `tsc -p tsconfig.scripts.json --noEmit` (exit 0) and
  `eslint tests/e2e-helpers/auth.ts tests/e2e-helpers/types.ts` (pass).

## Verification Results

| Gate | Command | Result |
| ---- | ------- | ------ |
| Task 1 | `node -e` include/paths/noEmit/typecheck-suffix assertions | `ok` |
| Task 2 | grep assertions on exports/imports/contract/no-dist-relative | `ok` |
| Task 3 | build dist + `tsc -p tsconfig.scripts.json --noEmit` + eslint | `VERIFY_OK` |

## Exact Final Typecheck Script

```text
pnpm --filter @cipherbox/crypto build && pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/api-client build && pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build && pnpm --filter @cipherbox/web exec tsc -b && tsc -p tsconfig.scripts.json --noEmit
```

## ESLint Change

None. D-03 eslint scope was already satisfied by the global
`**/*.{js,mjs,cjs,ts,tsx}` glob in `eslint.config.js`. No type-aware
(`parserOptions.project`) wiring exists, so no config edit was required.

## Resolved Shared-Helper Location

`tests/e2e-helpers/` — a bare directory (no `package.json`, not a pnpm
workspace package). Wave 2 consumers import via relative paths, e.g.:

- `packages/sdk-core/scripts/*.ts` -> `../../../tests/e2e-helpers/auth`
- `tests/desktop-e2e/scripts/*.ts` -> `../../e2e-helpers/auth`

## Post-Merge Reconciliation (symbol-drift check)

This branch merged origin/main (Phase 51) before execution. Verified against
the CURRENT built dist (not the plan's pre-merge quoted context):

- `createAxiosInstance` IS exported from `@cipherbox/api-client`
  (`packages/api-client/dist/index.d.ts` line 1; config type `ApiClientConfig`
  with `baseUrl` + `getAccessToken` unchanged).
- `SdkContext` (type) IS exported from `@cipherbox/sdk-core`
  (`packages/sdk-core/dist/types.d.ts`; shape `{ apiUrl, getAccessToken,
  axiosInstance? }` unchanged).

No symbol-name drift. No deviation required.

## Deviations from Plan

None — plan executed exactly as written. Note: the lint-staged pre-commit
hook (prettier) reformatted `tests/e2e-helpers/auth.ts` to drop the trailing
comma in the `authenticate` parameter list; this is a cosmetic
formatting-only change and does not affect behavior or the verify gates.

Task 3 produced no committable source change (eslint required no edit; built
dist is gitignored), so it has no dedicated task commit — its verify gate
passed and its outcome is captured in this SUMMARY.

## Self-Check: PASSED
