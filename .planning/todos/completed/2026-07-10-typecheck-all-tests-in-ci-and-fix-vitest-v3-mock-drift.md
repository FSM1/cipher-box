---
created: 2026-07-10
title: Typecheck all test files in CI and fix the pre-existing vitest-v3 Mock type drift
area: ci
files:
  - .github/workflows/ci.yml
  - package.json
  - packages/sdk-core/src/__tests__/cas.test.ts
  - packages/sdk-core/src/__tests__/share/grant.test.ts
  - packages/api-client/src/__tests__/instance.test.ts
  - packages/sdk/src/__tests__/
source: user directive during Phase 72 execution (2026-07-10) — "fix any pre-existing ts errors, do not just gloss over these" + "all tests should be typechecked as part of CI"
resolves_phase: 72
---

## Problem

CI's `pnpm typecheck` runs each package's `build` script (`tsc -p tsconfig.build.json`,
which **excludes** test files) plus `tsconfig.scripts.json` and `web tsc -b`. Test files
(`**/__tests__/**`, `*.test.ts`, `*.spec.ts`) are therefore **never typechecked in CI** —
vitest transpiles without typechecking and the production build excludes tests, so test-file
type drift is invisible to every gate. It has silently accumulated.

Inventory (via `pnpm --filter <pkg> exec tsc --noEmit`, which uses the base `tsconfig.json`
that DOES include tests):

- `@cipherbox/crypto`: 0
- `@cipherbox/core`: 0
- `@cipherbox/api-client`: 1 (`instance.test.ts` — `MockInstance` shape)
- `@cipherbox/sdk-core`: 50 (`cas.test.ts`, `share/grant.test.ts`)
- `@cipherbox/sdk`: ~12 files (per Phase 72 executor reports — enumerate exactly)
- `tests/sdk-e2e`, `tests/web-e2e`: clean (web-e2e verified clean during Phase 72)

Root cause is a **vitest v2 → v3 (`3.2.4`) `Mock` generics migration**: the tests use the old
`Mock<[Arg]>` single-type-arg form (now `Mock<(arg: T) => R>`) and untyped `vi.fn()` casts, so
`mockResolvedValue`/`mockResolvedValueOnce` are "not on type `Mock<Procedure> | (...)`"
(TS2339), `Mock<[Payload]>` trips TS2558 "expected 0-1 type args but got 2", and the resulting
`never` inference cascades (TS2322/TS2488).

## Solution

1. Migrate all failing test-file mock typings to the vitest v3 form (`Mock<(...args) => R>`,
   `vi.fn<...>()` / `vi.mocked()` where appropriate) until every package's
   `tsc --noEmit` (base tsconfig, tests included) is clean.
2. Add a per-package `typecheck` script that includes tests (e.g. `tsc --noEmit` against the
   test-inclusive tsconfig, or a `tsconfig.test.json`), and wire it into the root `typecheck`
   script so `pnpm typecheck` (already the CI `Typecheck` job) fails on ANY test-file type error.
3. Verify the CI `Typecheck` job now covers tests across every workspace (packages + `tests/*`).

Do this as the FINAL hardening pass of Phase 72 so it also covers the new phase test files
(`delete-item.test.ts`, `registration.test.ts`, `get-write-body-params-fail-closed.test.ts`,
`bin-operations.test.ts`, `maybe-republish-listing-cache.test.ts`, the zeroization it-block).
Relates to [[upload-batch-test-mock-type-drift]] (same drift class, already folded into 72-02).
