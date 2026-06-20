---
created: 2026-06-18
title: Migrate untyped .mjs E2E helper scripts to TypeScript
area: tooling
files:
  - packages/sdk-core/scripts/edit-filepointer.mjs
  - packages/sdk-core/scripts/rename-folder.mjs
  - packages/sdk-core/scripts/verify-filepointer.mjs
  - tests/desktop-e2e/scripts/test-move-content.mjs
  - tests/desktop-e2e/scripts/bump-ipns-sequence.mjs
  - tests/web-e2e/staging-perf-wallet.mjs
  - apps/desktop/src-tauri/generate-test-vectors.mjs
---

## Problem

A handful of E2E helper scripts are hand-written `.mjs` that import the built
SDK/crypto/api-client `dist/` bundles and drive real flows (publish, rename,
move, verify, sequence-bump). They are **not** typechecked, linted, or
unit-tested, and they import from `dist` rather than source — so they silently
drift from SDK contract changes and only break in desktop/web E2E (often only on
one OS) long after the breaking change merged.

Concrete recurrences:

- PR #488 → #495 broke `edit-filepointer.mjs` with a 400 (sdk-core API change
  not reflected in the untyped script).
- The decentralized signature-gated IPNS change (PR #509) broke the desktop
  conflict-detection helper: it POSTed a dummy unsigned record to bump the
  server sequence, which the new server correctly rejects with 400. It surfaced
  **only** on Windows (the `.ps1` `throw`s on a failed bump; the `.sh` swallowed
  it as a warning), 14 minutes into desktop E2E — never caught locally.

Because these scripts are skipped by `tsc`, `eslint`, vitest, and jest, every one
of these failures is invisible until a long E2E run on `main` (or a dispatched
ci-e2e) fails.

## Solution

TBD — migrate the helpers to TypeScript so they share the monorepo's type
safety and lint/test gates. Key design questions:

- **Compile vs. run-on-the-fly:** `tsx`/`ts-node` to execute `.ts` directly (no
  build step, simplest for CI invocation), vs. a small `tsconfig`/build that
  emits to a `dist` the runners invoke. `tsx` is likely the lowest-friction.
- **Import source, not dist:** importing `@cipherbox/sdk-core` / `@cipherbox/crypto`
  source (or their package entrypoints) so `tsc` catches contract drift at
  build/CI time instead of at E2E runtime. This is the core win — drop the
  `../dist/index.mjs` relative imports.
- **Typecheck/lint coverage:** ensure the migrated files are included in the
  relevant package `tsconfig` `include` globs and `eslint` scope so CI fails
  fast on drift. (Note: `apps/web` vitest `include` is `src/**/*.test.ts` — these
  helpers live outside `src`, so wiring them into a checked project matters.)
- **Cross-platform invocation:** the desktop `run-all.sh` / `run-all.ps1` and
  web runners invoke these via `node <file>.mjs`. Decide the new invocation
  (`tsx <file>.ts`) and update both the bash and PowerShell runners together.
- **Shared lib:** several scripts duplicate auth (`/auth/test-login`), `ctx`
  construction, and key derivation. Consider factoring a small typed helper
  module they all import.

## Why now / impact

Recurring, hard-to-debug CI failures that only appear in slow E2E runs on a
single OS. Typing these scripts converts a class of runtime E2E breakages into
fast, local `tsc`/`eslint` failures at the point the SDK contract changes.
