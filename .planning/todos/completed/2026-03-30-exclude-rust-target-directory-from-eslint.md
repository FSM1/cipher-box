---
created: 2026-03-30T00:14:11.681Z
title: Exclude Rust target/ directory from ESLint
area: tooling
files:
  - eslint.config.js
  - apps/api/src/ipns/delegated-routing.client.spec.ts:60
---

## Problem

`pnpm lint:fix` (run as final step of `pnpm api:generate`) reports 262 problems, but 261 are false positives from Rust build artifacts in `target/`:

- `target/debug/build/cipherbox-desktop-*/out/__global-api-script.js` — Tauri codegen (4 errors)
- `target/doc/static.files/*.js` — rustdoc output (~150 errors: `no-undef` for rustdoc globals)
- `target/doc/search.index/*.js` — rustdoc search index (~20 errors)
- `target/doc/src-files.js`, `target/doc/search.index/**` — more rustdoc output

These are generated files that should never be linted. The `target/` directory is already in `.gitignore` but not in ESLint's ignore list.

The remaining 1 legitimate warning is `@typescript-eslint/no-explicit-any` in `delegated-routing.client.spec.ts:60`.

## Solution

1. Add `target/` to the `ignores` array in `eslint.config.js`
2. Optionally fix the single `no-explicit-any` warning in `delegated-routing.client.spec.ts:60`
3. Verify `pnpm lint:fix` exits cleanly after the change
