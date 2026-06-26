---
created: 2026-06-20
title: Remove hardcoded @types/node version from tsconfig.scripts.json typeRoots
area: test-infra
phase: 55-or-later
files:
  - tsconfig.scripts.json
---

## Problem

`tsconfig.scripts.json` (added in Phase 54 plan 01) pins a version-specific `typeRoots` entry:

```json
"typeRoots": [
  "./node_modules/@types",
  "./node_modules/.pnpm/@types+node@22.19.7/node_modules/@types"
]
```

The `@types+node@22.19.7` path will break the `tsc -p tsconfig.scripts.json --noEmit` step (wired into root `pnpm typecheck`) when `@types/node` is bumped.

## Why it was deferred (not fixed inline during Phase 54 ship)

The obvious fixes do NOT work in this pnpm layout (empirically tested):

- Removing `typeRoots` entirely → `error TS2688: Cannot find type definition file for 'node'` (pnpm does not hoist `@types/node` to root `node_modules/@types/`; there is no `node_modules/@types/node`).
- Glob `./node_modules/.pnpm/@types+node@*/node_modules/@types` → same TS2688 (TypeScript does not expand `*` in `typeRoots`).

There are 4 `@types/node` versions in the store (`12.20.55`, `20.19.37`, `22.7.5`, `22.19.7`); the config must point at a concrete one. The pin matches the lockfile-resolved version, so it is correct today, just fragile on upgrade.

## Solution

Robust fix is a small dependency change (out of Phase 54's low-risk scope): declare `@types/node` as a direct root devDependency so pnpm hoists `node_modules/@types/node`, then the standard `./node_modules/@types` entry resolves it with no version pin and the `.pnpm` line can be dropped. Validate the existing 4 versions don't conflict, then run `pnpm typecheck`. Alternatively, add a CI check that fails if the pinned version drifts from the lockfile.
