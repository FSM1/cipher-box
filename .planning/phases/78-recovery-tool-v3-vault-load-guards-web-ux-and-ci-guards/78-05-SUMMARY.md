---
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
plan: 05
subsystem: ci-lint-boundary
tags: [eslint, ci, d-07, web-sdk-boundary, sc3a]
requires:
  - eslint.config.js (existing flat config)
  - pnpm lint CI job (existing, runs `eslint .`)
provides:
  - D-07 web/SDK import boundary enforced by ESLint in CI
affects:
  - apps/web/src/** (lint-enforced import/call boundary)
tech-stack:
  added: []
  patterns:
    - "@typescript-eslint/no-restricted-imports with allowTypeImports for a type-only exemption"
    - "no-restricted-syntax CallExpression callee-name selector for name-based bans"
key-files:
  created: []
  modified:
    - eslint.config.js
decisions:
  - "allowTypeImports correctly flags mixed imports (type Foo, bar) — no ImportDeclaration fallback selector needed (RESEARCH A1 resolved)."
metrics:
  duration: ~10m
  completed: 2026-07-12
status: complete
---

# Phase 78 Plan 05: D-07 Web/SDK Boundary ESLint Rule Summary

Promoted the D-07 web/SDK import boundary from a bespoke manual grep gate to a scoped ESLint flat-config block wired into the existing `pnpm lint` CI job, so a forbidden sdk-core/core runtime import or raw IPFS call now fails lint on every PR.

## What Was Built

A new flat-config object appended to `eslint.config.js`, scoped to `apps/web/src/**/*.{ts,tsx}` (ignoring `apps/web/src/**/__tests__/**`):

- **Gate A** — `@typescript-eslint/no-restricted-imports` (`error`) with a `patterns` group `['@cipherbox/sdk-core', '@cipherbox/core']`, `allowTypeImports: true`, and a message directing to the `@cipherbox/sdk` facade. Bans runtime imports of sdk-core/core; keeps `import type` allowed and keeps the `@cipherbox/sdk` facade allowed.
- **Gate B** — `no-restricted-syntax` (`error`) with selector `CallExpression[callee.name=/^(fetchFromIpfs|addToIpfs|unpinFromIpfs)$/]` — the name-based raw-IPFS-call check the import rule cannot cover.

Enforced by the existing `"lint": "eslint ."` script (confirmed in `package.json`) already present in the CI lint job — no new CI wiring needed.

## Fixture Verification (Task 2)

Throwaway fixtures were created under `apps/web/src`, linted with `npx eslint`, then deleted (not committed). Results:

| Case | Fixture | Expected | Result |
| ---- | ------- | -------- | ------ |
| (a) runtime import | `import { getSdkClient } from '@cipherbox/sdk-core'` | fail | EXIT=1 (fails) |
| (b) mixed import | `import { type Foo, bar } from '@cipherbox/sdk-core'` | fail | EXIT=1 (fails) |
| (c) pure type import | `import type { Foo } from '@cipherbox/core'` | pass | EXIT=0 (passes) |
| (d) raw IPFS call | `fetchFromIpfs('cid')` | fail | EXIT=1 (fails) |

**RESEARCH A1 / Assumption resolved:** `allowTypeImports` correctly still flags the mixed-import case (b) because `bar` is a runtime binding — the `ImportDeclaration` fallback selector contemplated in RESEARCH was NOT needed. No fixture files remain (`git status --porcelain apps/web/src` is empty).

**No legacy grep gate script survives:** `grep -rl "fetchFromIpfs|addToIpfs|unpinFromIpfs" scripts .github/workflows` returned nothing — the D-07 gate lived as a manual/PLAN grep command, not a checked-in script, so there was nothing to delete. CI `pnpm lint` now enforces the boundary.

## Clean-Tree Verification

`pnpm lint` exits 0 on the current clean tree (2 pre-existing `no-explicit-any` warnings in `apps/api/.../unpin-helpers.spec.ts`, unrelated and out of scope). The new rule flags no existing legitimate code.

## Deviations from Plan

None — plan executed exactly as written. Task 2 required no code change because `allowTypeImports` handled the mixed-import case, so the contemplated fallback selector was unnecessary. Task 2 is therefore verification-only with no additional commit.

## Acceptance Criteria

- [x] `no-restricted-imports` + `no-restricted-syntax` present in the apps/web/src-scoped block
- [x] `allowTypeImports` present (type-only imports allowed)
- [x] `pnpm lint` exits 0 on the clean tree
- [x] Forbidden runtime import, mixed import, and raw IPFS call all fail lint; pure `import type` passes
- [x] No throwaway fixtures remain; no legacy grep gate script survives
- [x] CI `pnpm lint` (`eslint .`) enforces the boundary

## Commits

- `5f1f37bde` — ci: enforce D-07 web/SDK import boundary via eslint

## Self-Check: PASSED

- FOUND: eslint.config.js (scoped D-07 block present)
- FOUND: commit 5f1f37bde
