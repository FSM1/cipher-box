---
created: 2026-07-06
title: Promote the D-07 web/SDK boundary from a grep gate to an ESLint/CI rule
area: web
files:
  - apps/web/.eslintrc.cjs
  - scripts/check-web-sdk-boundary.sh
resolves_phase: 78
---

## Problem

Phase 68.2 (SDK-READ-04, D-07) enforces that `apps/web/src` makes zero runtime
imports of `@cipherbox/sdk-core` / `@cipherbox/core` (type-only `import type`
allowed) and no raw IPFS/IPNS access — everything routes through the
`@cipherbox/sdk` facade. This is currently a **manual grep gate** (commit
`19f40f040`). Zero violations at HEAD, so the mitigation is present, but nothing
pins it: a future web change could silently reintroduce a runtime
`@cipherbox/sdk-core`/`@cipherbox/core` import and only a human re-running the
grep would catch it.

Flagged as a non-blocking hardening advisory by the 68.2 security audit
(`68.2-SECURITY.md`).

## Solution

Promote the boundary to an enforced rule so CI fails on reintroduction:

- Add an ESLint `no-restricted-imports` (or `no-restricted-syntax` allowing
  `import type`) rule scoped to `apps/web/src` banning runtime imports of
  `@cipherbox/sdk-core` and `@cipherbox/core`, plus raw IPFS/IPNS client
  entrypoints.
- Alternatively/additionally, wire the existing grep gate into `ci.yml` so it
  runs on every PR rather than only when someone remembers.

Keep the `import type` allowance (type-only imports are erased and don't cross
the runtime boundary).
