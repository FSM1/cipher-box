---
phase: 63-read-chain-navigation-and-rotation-core
plan: 05
subsystem: sdk-core/rotation
tags: [scope-exit-predicate, hasCoveringGrant, zero-rotation-invariant, barrel-wiring, tdd, ROT-02, SC4]
status: complete

dependencies:
  requires:
    - 63-01: read-chain navigation walk (navigateReadChain)
    - 63-02: grant issuance and invite re-wrap (issueReadGrant, claimInviteReadKey)
    - 63-03: rotation engine (rotateReadFromNode, rotateOne, Phase-64 seams)
  provides:
    - hasCoveringGrant: pure predicate (D-08) — gates every delete/move/rename
    - maybeRotateOnScopeExit: gating composition with injectable deps.rotate
    - CoverageParams, ScopeExitResult, ScopeExitDeps types
    - Full sdk-core barrel: all Phase-63 public symbols importable from @cipherbox/sdk-core
  affects:
    - packages/sdk-core/src/rotation/scope.ts (new)
    - packages/sdk-core/src/__tests__/rotation/scope.test.ts (new)
    - packages/sdk-core/src/share/index.ts (new)
    - packages/sdk-core/src/rotation/index.ts (new)
    - packages/sdk-core/src/index.ts (modified)

tech-stack:
  added: []
  patterns:
    - TDD RED/GREEN (scope.test.ts written before scope.ts)
    - Injectable deps.rotate seam for vi.fn() spy in zero-rotation invariant test
    - String-literal union ScopeExitResult (no TypeScript enum)
    - Export-only barrel pattern (share/index.ts, rotation/index.ts excluded from coverage)
    - D-08 pure predicate — no I/O, no async, no durable state

key-files:
  created:
    - packages/sdk-core/src/rotation/scope.ts
    - packages/sdk-core/src/__tests__/rotation/scope.test.ts
    - packages/sdk-core/src/share/index.ts
    - packages/sdk-core/src/rotation/index.ts
  modified:
    - packages/sdk-core/src/index.ts

decisions:
  - hasCoveringGrant checks relay set AND localGrantRecord independently (either is sufficient) — not relay-only; anti-malicious-relay (T-63-17 / §3.9)
  - maybeRotateOnScopeExit invokes deps.rotate exactly once regardless of how many ancestors match
  - Barrel files are export-only; no logic placed in them (coverage exclusion correct for src/**/index.ts)
  - Separate share/index.ts and rotation/index.ts barrels; src/index.ts uses named re-exports matching existing barrel style

metrics:
  duration: 12m
  completed: 2026-06-29
  tasks_completed: 2
  files_created: 4
  tests_added: 15
---

# Phase 63 Plan 05: Scope-Exit Predicate and Barrel Wiring Summary

One-liner: `hasCoveringGrant` pure predicate + `maybeRotateOnScopeExit` gating helper in named `scope.ts` with injectable deps for the SC#4 zero-rotation invariant test; all Phase-63 public symbols wired into the sdk-core barrel.

## What Was Built

### Task 1: hasCoveringGrant predicate + maybeRotateOnScopeExit (TDD)

RED commit `fb134136f`: 15 failing tests in `scope.test.ts` covering:

- `hasCoveringGrant` pure predicate: empty ancestry, relay-only match, localGrantRecord-only match, both match, neither match, self-root, non-ancestor local record
- `maybeRotateOnScopeExit` zero-rotation invariant (SC#4 / ROT-02): inject `vi.fn()` as `deps.rotate`; assert called 0 times when no covering grant, called exactly once when covered
- Anti-malicious-relay (T-63-17): relay omits grant root, localGrantRecord covers ancestor → rotate fires once

GREEN commit `6ef8744c0`: `packages/sdk-core/src/rotation/scope.ts` implementing:

- `hasCoveringGrant({ nodeAncestorIpnsNames, activeGrantRootIpnsNames, localGrantRecord })` — pure boolean; iterates ancestry, checks relay Set + localGrantRecord; short-circuits at first match; no I/O, no async
- `maybeRotateOnScopeExit(params, deps)` — calls hasCoveringGrant; if false returns `'no-rotation'` without touching deps.rotate; if true invokes `deps.rotate()` once and returns `'rotated'`
- Types: `CoverageParams`, `ScopeExitResult` (`'no-rotation' | 'rotated'`), `ScopeExitDeps`

### Task 2: sdk-core barrel wiring

Commit `8a18bc8b4`:

- `packages/sdk-core/src/share/index.ts` — re-exports `navigateReadChain`, `NavigateResult`, `issueReadGrant`, `claimInviteReadKey`, `ReadGrantPayload`
- `packages/sdk-core/src/rotation/index.ts` — re-exports `rotateReadFromNode`, `rotateOne`, 4 Phase-64 seams, `RotationJobRecord`, `RotationStatus`, `RotationParams`, `hasCoveringGrant`, `maybeRotateOnScopeExit`, `CoverageParams`, `ScopeExitResult`, `ScopeExitDeps`
- `packages/sdk-core/src/index.ts` — named re-exports from `./share` and `./rotation`; all four key symbols (`navigateReadChain`, `issueReadGrant`, `rotateReadFromNode`, `hasCoveringGrant`) confirmed reachable via grep

## Acceptance Criteria Check

- `grep -c 'export function hasCoveringGrant' packages/sdk-core/src/rotation/scope.ts` = 1
- No I/O in scope.ts (grep for fetch/axios/ipnsController/resolveIpnsRecord = 0 matches)
- Zero-rotation invariant test: rotateSpy not called for no-covering-grant case
- Covered-case test: rotateSpy called exactly once
- No `enum ` in scope.ts
- scope.ts min_lines = 159 (requirement: 40)
- All 15 tests pass (GREEN)
- `pnpm --filter @cipherbox/sdk-core build` exits 0 (tsup + tsc typecheck)

## Deviations from Plan

None — plan executed exactly as written.

Minor implementation decisions within Claude's Discretion scope:

- `hasCoveringGrant` uses a single for-loop checking both relay set and localGrantRecord per iteration (rather than two separate passes) — short-circuits at first match for performance on hot delete/move/rename paths
- `maybeRotateOnScopeExit` returns the string-literal tag `'no-rotation' | 'rotated'` directly (not wrapped in an object) — matches the plan spec

## Known Stubs

None — all exported functions are fully implemented. The four Phase-64 seams are in engine.ts (Plan 03), not this plan; they are explicitly named throws, not silent stubs.

## Threat Flags

No new threat surface introduced beyond what is documented in the plan's threat model. The T-63-17 / T-63-18 / T-63-19 / T-63-20 mitigations are all implemented:

- T-63-17: hasCoveringGrant cross-checks localGrantRecord (not relay-only) — proven by test
- T-63-18: maybeRotateOnScopeExit gates on hasCoveringGrant — zero-rotation invariant proven by spy
- T-63-19: "defer rather than skip" policy documented as HOST responsibility (D-08 comment in scope.ts)
- T-63-20: barrel symbols confirmed reachable via grep + build typecheck

## Self-Check: PASSED

- scope.ts: FOUND at packages/sdk-core/src/rotation/scope.ts
- scope.test.ts: FOUND at packages/sdk-core/src/__tests__/rotation/scope.test.ts
- share/index.ts: FOUND at packages/sdk-core/src/share/index.ts
- rotation/index.ts: FOUND at packages/sdk-core/src/rotation/index.ts
- src/index.ts: modified (all four key symbols reachable)
- Commit fb134136f (RED test): FOUND
- Commit 6ef8744c0 (GREEN scope.ts): FOUND
- Commit 8a18bc8b4 (barrel wiring): FOUND
- All 15 tests pass
- Build exits 0
