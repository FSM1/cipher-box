---
phase: 80-rotation-write-plane-and-re-mint-durability
plan: 03
subsystem: testing
tags: [rotation, zeroization, ts-rust-parity, owner-reconcile, memoization]

# Dependency graph
requires:
  - phase: 74-rotation-deep-scope-exit
    provides: RotateReadResult.rotatedNodes deep-tree key surfacing (SC1) that this hardens
provides:
  - "TS rotation engine stores a defensive 32-byte copy of every rotatedNodes readKey (non-aliased with parentNewReadKey) — Rust Zeroizing-clone parity (D-04)"
  - "buildGrantRemintCallbacks memoizes listSentGrants() per reconcile pass — bounds the O(nodes × shares) fan-out to <=1 fetch (D-02 TS mirror)"
affects: [80-07-owner-reconcile-getPinsFn, rotation, fuse-inode-refresh]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Defensive Uint8Array copy at the collection boundary (rotatedNodes.set) while the live parentNewReadKey reference is left untouched for the seal walk"
    - "Closure-scoped promise memo inside a callbacks-builder factory (per-pass cache, never global/static)"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts
    - packages/sdk/src/share/owner-reconcile.ts
    - packages/sdk/src/__tests__/owner-reconcile.test.ts

key-decisions:
  - "Defensive copy applied at the rotatedNodes.set() readKey ONLY; parentNewReadKey/parentOldReadKey left as live references (D-04, Pattern 4)"
  - "Cache is a closure-scoped `let cachedGrants: Promise<GrantRow[]>` populated via `??=` — scoped to one buildGrantRemintCallbacks bundle, verified to re-fetch on a fresh bundle"

patterns-established:
  - "Pattern 4 (rotatedNodes ownership): the returned map owns independent key copies so a future zero-on-drop of parentNewReadKey cannot corrupt consumer-visible keys"

requirements-completed:
  - "SC3 / D-04: TS rotatedNodes stores a defensive 32-byte copy of readKey (no aliasing with parentNewReadKey), matching Rust parity"
  - "SC2-perf / D-02 (TS mirror): queryGrantsFn caches listSentGrants() across calls within one reconcile pass"

coverage:
  - id: D1
    description: "TS rotation engine stores a non-aliased, non-zero 32-byte copy of every rotatedNodes readKey (root, BFS child, dirty-resume repair), matching Rust's Zeroizing-clone (D-04)"
    requirement: "SC3 / D-04: TS rotatedNodes stores a defensive 32-byte copy of readKey (no aliasing with parentNewReadKey), matching Rust parity"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#D-04: each rotatedNodes readKey is a non-aliased, non-zero copy (mutating parentNewReadKey does not affect the entry)"
        status: pass
    human_judgment: false
  - id: D2
    description: "buildGrantRemintCallbacks caches listSentGrants() per reconcile pass — <=1 fetch across multiple queryGrantsFn calls, closure-scoped (not global), per-node rootNodeId filtering unchanged (D-02 TS)"
    requirement: "SC2-perf / D-02 (TS mirror): queryGrantsFn caches listSentGrants() across calls within one reconcile pass"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#Test 1b: listSentGrants is fetched at most once across multiple queryGrantsFn calls, filtering stays correct per node"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#Test 1c: the cache is scoped per buildGrantRemintCallbacks call — a fresh callbacks bundle re-fetches (no global/static cache)"
        status: pass
    human_judgment: false

# Metrics
duration: 15min
completed: 2026-07-12
status: complete
---

# Phase 80 Plan 03: Rotation-key ownership + sent-grants memo Summary

**TS rotation engine now stores non-aliased 32-byte defensive copies of every rotatedNodes readKey (Rust Zeroizing-clone parity, D-04), and the owner-reconcile driver memoizes listSentGrants() per pass to bound the fan-out to a single fetch (D-02 TS).**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-07-12T20:00:00Z
- **Completed:** 2026-07-12T20:05:00Z
- **Tasks:** 2 (both TDD)
- **Files modified:** 4

## Accomplishments

- Applied `new Uint8Array(...)` defensive copy at both aliasing `rotatedNodes.set()` sites — root branch (`rootResult.childReadKey`) and BFS child branch (`result.childReadKey`). The third site (dirty-resume repair, ~:1817) already copied `readKeyPrime`, so all three now own independent buffers. `parentNewReadKey`/`parentOldReadKey` left untouched.
- Added an engine regression test proving each rotatedNodes readKey is a distinct object from `result.readKey` (the retained parentNewReadKey alias), is non-zero, equals the correct new key, and survives a simulated zero-on-drop of the parent reference.
- Introduced a closure-scoped `cachedGrants` promise memo in `buildGrantRemintCallbacks` (`??=` populate-once), leaving the per-node `rootNodeId` filter unchanged.
- Added two owner-reconcile tests: single-fetch across multiple `queryGrantsFn` calls with correct per-node filtering, and a fresh-bundle-re-fetches test proving the cache is not global/static.

## Task Commits

Committed as a single commit per execution constraint (code + tests + SUMMARY together):

1. **Task 1: defensive 32-byte copy at every rotatedNodes.set readKey (D-04)** — engine.ts + engine.test.ts
2. **Task 2: cache listSentGrants() per reconcile pass (D-02 TS)** — owner-reconcile.ts + owner-reconcile.test.ts

## Files Created/Modified

- `packages/sdk-core/src/rotation/engine.ts` — defensive `new Uint8Array(...)` copy at root (:2060) and BFS child (:2234) rotatedNodes.set readKey sites
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — D-04 non-aliasing/non-zero/correct-value regression test
- `packages/sdk/src/share/owner-reconcile.ts` — closure-scoped `cachedGrants` memo wrapping `transport.listSentGrants()`
- `packages/sdk/src/__tests__/owner-reconcile.test.ts` — single-fetch cache assertion + per-pass-scope assertion

## Decisions Made

- Defensive copy at the collection boundary only; the live `parentNewReadKey` reference the walk uses to seal children is deliberately left aliasing `childReadKey` (matches the plan's Pattern 4 and Rust's structure). No Rust change — Rust already clones into `Zeroizing<[u8;32]>`.
- Memo implemented with `let cachedGrants: Promise<GrantRow[]> | undefined` + `??=`, caching the promise (not the awaited value) so concurrent first-callers share one in-flight fetch.

## Deviations from Plan

None - plan executed exactly as written. (The dirty-resume `rotatedNodes.set` at ~:1817 flagged by the plan's grep instruction already used a `new Uint8Array(readKeyPrime)` defensive copy and required no change.)

## Issues Encountered

- Scoped test runs initially failed with vite `Failed to resolve entry for package "@cipherbox/core"` / `@cipherbox/api-client` — stale/absent workspace dists. Resolved as setup by building `@cipherbox/core`, `@cipherbox/api-client`, `@cipherbox/crypto`, `@cipherbox/sdk-core` (dist-staleness only; no code impact).
- Prettier flagged one wrapping in the new engine test assertion; fixed via `prettier --write` and re-verified with eslint + a re-run of the test suite.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- 80-07 will add `getPinsFn` to the same `buildGrantRemintCallbacks` builder (sequential, same file) — the memo pattern is now established there for it to extend.

---
*Phase: 80-rotation-write-plane-and-re-mint-durability*
*Completed: 2026-07-12*
