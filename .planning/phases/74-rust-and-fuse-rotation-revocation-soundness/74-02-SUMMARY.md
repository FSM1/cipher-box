---
phase: 74-rust-and-fuse-rotation-revocation-soundness
plan: 02
subsystem: crypto
tags: [typescript, rotation-engine, read-key-chaining, revocation, tdd, cross-language-parity]

# Dependency graph
requires:
  - phase: 74-rust-and-fuse-rotation-revocation-soundness
    provides: "RotatedNodeKey struct + RotateReadResult.rotated_nodes (Rust, plan 74-01) — the LOCKED field contract mirrored here"
provides:
  - "RotatedNodeKey type (packages/sdk-core/src/rotation/engine.ts)"
  - "RotateReadResult.rotatedNodes: Map<string, RotatedNodeKey> keyed by ipnsName"
  - "Per-node key population at the root commit branch and the BFS child commit branch inside rotateReadFromNode"
affects: [74-03-rust-and-fuse-rotation-revocation-soundness]

# Tech tracking
tech-stack:
  added: []
  patterns: ["Per-node result Map threaded at the two commit call sites, additive to the existing root-convenience RotateReadResult fields — mirrors the Rust twin's approach from 74-01"]

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/rotation/index.ts
    - packages/sdk-core/src/index.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts

key-decisions:
  - "RotatedNodeKey.sequenceNumber typed bigint, not the LOCKED-table's literal number — matches this file's existing IPNS sequence-number convention (RotateReadResult.sequenceNumber, CommittedRotation.newSequenceNumber are both bigint); using number would create an internal type inconsistency and cannot hold a real u64 IPNS sequence number safely"
  - "dirtyResumeResult (root-skipped-but-dirty-tail-recovered branch) threads the SAME live rotatedNodes Map reference rather than a fresh empty Map — required for TS to structurally satisfy the now-non-optional field; correctly reflects entries added by the shared BFS loop for any dirty-tail node committed via the normal (non-repair) path before the object is actually returned"
  - "repairDirtyNode's TS crash-resume checkpoint-repair path does NOT populate rotatedNodes — plan 74-02's task action/acceptance_criteria/must_haves scope this widening to exactly the root commit branch and the BFS child commit branch (unlike Rust 74-01, which additionally folded its repair_dirty_node hook in); documented as a known asymmetry, not a defect, since the plan's own gate is the two commit points"
  - "RotatedNodeKey exported from both the rotation barrel (rotation/index.ts) and the top-level sdk-core barrel (index.ts) alongside RotateReadResult, so external consumers can reference the type"

requirements-completed: [SC1]

coverage:
  - id: D1
    description: "RotateReadResult.rotatedNodes surfaces every rotated node's post-rotation read key (root, intermediate folder, leaf file), keyed by ipnsName, for a depth>=2 tree — TS twin of the Rust 74-01 widening"
    requirement: SC1
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/engine.test.ts#rotateReadFromNode — rotatedNodes deep-tree parity with Rust (Plan 74-02, SC1) > rotateReadFromNode surfaces every rotated node key for a deep tree"
        status: pass
    human_judgment: false
  - id: D2
    description: "No regression to the sdk-core rotation engine test suite after the additive widening"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test -- rotation/engine (370/370 passing, including 57 in engine.test.ts)"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-11
status: complete
---

# Phase 74 Plan 02: Deep Scope-Exit Key Surfacing (TS Engine Parity) Summary

**Widened the TS `RotateReadResult` with a `rotatedNodes: Map<string, RotatedNodeKey>` field, field-for-field parity with the Rust twin landed in 74-01, so the TS rotation engine surfaces every rotated node's post-rotation read key at the root commit and BFS child commit points.**

## Performance

- **Duration:** ~12 min
- **Completed:** 2026-07-11
- **Tasks:** 2 (TDD: RED + GREEN)
- **Files modified:** 4 (`engine.ts`, `rotation/index.ts`, `index.ts`, `engine.test.ts`)

## Accomplishments

- Added `RotatedNodeKey` type (`ipnsName: string`, `readKey: Uint8Array`, `generation: number`, `sequenceNumber: bigint`) to `packages/sdk-core/src/rotation/engine.ts` — the TS twin of Rust `RotatedNodeKey` (`crates/sdk/src/rotation/engine.rs`, plan 74-01), matching the LOCKED cross-language contract field-for-field with one deliberate type deviation (see Decisions).
- Added `RotateReadResult.rotatedNodes: Map<string, RotatedNodeKey>` additively — the existing top-level `readKey`/`generation`/`sequenceNumber` root-convenience fields are unchanged.
- Populated the map at the two commit points the plan specifies:
  1. The root commit branch (`rotateReadFromNode`'s "Normal path: root just committed in this run" `else` branch), keyed by `rootNodeIpnsName`.
  2. The BFS child commit branch (`if (!result.skipped) { ... }` inside the frontier walk), keyed by `item.childRef.ipnsName`.
- Both `RotateReadResult` return sites (the fresh-commit return and the dirty-resume-republish `dirtyResumeResult`) now carry the same live `rotatedNodes` Map reference, so TypeScript's structural typing is satisfied and the dirty-resume path correctly reflects whatever the shared BFS loop populated by the time it is actually returned.
- Added a new Vitest test, `rotateReadFromNode surfaces every rotated node key for a deep tree`, seeding a 3-node tree (root → folderB → fileC, each a distinct IPNS name) via the existing mock-deps pattern from the file's other `rotateReadFromNode` tests, and asserting all three levels appear in `rotatedNodes` with distinct 32-byte post-rotation keys, mirroring the Rust 74-01 test's structure and assertions.
- Exported `RotatedNodeKey` from both `packages/sdk-core/src/rotation/index.ts` and the top-level `packages/sdk-core/src/index.ts` barrels, alongside `RotateReadResult` (Rule 2 — the type would otherwise be unreachable to external consumers).

## Task Commits

Each task was committed atomically (TDD RED → GREEN):

1. **Task 1 (RED): Failing deep-tree parity test in engine.test.ts** — `09e22d5d8` (test)
2. **Task 2 (GREEN): Widen TS RotateReadResult + populate at both commit points** — `391aeaa56` (feat)

_TDD gate sequence verified in git log: `test(74-02)` commit precedes `feat(74-02)` commit._

## Files Created/Modified

- `packages/sdk-core/src/rotation/engine.ts` — `RotatedNodeKey` type, `RotateReadResult.rotatedNodes` field, population at the root/BFS-child commit branches, threaded into both return sites.
- `packages/sdk-core/src/rotation/index.ts` — export `RotatedNodeKey`.
- `packages/sdk-core/src/index.ts` — export `RotatedNodeKey`.
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — new deep-tree parity test describe block.

## Decisions Made

- **`sequenceNumber: bigint`, not `number`.** The plan's LOCKED contract table lists `RotatedNodeKey.sequenceNumber` as TS `number` (a literal translation of Rust's `u64`). Every other IPNS sequence number in this exact file — the existing `RotateReadResult.sequenceNumber`, `CommittedRotation.newSequenceNumber`, `ParentTrackingState.parentLastSeq` — is `bigint`. Using `number` for the nested map entry while the sibling top-level field stays `bigint` would be an internal inconsistency and cannot safely represent a real 64-bit IPNS sequence number. Treated as a Rule 1 (bug) fix to the plan's table, not a deviation from its intent.
- **`dirtyResumeResult` threads the live `rotatedNodes` reference.** Making `rotatedNodes` a required field on `RotateReadResult` means the dirty-resume-skip branch's object literal must also satisfy the type. Since that branch falls through into the same shared BFS `while` loop before the object is actually returned, passing the same `Map` instance (not a copy) is both type-correct and behaviorally sound — the caller sees whatever got populated by the time the function actually returns.
- **`repairDirtyNode`'s crash-resume path is out of scope for TS in this plan**, unlike Rust 74-01 which folded its `repair_dirty_node` hook into `rotated_nodes` as part of the same plan. Plan 74-02's task action, acceptance_criteria, and must_haves explicitly scope the widening to "the root commit branch and the BFS child commit branch" only — no mention of the checkpoint-repair path. This is a real (documented) asymmetry with Rust, left as a candidate for a future follow-up plan rather than silently expanded scope here.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `RotatedNodeKey.sequenceNumber` typed `bigint` instead of the plan table's literal `number`**
- **Found during:** Task 2 (widening `RotateReadResult`)
- **Issue:** The plan's LOCKED cross-language field contract table lists TS `sequenceNumber: number`, a direct (but incorrect for this codebase) translation of Rust's `u64`. Every other sequence-number field in `engine.ts` is `bigint` (matches IPNS's actual 64-bit sequence numbers and this file's established convention).
- **Fix:** Typed `RotatedNodeKey.sequenceNumber` as `bigint`, matching the existing `RotateReadResult.sequenceNumber`/`CommittedRotation.newSequenceNumber` convention.
- **Files modified:** `packages/sdk-core/src/rotation/engine.ts`
- **Verification:** `pnpm --filter @cipherbox/sdk-core typecheck` passes; new test asserts `result.sequenceNumber === rootEntry.sequenceNumber` (both `bigint`) without a type error.
- **Committed in:** `391aeaa56` (Task 2 commit)

**2. [Rule 2 - Missing Critical] Exported `RotatedNodeKey` from both barrels**
- **Found during:** Task 2
- **Issue:** The plan only specified adding the type to `engine.ts`; without a barrel export it would be structurally present on `RotateReadResult.rotatedNodes` but unnameable by external consumers (`packages/sdk`, future FUSE callers).
- **Fix:** Added `type RotatedNodeKey` to `rotation/index.ts` and the top-level `index.ts` export lists, alongside the existing `RotateReadResult` export.
- **Files modified:** `packages/sdk-core/src/rotation/index.ts`, `packages/sdk-core/src/index.ts`
- **Verification:** `pnpm --filter @cipherbox/sdk-core typecheck` passes.
- **Committed in:** `391aeaa56` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 bug fix to the plan's field-type table, 1 missing-critical export)
**Impact on plan:** Both fixes necessary for internal type consistency and external usability of the new type. No scope creep — the population scope (root + BFS-child commit points only, no `repairDirtyNode`) was followed exactly as the plan's task action/acceptance_criteria specify.

## Issues Encountered

None. The RED test failed at runtime with a genuine assertion error (`expected undefined to be an instance of Map`) rather than a type error, since Vitest transforms via esbuild without full type-checking — still a valid RED per the plan's `<verify>` (`! pnpm --filter @cipherbox/sdk-core test -- rotation/engine`).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `RotatedNodeKey`/`RotateReadResult.rotatedNodes` (TS) is now at explicit field-for-field parity with the Rust twin from 74-01 (`ipnsName`↔`ipns_name`, `readKey`↔`read_key`, `generation`↔`generation`, `sequenceNumber`↔`sequence_number` — bigint/u64 both 64-bit).
- Known asymmetry for a future plan to consider: Rust's `repair_dirty_node` crash-resume hook populates `rotated_nodes`; TS's `repairDirtyNode` does not (out of scope for 74-02 per its own task action). If a future FUSE/desktop caller (74-03 or later) needs post-repair keys surfaced from a dirty-resume run, this gap should be closed then.
- `packages/sdk` (`client.ts`) consumes `RotateReadResult.readKey`/`sequenceNumber`/`generation` only — no consumer breakage from the additive `rotatedNodes` field; `pnpm --filter @cipherbox/sdk-core typecheck` and the scoped rotation test suite (370/370) both green.
- No blockers.

---
*Phase: 74-rust-and-fuse-rotation-revocation-soundness*
*Plan: 02*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: packages/sdk-core/src/rotation/engine.ts
- FOUND: .planning/phases/74-rust-and-fuse-rotation-revocation-soundness/74-02-SUMMARY.md
- FOUND commit: 09e22d5d8 (test RED)
- FOUND commit: 391aeaa56 (feat GREEN)
