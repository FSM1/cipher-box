---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 04
subsystem: sdk
tags: [ipns, write-plane, fail-closed, vitest, typescript]

requires:
  - phase: 72-sdk-write-plane-durability-and-correctness (plan 03)
    provides: deleteItem write-chain UUID trim, base-aware merge scaffolding
provides:
  - getWriteBodyParams (client.ts) throws on a genuine transient IPNS resolve
    miss when a real writeKey is present, instead of silently sealing an
    empty write-body
  - Identical fail-closed split mirrored into the bin/index.ts getWriteBodyParams twin
  - Unit test coverage for both copies' throw + two preserved fail-open paths
affects: [72-05, 72-08 (getWriteBodyParams dedupe)]

tech-stack:
  added: []
  patterns:
    - "Split a combined `!resolved || !x` fail-open condition into two branches when only one sub-condition is a genuine transient-miss signal — the other sub-condition (structurally-absent data) stays fail-open"

key-files:
  created:
    - packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/bin/index.ts

key-decisions:
  - "Exercised the private getWriteBodyParams via renameItem (client.ts) and addToBin (bin/index.ts) rather than loosening visibility, mirroring the existing delete-item.test.ts / client-write-plane-recovery.test.ts convention"
  - "Left the !resolved.published.writeSealed sub-case fail-open exactly as before (structurally never-write-capable folder is not a transient miss, per RESEARCH.md Pitfall 3 / Assumption A1)"

patterns-established:
  - "Fail-closed transient-miss throw carries the folder ipnsName + explicit cause in the error message, matching the T-68.1-01-03 fail-closed convention already used for unopenable write-bodies"

requirements-completed: [SC#2]

coverage:
  - id: D1
    description: "getWriteBodyParams (client.ts) throws when a real writeKey is present and resolvePublishedNode genuinely returns null (transient IPNS resolve miss), instead of returning writeChildren: []"
    requirement: "SC#2"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts#THROWS when a real writeKey is present and the resolve returns null (transient miss)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Both existing fail-open paths (zero/absent writeKey; resolved record with no writeSealed field) remain unchanged in client.ts"
    requirement: "SC#2"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts#does NOT throw when writeKey is zero/absent (read-only-device fallback, unchanged)"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts#does NOT throw when a real writeKey resolves to a record without writeSealed (never-write-capable, unchanged)"
        status: pass
    human_judgment: false
  - id: D3
    description: "The bin/index.ts getWriteBodyParams twin (addToBin) receives the identical fail-closed change and fails BEFORE the durable bin write (no orphaned bin entry), with the writeSealed-absent path staying fail-open"
    requirement: "SC#2"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts#THROWS when a real writeKey is present and the folder resolve returns null (transient miss)"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts#does NOT throw when a real writeKey resolves to a record without writeSealed (never-write-capable, unchanged)"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 04: SDK getWriteBodyParams fail-closed on transient resolve miss Summary

**Both `getWriteBodyParams` copies now throw on a genuine transient IPNS resolve miss when a real writeKey is present, instead of silently sealing an empty write-body that discards the entire write chain.**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-07-10T16:02:00+02:00 (approx, first RED commit 16:02:39+02:00)
- **Completed:** 2026-07-10T16:05:51+02:00
- **Tasks:** 2 completed
- **Files modified:** 3 (2 source, 1 new test)

## Accomplishments

- `packages/sdk/src/client.ts` `getWriteBodyParams`: split the combined `!resolved || !resolved.published.writeSealed` fail-open condition into two branches. `!resolved` (a genuine transient IPNS resolve miss) with a real (non-zero, 32-byte) writeKey present now THROWS a descriptive error naming the folder's `ipnsName` and the transient-miss cause. `!resolved.published.writeSealed` (a resolved record that structurally never had a write-body — pre-D-03) remains fail-open, returning `writeChildren: []` exactly as before.
- Mirrored the identical split, error message, and comment into the `packages/sdk/src/bin/index.ts` `getWriteBodyParams` twin (used by `addToBin`/`restoreFromBin`), preserving both copies' identical branching for Plan 08's future dedupe.
- New unit test file `packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts` (6 tests, all passing) covers: the fail-closed throw for both copies, the zero-writeKey read-only-device fallback (unchanged), and the resolved-without-writeSealed fail-open path (unchanged) for both copies.
- Full `@cipherbox/sdk` test suite green: 372 passed, 36 skipped, 0 failed (43 test files).

## Task Commits

Each task was committed atomically, RED before GREEN per the plan's TDD requirement:

1. **Task 1 (client.ts):**
   - `82b76a8f7` — `test(72-04): add failing fail-closed test for getWriteBodyParams transient miss` (RED)
   - `b83afe125` — `feat(72-04): fail closed on transient IPNS resolve miss in getWriteBodyParams` (GREEN)
2. **Task 2 (bin/index.ts twin):**
   - `4196c315a` — `test(72-04): add failing fail-closed test for bin/index.ts getWriteBodyParams twin` (RED)
   - `63187fef4` — `feat(72-04): mirror fail-closed transient-miss handling into bin/index.ts twin` (GREEN)

_TDD Gate Compliance: RED gate verified before each GREEN commit — ran the target test file, confirmed exactly one new failure (the throw case) with all other assertions already passing under the unmodified code, before implementing the fix._

## Files Created/Modified

- `packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts` (new) — 6 unit tests covering both `getWriteBodyParams` copies' fail-closed throw and both preserved fail-open paths
- `packages/sdk/src/client.ts` — `getWriteBodyParams` fail-closed split (Task 1)
- `packages/sdk/src/bin/index.ts` — `getWriteBodyParams` twin fail-closed split (Task 2)

## Decisions Made

- `getWriteBodyParams` is private in both copies, so each test case is exercised through a public method: `renameItem` for client.ts (calls `getWriteBodyParams(folder)` directly with no other write-plane side effects, keeping the mock call sequence easy to reason about against `reconcileFolderSequence`'s own `resolveIpnsRecord` pre-check), and `addToBin` for bin/index.ts (its own comment already documents that `getWriteBodyParams` is resolved BEFORE the durable bin write specifically so a throw here doesn't leave an orphaned bin entry — the new throw case's assertion that `addToIpfs`/`updateFolderMetadataAndPublish` are never called directly proves that ordering holds).
- Left the `!resolved.published.writeSealed` sub-case (structurally never-write-capable folder) fail-open exactly as before, per RESEARCH.md Pitfall 3 / Assumption A1's explicit resolution: only the genuine `!resolved` transient-miss branch fails closed.

## Deviations from Plan

**Documentation-accuracy note (not a code deviation):** the plan's premise (RESEARCH.md Pitfall 3, PATTERNS.md) states the two copies are "byte-for-byte identical" today. On inspection, this is true of their *behavior* and *branching structure* but not their literal source text: `client.ts` calls the private `resolvePublishedNode(folder.ipnsName)` helper (itself `resolveIpnsRecord` + `fetchFromIpfs` + `JSON.parse`), while `bin/index.ts` inlines those same three steps directly (it cannot call a private class method). This pre-existing structural difference was NOT introduced by this plan — the fail-closed change applied the identical error message and identical branch split to both, so the two copies' *logic* stays in lockstep for Plan 08's dedupe. Worth flagging for Plan 08: dedupe will need to either export `resolvePublishedNode` as a standalone helper or otherwise reconcile this call-site difference, not just the branching.

No other deviations — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC#2 fully delivered: both `getWriteBodyParams` copies fail closed on a transient resolve miss with a real writeKey, preserving both legitimate fail-open paths.
- Plan 08 (SC#6, getWriteBodyParams dedupe) should account for the `resolvePublishedNode`-helper vs. inlined-steps call-site difference noted above when consolidating the two copies into one.
- Full SDK unit suite green; no regressions introduced.

---
*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*

## Self-Check: PASSED

- FOUND: packages/sdk/src/__tests__/get-write-body-params-fail-closed.test.ts
- FOUND: packages/sdk/src/client.ts
- FOUND: packages/sdk/src/bin/index.ts
- FOUND commit: 82b76a8f7 (RED, Task 1)
- FOUND commit: b83afe125 (GREEN, Task 1)
- FOUND commit: 4196c315a (RED, Task 2)
- FOUND commit: 63187fef4 (GREEN, Task 2)
