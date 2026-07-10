---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 07
subsystem: sdk
tags: [typescript, sdk-write-plane, dead-code-removal, moveInSharedFolder]

# Dependency graph
requires:
  - phase: 72-sdk-write-plane-durability-and-correctness
    provides: "Plan 01's rewritten move-in-shared-folder.test.ts reachable-path regression gate; Plan 06's prior write-plane hardening"
provides:
  - "moveInSharedFolder with the unreachable legacy share-keys branch and its Ed25519-as-AES wrong-key bug deleted"
  - "moveInSharedFolder signature slimmed: getShareKeysFn parameter removed"
  - "Both apps/web moveInSharedFolder call sites updated to the new signature"
affects: [sdk-write-plane, shared-folder-move]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Refactor-under-test: Plan 01 seeded a live regression test for the reachable branch specifically so this dead-branch deletion could be verified, not refactor-blind"

key-files:
  created: []
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/move-in-shared-folder.test.ts
    - apps/web/src/hooks/useSharedWriteOps.ts

key-decisions:
  - "Updated the Plan 01 test file's call site and doc comment (not in the plan's file list but required for the SDK to compile/typecheck after the signature change) — the test literally passed the now-removed getShareKeysFn arg"
  - "Left fetchShareKeys in share.service.ts untouched — still used by resolveFileIpnsKey in useSharedWriteOps.ts and imported there"

requirements-completed: [SC#5]

coverage:
  - id: D1
    description: "Unreachable moveInSharedFolder legacy share-keys branch (Ed25519-as-AES wrong-key bug) and its getShareKeysFn parameter deleted from packages/sdk/src/client.ts"
    requirement: "SC#5"
    verification:
      - kind: unit
        ref: "grep -c 'shareKeys.length > 0' packages/sdk/src/client.ts == 0"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/move-in-shared-folder.test.ts (reachable-path gate)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Both apps/web moveInSharedFolder call sites (useSharedWriteOps.ts) updated to drop the removed getShareKeysFn arg; web app typechecks"
    requirement: "SC#5"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/web exec tsc -b"
        status: pass
    human_judgment: false

duration: 8min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 07: Remove unreachable moveInSharedFolder legacy branch Summary

**Deleted the dead Ed25519-as-AES-key legacy branch and getShareKeysFn parameter from moveInSharedFolder, updating both the SDK's own reachable-path regression test and the two apps/web call sites in the same change.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-07-10T14:49:38Z
- **Completed:** 2026-07-10T14:52:04Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Deleted the unreachable `shareKeys.length > 0` legacy branch in `CipherBoxClient.moveInSharedFolder` (packages/sdk/src/client.ts), which contained a latent bug assigning an Ed25519 `ipnsPrivateKey` as an AES `destWriteKey` — this branch could never execute because its sole producer (`fetchShareKeys`) hard-returns `[]`.
- Removed the now-unused `getShareKeysFn` callback parameter from the method signature and its stale "retained for backward compatibility" doc comment; the reachable one-hop write-chain branch is retained unchanged (dedented, no behavior change).
- Updated both `apps/web/src/hooks/useSharedWriteOps.ts` call sites (single move + batch move loop) to drop the removed `getShareKeysFn` argument, matching the new SDK signature. `fetchShareKeys` import stays — still consumed by `resolveFileIpnsKey` in the same file.

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove the unreachable moveInSharedFolder legacy branch and its callback param** - `1cbcf92fb` (fix)
2. **Task 2: Drop the removed arg from both apps/web moveInSharedFolder call sites** - `2a2b225db` (fix)

**Plan metadata:** (this commit)

## Files Created/Modified
- `packages/sdk/src/client.ts` - Deleted the dead legacy share-keys branch and `getShareKeysFn` param from `moveInSharedFolder`; retained reachable write-chain branch
- `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` - Dropped the now-removed `getShareKeysFn` arg from its call site and rewrote the two-branch doc comment to describe the single remaining reachable branch
- `apps/web/src/hooks/useSharedWriteOps.ts` - Both `moveInSharedFolder` call sites (single-item move, batch-move loop) drop the removed arg

## Decisions Made
- Modified `move-in-shared-folder.test.ts` even though it wasn't in the plan's `files_modified` list, because it directly called the old signature with `getShareKeysFn: async () => []` — required for the SDK package to typecheck/build after Task 1's signature change (Rule 3, blocking issue).
- Kept `fetchShareKeys` in `share.service.ts` fully intact per the plan's explicit scope boundary (documented historical stub, out of the locked 9-todo scope).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated move-in-shared-folder.test.ts call site to match the new signature**
- **Found during:** Task 1 (removing getShareKeysFn from client.ts)
- **Issue:** The Plan 01 regression test still called `client.moveInSharedFolder(SHARE_ID, { ..., getShareKeysFn: async () => [] })` — an excess-property TypeScript error against the new type, which would break `pnpm --filter @cipherbox/sdk build`'s `tsc -p tsconfig.build.json` step even though vitest's untyped transform ran it fine at runtime.
- **Fix:** Removed the `getShareKeysFn` line from the test's call site and rewrote the file's header doc comment (previously describing "two branches") to describe the single reachable branch that now exists.
- **Files modified:** packages/sdk/src/__tests__/move-in-shared-folder.test.ts
- **Verification:** `pnpm --filter @cipherbox/sdk exec vitest run src/__tests__/move-in-shared-folder.test.ts` and `pnpm --filter @cipherbox/sdk build` (tsup + tsc) both pass clean
- **Committed in:** `1cbcf92fb` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary to keep the SDK package compiling after the signature change; no scope creep — the fix was scoped to the exact call site broken by Task 1's own change.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- SC#5 fully delivered: the latent Ed25519-as-AES wrong-key branch is gone, `moveInSharedFolder`'s public surface is slimmer, and both SDK (`pnpm --filter @cipherbox/sdk test`, 389 passed / 36 skipped) and web (`pnpm --filter @cipherbox/web exec tsc -b`) gates are green.
- No blockers for subsequent Phase 72 plans.

---
*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*

## Self-Check: PASSED
All modified files and commit hashes verified present on disk / in git log.
