---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 01
subsystem: testing
tags: [vitest, sdk, node-v3, aes-gcm, write-chain]

# Dependency graph
requires:
  - phase: 68.1
    provides: write-body model (node/v3 read/write chain, SealedChildRef/WriteChildRef)
provides:
  - Live, non-skipped regression test of moveInSharedFolder's reachable write-chain branch
affects: [72-07-plan (dead-branch removal depends on this gate)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Real crypto fixtures over mocked crypto: use @cipherbox/core's sealNode/unsealNode/sealChildReadKey/sealChildWriteKey to build genuine AAD-bound envelopes in unit tests rather than mocking wrapKey/unwrapKey, when the code path under test never calls ECIES wrap/unwrap"
    - "Distinct ipnsName vs childId fixture values as a structural guard against UUID-vs-ipnsName write-chain confusion bugs"

key-files:
  created: []
  modified:
    - packages/sdk/src/__tests__/move-in-shared-folder.test.ts

key-decisions:
  - "Did not modernize the 13 legacy describe.skip tests (they exercise the branch Plan 07 deletes); replaced with one focused live test of the reachable branch per RESEARCH Critical Finding 3 guidance"
  - "No @cipherbox/crypto mock needed — the reachable write-chain branch never calls wrapKey/unwrapKey (that's legacy-branch-only), so only sdk-core's network seams (resolveIpnsRecord/fetchFromIpfs/addToIpfs/createAndPublishIpnsRecord) are mocked"

patterns-established:
  - "SC#5 regression gate: moveInSharedFolder reachable branch now has a live green test that will survive Plan 07's dead-branch removal"

requirements-completed: [SC#5]

coverage:
  - id: D1
    description: "moveInSharedFolder's reachable (non-legacy) code path has a live, non-skipped unit test exercising a real intra-shared-folder move, with the destination write link keyed by node UUID (childId) rather than ipnsName"
    requirement: "SC#5"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/move-in-shared-folder.test.ts#CipherBoxClient.moveInSharedFolder -- reachable write-chain branch (68.1-20) > moves an item into a direct-child destination via the write chain, keying the destination write link by node UUID (childId), never by ipnsName"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 01: Establish moveInSharedFolder Reachable-Branch Regression Gate Summary

**Rewrote the 100%-skipped `move-in-shared-folder.test.ts` into one live test that drives `moveInSharedFolder`'s reachable write-chain branch with real AES-GCM AAD-bound seal/unseal from `@cipherbox/core`.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-07-10T12:33:00Z
- **Completed:** 2026-07-10T12:53:23Z
- **Tasks:** 1 completed
- **Files modified:** 1

## Accomplishments

- `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` no longer contains any `describe.skip` — the file now runs 1 live, passing, non-skipped test (was: 13 tests, 13 skipped)
- Removed all imports of retired core types (`FolderChild`, `FilePointer`, `FolderEntry`) — the file no longer references them anywhere, including in comments
- New test builds a genuine node/v3 write-chain fixture (source shared folder with a destination subfolder + a moved item as read/write-body children) using real `sealNode`/`sealChildReadKey`/`sealChildWriteKey`, then invokes `CipherBoxClient.moveInSharedFolder` with `getShareKeysFn: async () => []` to route into the reachable (non-legacy) branch
- Test decodes the actual published DEST and SOURCE envelopes (via `unsealNode` with the fixture's real keys) after the move and asserts the destination's new `WriteChildRef.childId` equals the moved item's node UUID and is explicitly NOT equal to its ipnsName — the fixture uses genuinely different values for the two so a UUID-vs-ipnsName confusion in the write-chain filter cannot silently pass
- Also asserts publish ordering (DEST before SOURCE, dup-not-orphan) and that the source's write-body/read-body entries for the moved item are both fully removed while the untouched destination-folder reference remains

## Task Commits

Each task was committed atomically:

1. **Task 1: Rewrite move-in-shared-folder.test.ts to cover the reachable branch** - `6baee7d08` (test)

**Plan metadata:** (this commit, docs: complete plan)

## Files Created/Modified

- `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` - Rewritten from 13 fully-skipped legacy tests to 1 live test of the reachable write-chain branch

## Decisions Made

- Did not un-skip or modernize the 13 legacy tests — they exercise the `shareKeys.length > 0` legacy branch that Plan 07 deletes; modernizing dead-branch tests would be wasted effort per 72-RESEARCH.md Critical Finding 3 guidance ("un-skipping and modernizing all 13 existing tests is likely too large for this phase")
- Chose real crypto (`sealNode`/`unsealNode`/`sealChildReadKey`/`sealChildWriteKey`) over mocking `@cipherbox/crypto`, mirroring `update-shared-single-file.test.ts`'s pattern, since the reachable branch performs zero `wrapKey`/`unwrapKey` calls (those live only in the legacy branch) — this makes the test a genuine end-to-end proof of the AAD-bound write-chain hop, not just a mock-call assertion
- Only mocked the sdk-core network transport seams (`resolveIpnsRecord`, `fetchFromIpfs`, `addToIpfs`, `createAndPublishIpnsRecord`) — everything else (crypto, `buildSharedWriteContext`, the stateless `shareOps.moveInSharedFolder` op, `adoptSharedFolderResult`) runs for real

## Deviations from Plan

None - plan executed exactly as written. One self-correction during execution: the initial draft's doc-comment prose used the literal strings `describe.skip` and `FolderChild`/`FilePointer`/`FolderEntry` when describing what was removed, which made the acceptance-criteria grep counts (which grep the whole file, not just code) return 1 instead of 0. Reworded the comment to describe the same facts without those literal substrings before committing — no functional change, verified both grep counts return 0 and the test still passes after the edit.

## Issues Encountered

`git commit` appeared to hang for the full 2-minute Bash timeout (known 1Password SSH-signing false-negative per project memory). Verified via `git log --oneline -3` that the commit landed cleanly (`6baee7d08`) before proceeding — did not retry or force an unsigned commit.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC#5's regression gate is live and green against the CURRENT `client.ts` (dead legacy branch still present) — Plan 07 can now safely delete the `shareKeys.length > 0` branch and this test will catch any regression to the reachable branch's UUID-keyed write-chain logic
- `pnpm --filter @cipherbox/sdk exec tsc --noEmit -p .` was run to confirm no new typecheck errors were introduced by this file; all pre-existing errors reported belong to unrelated sibling test files (documented drift, see project MEMORY.md "SDK helper scripts drift" / "mock drift" entries) and are out of scope for this plan

---

*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*

## Self-Check: PASSED

- FOUND: `.planning/phases/72-sdk-write-plane-durability-and-correctness/72-01-SUMMARY.md`
- FOUND: `packages/sdk/src/__tests__/move-in-shared-folder.test.ts`
- FOUND: commit `6baee7d08`
