---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 10
subsystem: crypto
tags: [zeroization, sdk-core, ipns, e2e-scripts]

# Dependency graph
requires:
  - phase: 77-crypto-hygiene-and-terminology-canonicalization
    provides: "77-05 (TEE-wrap caller boundary edits to registration.ts, this plan runs after it in Wave 2)"
provides:
  - "createSubfolder zeroes its minted ipnsPrivateKey/readKey/writeKey on any seal/upload/publish throw"
  - "verify-filepointer.mts clears userPrivateKey and derived read keys before process exit"
affects: [crypto-hygiene-audits, sdk-core-key-lifecycle]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Error-path zeroization: try/catch around seal->upload->publish, zero minted keys only in catch, rethrow — mirrors createFileMetadata's existing pattern"
    - "E2E script key-clearing: try/finally around main() body with clearBytes() calls in finally — mirrors edit-filepointer.mts/rename-folder.mts"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
    - packages/sdk-core/scripts/verify-filepointer.mts

key-decisions:
  - "Error-path try/catch in createSubfolder wraps only sealNode/addToIpfs/createAndPublishIpnsRecord (steps 6-8), not the TEE-enrollment fail-closed gate (step 5) — matches the plan's must_haves scope exactly (sealNode/addToIpfs/createAndPublishIpnsRecord throw), keeping the change minimal and grep-verifiable."
  - "verify-filepointer.mts also clears vaultKeyBlob.rootWriteKey even though it is unused in this script's read-only flow — it is still loaded into memory by loadVaultKeyBlob and left in scope until exit, so it is cleared for parity with the sibling scripts and defense in depth."

requirements-completed: [SC1]

coverage:
  - id: D1
    description: "createSubfolder zeroes minted ipnsPrivateKey/readKey/writeKey when sealNode/addToIpfs/createAndPublishIpnsRecord throws; success path unchanged (D-09)"
    requirement: "SC1"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/folder.test.ts#createSubfolder (phase 63 — first-publish seq 1n) > zeroes the minted ipnsPrivateKey/readKey/writeKey when createAndPublishIpnsRecord throws (error path)"
        status: pass
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/folder.test.ts#createSubfolder (phase 63 — first-publish seq 1n) > does NOT zero minted keys before return (caller is terminal owner, D-09)"
        status: pass
    human_judgment: false
  - id: D2
    description: "verify-filepointer.mts clears userPrivateKey and derived read keys (rootReadKey/rootWriteKey/fileReadKey/subReadKey) in a finally block before exit"
    requirement: "SC1"
    verification:
      - kind: other
        ref: "pnpm --filter @cipherbox/sdk-core typecheck (script is in the typechecked scope, exits 0)"
        status: pass
    human_judgment: true
    rationale: "This script family has no automated test harness — verification is typecheck + source review, matching the sibling scripts' manual-only precedent (no unit tests exist for edit-filepointer.mts or rename-folder.mts either). A human smoke run against a local dev stack is optional per the plan's human-check note."

duration: 20min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 10: Error-Path Zeroization for createSubfolder and verify-filepointer.mts Summary

**Closed the last two owned-key error-path leaks in sdk-core: createSubfolder now zeroes its minted IPNS/read/write keys on any seal-upload-publish throw, and verify-filepointer.mts clears userPrivateKey plus derived read keys before exit.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-07-11T11:45:00Z
- **Completed:** 2026-07-11T11:50:19Z
- **Tasks:** 2 (1 TDD task with RED+GREEN commits, 1 auto task)
- **Files modified:** 3

## Accomplishments
- `createSubfolder` (`packages/sdk-core/src/folder/registration.ts`) now wraps `sealNode` -> `addToIpfs` -> `createAndPublishIpnsRecord` in try/catch; on throw it zeroes the minted `ipnsPrivateKey`, `readKey`, and `writeKey` before rethrowing. The success-path return and its "do NOT zero — caller is terminal owner, D-09" comment are unchanged.
- Added a forced-throw unit test to `folder.test.ts` that rejects `createAndPublishIpnsRecord` and asserts the three minted key buffers are all-zero afterward, alongside the pre-existing success-path "does NOT zero" test (both green).
- `verify-filepointer.mts` now imports `clearBytes` from `@cipherbox/crypto`, wraps its main body (from after the `vaultKeyBlob` load onward) in try/finally, and clears `userPrivateKey`, `vaultKeyBlob.rootReadKey`, `vaultKeyBlob.rootWriteKey`, and (when the `--folder-name` branch runs) `fileReadKey`/`subReadKey` in the finally block — bringing it to parity with `edit-filepointer.mts` and `rename-folder.mts`.

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Forced-throw zeroization test for createSubfolder** - `8076b4f0d` (test)
2. **Task 1 (GREEN): Zero minted keys on createSubfolder error path** - `de55fd24b` (feat)
3. **Task 2: Zeroize verify-filepointer.mts keys before exit** - `0a55b971e` (fix)

**Plan metadata:** (this commit) - docs: complete plan

## Files Created/Modified
- `packages/sdk-core/src/folder/registration.ts` - `createSubfolder` wraps seal/upload/publish in try/catch, zeroing minted keys only on the error path
- `packages/sdk-core/src/__tests__/folder.test.ts` - new forced-throw zeroization test for `createSubfolder`
- `packages/sdk-core/scripts/verify-filepointer.mts` - `clearBytes` import + try/finally clearing `userPrivateKey`/`vaultKeyBlob.rootReadKey`/`vaultKeyBlob.rootWriteKey`/`fileReadKey`/`subReadKey`

## Decisions Made
- Scoped the `createSubfolder` try/catch to exactly the three functions named in the plan's `must_haves.truths` (`sealNode`/`addToIpfs`/`createAndPublishIpnsRecord`), leaving the pre-existing TEE-enrollment fail-closed gate (step 5) outside the try — it already fails closed before any IPFS side effects and is out of this plan's stated scope.
- Cleared `vaultKeyBlob.rootWriteKey` in `verify-filepointer.mts` even though the script's read-only flow never uses it, since `loadVaultKeyBlob` still loads it into memory — clearing it matches the sibling scripts' behavior and closes the same class of leak defensively.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- All owned-key error-path leaks identified in the phase's crypto-hygiene audit (todos `2026-07-10-zeroize-createsubfolder-keys-on-error-path` and `2026-06-20-e2e-helper-scripts-zeroize-userprivatekey`) are now closed.
- `pnpm --filter @cipherbox/sdk-core test` (371 passed, 12 skipped) and `pnpm --filter @cipherbox/sdk-core typecheck` both green.

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*

## Self-Check: PASSED

All 3 modified files found on disk; all 3 task commits (`8076b4f0d`, `de55fd24b`, `0a55b971e`) verified present in git log.
