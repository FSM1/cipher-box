---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 09
subsystem: crypto
tags: [base64, ipns, sdk-core, sdk, terminology-canonicalization]

# Dependency graph
requires:
  - phase: 77-crypto-hygiene-and-terminology-canonicalization (plan 01)
    provides: hoisted @cipherbox/crypto bytesToBase64/base64ToBytes codec
  - phase: 77-crypto-hygiene-and-terminology-canonicalization (plan 05)
    provides: file/index.ts TEE-wrap hex boundary (this plan edits the same file afterward)
provides:
  - file/index.ts base64 duplicate removed, now consumes @cipherbox/crypto codec
  - createFileMetadata return field and UploadResult field renamed to canonical encryptedIpnsPrivateKey
affects: [77-crypto-hygiene-and-terminology-canonicalization (remaining phase-close plans)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "In-memory IPNS-key wrap field is always named encryptedIpnsPrivateKey end-to-end (matches folder/registration.ts and vault/index.ts convention)"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/file/index.ts
    - packages/sdk-core/src/upload/index.ts
    - packages/sdk-core/src/__tests__/file/file-node.test.ts
    - packages/sdk-core/src/__tests__/upload.test.ts
    - packages/sdk/src/__tests__/helpers.ts
    - packages/sdk/src/__tests__/client-pinning.test.ts
    - packages/sdk/src/__tests__/client-extended.test.ts
    - packages/sdk/src/__tests__/upload-batch.test.ts
    - packages/sdk/src/__tests__/client-upload-concurrency.test.ts
    - packages/sdk/src/__tests__/owner-reconcile.test.ts

key-decisions:
  - "Retained ipnsPrivateKeyEncrypted only in packages/sdk/src/client.ts historical doc comments and landing/src/scripts/demo-data.ts, per plan's explicit out-of-scope list"
  - "Fixed an unrelated pre-existing test-mock gap (owner-reconcile.test.ts missing bytesToBase64 in its @cipherbox/crypto mock, introduced by sibling plan 77-08) because it blocked this plan's own `pnpm --filter @cipherbox/sdk test` verification gate"

patterns-established:
  - "Canonical field-name check: grep the whole repo src tree for the legacy token before declaring a rename complete; only doc comments / demo data may retain it"

requirements-completed: [SC2, SC3]

coverage:
  - id: D1
    description: "file/index.ts base64 duplicate removed; imports bytesToBase64/base64ToBytes from @cipherbox/crypto instead of local chunked implementation"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/file/file-node.test.ts (11 tests)"
        status: pass
    human_judgment: false
  - id: D2
    description: "createFileMetadata's return field and UploadResult's field renamed from ipnsPrivateKeyEncrypted to canonical encryptedIpnsPrivateKey, with all consuming test fixtures/assertions updated in lockstep"
    requirement: "SC2, SC3"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test (370 passed, 12 skipped)"
        status: pass
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (411 passed, 3 skipped)"
        status: pass
      - kind: other
        ref: "grep -rn ipnsPrivateKeyEncrypted packages/sdk-core/src packages/sdk/src/__tests__ (0 matches)"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 09: File-pipeline base64 dedup and encryptedIpnsPrivateKey rename Summary

**Removed the last base64 duplicate in `file/index.ts` (now consumes `@cipherbox/crypto`'s codec) and renamed the adjective-last `ipnsPrivateKeyEncrypted` field to the canonical `encryptedIpnsPrivateKey` on `createFileMetadata`'s return type and `UploadResult`, updating every sdk-core and sdk test fixture in lockstep.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-07-11T09:26:00Z
- **Completed:** 2026-07-11T09:38:40Z
- **Tasks:** 2
- **Files modified:** 11

## Accomplishments
- Local `bytesToBase64`/`base64ToBytes` pair in `packages/sdk-core/src/file/index.ts` removed; the two call sites (`fileIv` encoding, IPNS record/public-key base64) now import the shared, byte-identical codec from `@cipherbox/crypto`.
- `createFileMetadata`'s return type field and `UploadResult`'s field both renamed `ipnsPrivateKeyEncrypted` -> `encryptedIpnsPrivateKey`, eliminating the double-naming of the same wrapped-key value within `createFileMetadata` (it already built `ipnsRecord.encryptedIpnsPrivateKey` for the identical value).
- All consuming test fixtures/assertions across sdk-core and sdk updated to the canonical name, including the loose mock object in `sdk/src/__tests__/helpers.ts` and the cross-name parity assertion in `file-node.test.ts`.
- `packages/sdk-core` dist rebuilt before running `packages/sdk` tests (Pitfall 5), confirming the rename change propagated correctly across the package boundary.

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove the file/index.ts base64 duplicate (todo #6)** - `9883c2aae` (refactor)
2. **Task 2: Rename ipnsPrivateKeyEncrypted → encryptedIpnsPrivateKey across source + tests (todo #8)** - `afb038a7d` (refactor)

**Plan metadata:** (this commit) `docs(77-09): complete file-pipeline dedup and rename plan`

## Files Created/Modified
- `packages/sdk-core/src/file/index.ts` - removed local base64 codec, imports from `@cipherbox/crypto`; return-type field renamed to `encryptedIpnsPrivateKey`
- `packages/sdk-core/src/upload/index.ts` - `UploadResult.ipnsPrivateKeyEncrypted` -> `encryptedIpnsPrivateKey`, assignment updated
- `packages/sdk-core/src/__tests__/file/file-node.test.ts` - test names/assertions updated to canonical field; cross-name assertion now compares `result.ipnsRecord.encryptedIpnsPrivateKey` to `result.encryptedIpnsPrivateKey`
- `packages/sdk-core/src/__tests__/upload.test.ts` - mock return value and assertion updated to canonical field
- `packages/sdk/src/__tests__/helpers.ts` - loose mock `SealedChildRef`-adjacent fixture field renamed
- `packages/sdk/src/__tests__/client-pinning.test.ts` - two mock `uploadFile` return objects renamed
- `packages/sdk/src/__tests__/client-extended.test.ts` - two `sdkCore.uploadFile` mock resolves renamed
- `packages/sdk/src/__tests__/upload-batch.test.ts` - `makeUploadResult` helper field renamed
- `packages/sdk/src/__tests__/client-upload-concurrency.test.ts` - `setupUploadMocks` fixture field renamed
- `packages/sdk/src/__tests__/owner-reconcile.test.ts` - added missing `bytesToBase64` mock to its `@cipherbox/crypto` `vi.mock` (unrelated pre-existing gap surfaced by running the full sdk suite, see Deviations)

## Decisions Made
- Left `ipnsPrivateKeyEncrypted` untouched in `packages/sdk/src/client.ts` (historical doc comments at ~1632/3779/3905) and `landing/src/scripts/demo-data.ts` (untyped legacy v2 marketing JSON) — both explicitly out of scope per the plan.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed owner-reconcile.test.ts crypto mock missing bytesToBase64**
- **Found during:** Task 2 verification (`pnpm --filter @cipherbox/sdk test`)
- **Issue:** `packages/sdk/src/__tests__/owner-reconcile.test.ts` mocks `@cipherbox/crypto` with an explicit export list that omitted `bytesToBase64`. Plan 77-08 (a sibling Wave-1 plan already committed to this branch) rewired `packages/sdk-core/src/rotation/engine.ts`'s `reMintGrantsRootedAt` to call the hoisted `bytesToBase64` from `@cipherbox/crypto` instead of a local helper, but did not touch this test file's mock (it wasn't in 77-08's `files_modified` list). This caused `runOwnerReconcile > Test 3` to fail with "No bytesToBase64 export is defined on the mock" — unrelated to this plan's rename/dedup work, but it blocked this plan's own `pnpm --filter @cipherbox/sdk test` verification gate, which the plan requires to exit 0.
- **Fix:** Added `bytesToBase64: vi.fn((bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)))` to the existing `vi.mock('@cipherbox/crypto', ...)` call, matching the real implementation's output for small test byte arrays (the test's `EXPECTED_ENCRYPTED_KEY` fixture already assumed this encoding).
- **Files modified:** `packages/sdk/src/__tests__/owner-reconcile.test.ts`
- **Verification:** `pnpm --filter @cipherbox/sdk test` — 51 test files passed (was 50 passed / 1 failed), 411 tests passed / 3 skipped.
- **Committed in:** `afb038a7d` (Task 2 commit, bundled since it was required for that task's own verification to pass)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** The fix is test-infrastructure-only (a mock completeness gap from a sibling plan), touches no production code, and was necessary to satisfy this plan's own stated verification command. No scope creep into 77-08's actual deliverables.

## Issues Encountered
None beyond the deviation above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The file pipeline (`file/index.ts`, `upload/index.ts`) now uses the single `@cipherbox/crypto` base64 codec and the canonical `encryptedIpnsPrivateKey` name end-to-end, in-memory.
- `packages/sdk-core` and `packages/sdk` suites are both green against a freshly rebuilt sdk-core dist.
- Remaining phase 77 plans can proceed; no blockers introduced by this plan.

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*
