---
phase: 51-crypto-signature-secret-leak-hardening
plan: 01
subsystem: api/ipns
tags: [security, validation, tdd, ipns, s1]
dependency_graph:
  requires: []
  provides: [S1-embedded-vs-DTO-validation]
  affects: [apps/api/src/ipns/ipns.service.ts]
tech_stack:
  added: []
  patterns: [BadRequestException-400, offset-aware-sequence-tolerance, parseIpnsRecord-reuse]
key_files:
  created: []
  modified:
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.service.spec.ts
decisions:
  - CAS check (409) placed before S1 sequence check (400) so concurrent-modification errors remain authoritative
  - S1 reuses already-parsed incoming record from anti-rollback block to avoid double parse
  - first-publish tolerance accepts embedded seq offset of 0n or 1n from expectedSequenceNumber
metrics:
  duration: 9min
  completed: "2026-06-19T19:46:00Z"
  tasks_completed: 3
  files_modified: 2
---

# Phase 51 Plan 01: S1 Embedded-vs-DTO IPNS Publish Validation Summary

One-liner: BadRequestException (400) gate inside upsertFolderIpns rejecting signed records whose embedded CID or offset-aware sequence disagrees with the DTO, closing finding S1 (D-01) without touching the existing anti-rollback (409) or CAS (409) logic.

## What Was Built

S1 validation block inserted in `upsertFolderIpns` between the existing anti-rollback block and the metadataCid persist path:

1. **CID integrity gate**: Extracts the embedded CID from `incomingParsed.value` via regex `/\/ipfs\/([a-zA-Z0-9]+)/` and throws `BadRequestException` if it differs from the DTO `metadataCid`.

2. **Offset-aware sequence gate** (when `expectedSequenceNumber` provided):
   - First publish (`!existing`): accepts embedded sequence equal to `expectedSeqBigInt` or `expectedSeqBigInt + 1n` (0n or 1n when expectedSeq=0).
   - Subsequent publish: requires exactly `expectedSeqBigInt + 1n`.

3. **Parse efficiency**: `incomingParsed` is hoisted before the anti-rollback block; the anti-rollback block stores its parse result there. The S1 block only calls `parseIpnsRecord` for the first-publish path where anti-rollback did not run.

4. **CAS ordering**: The existing `ConflictException` (409) CAS check was moved to fire BEFORE S1 sequence check so concurrent-modification errors remain the authoritative signal.

## Test Results

- 79 tests total, 79 passed, 0 failed.
- New S1 tests (6 cases): CID mismatch 400, seq mismatch 400, first-publish 0n tolerance, first-publish 1n tolerance, valid pass-through, anti-rollback 409 regression guard — all green.
- All pre-existing tests pass after Rule 1 auto-fixes.

## Commits

| Hash | Message |
| --- | --- |
| acc397b63 | test 51-01: add failing S1 embedded-vs-DTO CID and offset-aware sequence tests (RED) |
| da7e2d2b8 | feat 51-01: implement S1 embedded-vs-DTO CID and offset-aware sequence validation (GREEN) |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] CAS ordering — moved before S1 sequence check**

- **Found during:** Task 2 GREEN
- **Issue:** S1 sequence check fired before the CAS (ConflictException 409) check, causing existing `conflict detection` tests to receive a 400 instead of a 409. The plan did not specify relative ordering between S1 and CAS.
- **Fix:** Moved CAS check to precede S1 so concurrent-modification 409s remain the primary rejection signal. S1 is now a secondary integrity gate after CAS passes.
- **Files modified:** `apps/api/src/ipns/ipns.service.ts`
- **Commit:** da7e2d2b8

**2. [Rule 1 - Bug] Pre-existing tests used `metadataCid: 'new-cid'` mismatching the default parseIpnsRecord mock**

- **Found during:** Task 2 GREEN
- **Issue:** Three tests in `upsertFolderIpns (tested through publishRecord)` and two conflict-detection batch tests passed non-CID test strings (`'new-cid'`, `'bafkreifile1'`, `'bafkreifile2'`) as `metadataCid` without aligning the `parseIpnsRecord` mock — previously harmless since no CID comparison existed. S1 now enforces this alignment.
- **Fix:** Updated those tests to use `testMetadataCid` (which the default mock already returns) or added `mockParseIpnsRecord` overrides returning matching values. Test behavior is semantically unchanged.
- **Files modified:** `apps/api/src/ipns/ipns.service.spec.ts`
- **Commit:** da7e2d2b8

## Known Stubs

None. S1 validation is fully wired; no placeholder logic.

## Threat Surface Scan

No new network endpoints, auth paths, or trust boundaries introduced. S1 is additive inline validation on an existing endpoint.

## Self-Check: PASSED

- `apps/api/src/ipns/ipns.service.ts` exists and contains `throw new BadRequestException` for embedded CID mismatch and sequence mismatch.
- `apps/api/src/ipns/ipns.service.spec.ts` exists with new S1 test cases.
- Commits acc397b63 and da7e2d2b8 exist in git log.
- 79/79 tests pass.
