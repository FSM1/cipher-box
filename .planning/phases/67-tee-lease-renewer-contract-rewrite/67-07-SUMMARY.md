---
phase: 67-tee-lease-renewer-contract-rewrite
plan: "07"
subsystem: apps/api/republish
tags: [tee, ipns, relay, security, equality-cas, tdd]
dependency_graph:
  requires: [67-01]
  provides: [renewIpnsRecordEol, getDueEntries-joined, RepublishEntry-v2, enrollFolder-2arg]
  affects: [apps/api/src/tee/tee.service.ts, apps/api/src/republish/republish.service.ts, apps/api/src/republish/republish.service.spec.ts, apps/api/src/ipns/ipns.service.ts, apps/api/src/tee/tee.service.spec.ts]
tech_stack:
  added: []
  patterns: [TypeORM QB inner-join pairing, equality CAS write-back, TDD RED/GREEN]
key_files:
  created: []
  modified:
    - apps/api/src/tee/tee.service.ts
    - apps/api/src/republish/republish.service.ts
    - apps/api/src/republish/republish.service.spec.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/tee/tee.service.spec.ts
decisions:
  - "getDueEntries uses two-step QB (schedule innerJoin + record select) for testability while satisfying innerJoin grep requirement"
  - "renewIpnsRecordEol: affected===0 is harmless discard (not a throw) — forward-publish race and tombstone both map to the same discard path"
  - "teeKeyStateService no longer consulted in processRepublishBatch — epoch self-derived by TEE from encrypted key (D-03)"
  - "enrollFolder collapses to 2 args: signing columns live in ipns_records, not the schedule"
  - "api:generate NOT run: relay<->TEE interface is internal service-to-service; tee.controller.ts unchanged"
metrics:
  duration: 14m
  completed: "2026-07-01T00:55:08Z"
  tasks_completed: 3
  tasks_total: 3
  files_modified: 5
status: complete
---

# Phase 67 Plan 07: Relay Contract Rewrite — ipns_records as Sole Signing Source Summary

Reshaped the relay so the canonical `ipns_records` row is the sole source of the TEE's
signing inputs (D-02 / TEE-03) and hardened the EOL-only renewal write with an equality
CAS replacing the weak `LessThanOrEqual` write-back (§6.6 / TEE-04 carryover).

## Tasks Completed

### Task 1 (TDD RED): getDueEntries JOIN + teeEntries rebuild spec

Rewrote `republish.service.spec.ts` to reflect the new contract:

- Removed `createMockEntry` references to dropped schedule fields (`encryptedIpnsKey`,
  `keyEpoch`, `latestCid`, `sequenceNumber`) which 67-01 removed from the entity.
- Added `createMockRecord()` helper for `IpnsRecord` pairs.
- Set up QB mock chain: `scheduleQBMock` (innerJoin), `recordSelectQBMock`, and
  `recordUpdateQBMock` (renewIpnsRecordEol UPDATE).
- Added tests: innerJoin condition with tombstone+key filter, paired `{schedule, record}`
  return shape, tombstone-exclusion, teeEntries sourced from record (signedRecord,
  encryptedIpnsKey, keyEpoch — no latestCid/sequenceNumber/currentEpoch/previousEpoch).

Commit: `991afdbbc` — 27 tests failing (RED confirmed).

### Task 1+2 (TDD GREEN): Implement tee.service.ts + republish.service.ts

`tee.service.ts` — reshaped interfaces:

- `RepublishEntry`: removed `latestCid`, `sequenceNumber`, `currentEpoch`, `previousEpoch`;
  added `signedRecord: string` (base64 of `ipns_records.signed_record`).
- `RepublishResult`: added `requiresReEnroll?: true`.

`republish.service.ts` — full rewrite:

- `getDueEntries()` → `Promise<DueEntryPair[]>` using two-step QB:
  1. Schedule QB with `innerJoin(IpnsRecord, 'r', '... tombstoned_at IS NULL AND encrypted_ipns_private_key IS NOT NULL')` filter.
  2. Record QB with same tombstone+key filter on the matched names (race window guard).
  Returns `{ schedule, record }` pairs only.

- `processRepublishBatch()`:
  - Removed `teeKeyStateService.getCurrentState()` from batch path (D-03: TEE self-derives epoch).
  - Rebuilds `teeEntries` from `pair.record` (all signing inputs canonical).
  - `scheduleRepository.save()` writes ONLY scheduling fields (no crypto columns).
  - `requiresReEnroll` → log + `handleEntryFailure` (non-fatal, Phase 68/69).
  - Epoch upgrade → `ipnsRecordRepository.update({ipnsName}, {encryptedIpnsPrivateKey, keyEpoch})`.

- `renewIpnsRecordEol(ipnsName, loadedSeq, renewedSignedRecord)`:
  - Replaces `syncIpnsRecordSequence` and its `LessThanOrEqual` write-back.
  - QB UPDATE `signed_record` WHERE `sequence_number = :expected AND tombstoned_at IS NULL`.
  - `affected === 0` → log debug + return (forward-publish race or tombstone: harmless discard, no throw).
  - `affected > 0` → EOL renewal written (same CID, same seq, later EOL bytes).
  - Wrapped in try/catch: non-fatal, publish already succeeded.

- `enrollFolder(userId, ipnsName)`: collapsed to 2 args (scheduling-only).

Commit: `8daa66a16` — all 39 tests passing (GREEN confirmed).

### Task 3: enrollFolder 2-arg callers + api typecheck restoration

`ipns.service.ts` — two call sites updated:

- Existing-record path (line ~423): `enrollFolder(existing.userId, ipnsName)` — dropped
  `Buffer.from(encryptedIpnsPrivateKey!, 'hex')`, `keyEpoch!`, `metadataCid`, `newSeq`.
- New-record path (line ~459): `enrollFolder(userId, ipnsName)` — same drop.

`tee.service.spec.ts` — `sampleEntries` updated to new `RepublishEntry` shape
(added `signedRecord`; removed `latestCid`, `sequenceNumber`, `currentEpoch`, `previousEpoch`).

`apps/api tsc --noEmit` now shows only two pre-existing unrelated errors:

- `ipns-verify-cache.spec.ts:370` — TS2352 (pre-existing, unrelated to this phase)
- `http-metrics.interceptor.spec.ts:6` — TS2724 (pre-existing, unrelated to this phase)

All 9 republish-service and schedule-entity typecheck errors from 67-01 are resolved.

Commit: `a8ee5cece`

**api:generate NOT required.** The relay-TEE interface (`RepublishEntry`/`RepublishResult` in
`tee.service.ts`) is an internal service-to-service fetch via `TeeService.republish`. The
`tee.controller.ts` exposes only `connection-test` and was not modified. No public
`*.controller.ts` or `*.dto.ts` was changed. Confirmed: `git status --porcelain apps/api/src`
shows no modified controller or DTO files.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Buffer encoding mismatch in spec assertion**

- **Found during:** Task 1+2 GREEN verification
- **Issue:** Test assertion used `Buffer.from('renewed-signed-record', 'base64')` but the
  service correctly decodes the teeResult base64 back to UTF-8 bytes via
  `Buffer.from(result.signedRecord, 'base64')`. The assertion encoding was wrong.
- **Fix:** Changed to `Buffer.from('renewed-signed-record')` (UTF-8 bytes, not base64 decode).
- **Files modified:** `apps/api/src/republish/republish.service.spec.ts`
- **Commit:** included in `8daa66a16`

**2. [Rule 2 - Missing] Unused `In` import removed**

- **Found during:** Task 3 typecheck
- `import { Repository, In }` — `In` was unused after removing the old `getDueEntries` find.
- **Fix:** Removed `In` from the import.
- **Files modified:** `apps/api/src/republish/republish.service.ts`
- **Commit:** `8daa66a16`

## Known Stubs

None. All plan behaviors are fully wired.

## Threat Surface Scan

No new public network endpoints, auth paths, file access patterns, or schema changes were
introduced. The relay-TEE surface (`/republish` POST to internal TEE worker) narrows:
fewer fields sent (removed `latestCid`, `sequenceNumber`, `currentEpoch`, `previousEpoch`).

## Self-Check: PASSED

- FOUND: all 4 modified source files
- FOUND: commits 991afdbbc, 8daa66a16, a8ee5cece
- FOUND: renewIpnsRecordEol (3 occurrences in republish.service.ts)
- CONFIRMED: LessThanOrEqual removed (0 occurrences)
- CONFIRMED: syncIpnsRecordSequence removed (0 occurrences)
- 39/39 tests passing
- typecheck: only 2 pre-existing unrelated errors remain
