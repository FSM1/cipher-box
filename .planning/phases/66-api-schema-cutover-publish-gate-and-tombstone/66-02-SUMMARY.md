---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "02"
subsystem: api/ipns
tags: [atomic-cas, tombstone, ipns, tee, publish-gate, generation-gate, seq-floor]
status: complete

dependency_graph:
  requires: [66-01]
  provides: [atomic-cas-publish, tombstone-state-machine, seq-floor-discriminant]
  affects: [ipns-service, ipns-controller, ipns-record-codec, publish-dto]

tech_stack:
  added: []
  patterns:
    - TypeORM createQueryBuilder().update() atomic conditional UPDATE
    - Discriminated union return type for parseCachedRecord
    - HttpException with HttpStatus.GONE for 410 typed body flowing through api:generate

key_files:
  created:
    - apps/api/src/ipns/dto/tombstone-ipns.dto.ts
  modified:
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns-record.codec.ts
    - apps/api/src/ipns/ipns.controller.ts
    - apps/api/src/ipns/dto/publish.dto.ts
    - apps/api/src/ipns/dto/index.ts

decisions:
  - "Atomic CAS WHERE uses CAST(:incoming AS bigint) rather than ::bigint shorthand to avoid TypeORM parameter-parser confusion"
  - "generation and expectedSequenceNumber both default to stored values when omitted for backward-compat unconditional publish paths"
  - "parseCachedRecord returns SeqFloor interface (not a discriminant string) for clean TypeScript narrowing via 'seqFloor' in r"
  - "tombstoneRecord calls unenrollIpns unconditionally after the UPDATE (idempotent; avoids orphaned schedule rows)"

metrics:
  duration: "928s (~15 min)"
  completed: "2026-06-30"
  tasks_completed: 3
  tasks_total: 3
  files_modified: 6
---

# Phase 66 Plan 02: Atomic CAS Publish Gate and Tombstone State Machine Summary

Atomic CAS publish (TEE-04), forward-only generation gate (TEE-07), tombstone state machine (WRITE-04), and parseCachedRecord seq-floor discriminant (TEE-05) wired and building clean on the ipns surface.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Atomic CAS publish gate (seq + generation + tombstone) | 6cde81c10 | ipns.service.ts, publish.dto.ts |
| 2 | Tombstone state machine — tombstoneRecord, POST /ipns/tombstone, 410 disambiguation | 340258ebe | ipns.service.ts, ipns.controller.ts, tombstone-ipns.dto.ts, dto/index.ts |
| 3 | parseCachedRecord case-split (seqFloor discriminant) + resolveRecord handling | 2f5141b99 | ipns-record.codec.ts, ipns.service.ts |

## What Was Built

### Task 1 — Atomic CAS publish

Replaced the non-atomic `findOne → in-memory CAS → save` in `upsertIpnsRecord` with a single `createQueryBuilder().update(IpnsRecord)` whose WHERE clause fuses all four predicates:

```
ipns_name = :ipnsName
AND sequence_number = :expected
AND generation <= CAST(:incoming AS bigint)
AND tombstoned_at IS NULL
```

`result.affected === 0` triggers exactly one follow-up `findOne` to distinguish 410 (tombstoned) from 409 (stale seq / generation regression). The first-publish INSERT path is unchanged. Added optional `generation` field to `PublishIpnsDto` and `PublishIpnsEntryDto`.

### Task 2 — Tombstone state machine

Added `IpnsService.tombstoneRecord(userId, ipnsName)`: atomic UPDATE setting `tombstoned_at = NOW()` scoped to `user_id = :userId` (V4 access control), followed by `republishService.unenrollIpns`. Added `TombstoneIpnsDto` and `POST /ipns/tombstone` endpoint. The 0-row CAS disambiguation in Task 1 throws `HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE)` when `tombstonedAt` is set. `resolveRecord` checks `cached?.tombstonedAt` and throws the same 410 before calling `parseCachedRecord`. Both `publishRecord` and `resolveRecord` carry `@ApiResponse({ status: 410, ... })` decorators so the marker flows through `api:generate` (D-07).

### Task 3 — parseCachedRecord case-split

Changed `parseCachedRecord` return type from `IpnsRecordFields | null` to `IpnsRecordFields | SeqFloor | null`. The null-signedRecord branch now returns `{ seqFloor: cached.sequenceNumber }` instead of null. In `resolveRecord`, a type-narrowing helper `isSeqFloor` switches on the discriminant: when present, gates the network record (`networkSeq >= floorSeq → serve; else fail closed → null → 404`). CID-mismatch and no-latestCid cases remain null.

## Verification

- `pnpm --filter @cipherbox/api build` produces zero errors in src/ipns/. The 102 total errors are all pre-existing in src/shares/ (sibling plan 66-04 scope).
- Grep checks passed: IPNS_TOMBSTONED count = 2, HttpStatus.GONE count = 2, seqFloor in codec = 4 occurrences, seqFloor in service = 7 occurrences, user_id = :userId count = 2, tombstone route in controller present.
- Behavioral proof deferred to sdk-e2e tests 15/16/17/20 in plan 66-09 (D-08 — checker subagents are static-analysis only).

## Threat Mitigations Applied

| Threat | Mitigation |
|--------|-----------|
| T-66-T1 Concurrent publishes → silent overwrite | Atomic UPDATE WHERE sequence_number = :expected; affected===0 → 409 |
| T-66-T2 Replay of old lower-seq record | Anti-rollback embedded-seq check preserved + CAS seq gate |
| T-66-T3 Generation regression | generation <= CAST(:incoming AS bigint) in fused WHERE |
| T-66-T4 Tombstoned name re-publication | tombstoned_at IS NULL in fused WHERE; 0 rows → 410 |
| T-66-I1 Shared-folder row serving ungated network CID | seqFloor discriminant gates network record; fail closed below floor |
| T-66-A1 Non-owner tombstoning a record | WHERE includes user_id = :userId (V4 access control) |

## Deviations from Plan

### Auto-applied adjustments

**1. [Rule 1 - Fix] TypeScript narrowing for incomingParsed**

- Found during: Task 1
- Issue: TypeScript couldn't narrow `incomingParsed: ... | null` through the `if (x === null) { x = await ...}` async assignment. Reported TS18047 on subsequent uses.
- Fix: Introduced `const resolvedParsed = incomingParsed` after the null-fill block so TypeScript sees a non-null const.
- Files modified: apps/api/src/ipns/ipns.service.ts

**2. [Rule 1 - Fix] TypeORM .set() type cast**

- Found during: Task 1
- Issue: The dynamically-built SET clause object (with callback for sequenceNumber raw SQL) caused TS2352/TS2559 with complex `Parameters<ReturnType<...>>` cast.
- Fix: Replaced with `as any` (documented with eslint-disable comment). The runtime shape is correct TypeORM QueryBuilder input.
- Files modified: apps/api/src/ipns/ipns.service.ts

**3. [Rule 2 - Missing behavior] effectiveExpected for backward-compat unconditional publish**

- Found during: Task 1 implementation
- Issue: Plan's WHERE clause requires `sequence_number = :expected`. When `expectedSequenceNumber` is undefined (legacy unconditional publish path), passing NULL breaks the WHERE (NULL comparisons are always false in SQL).
- Fix: `effectiveExpected = expectedSequenceNumber ?? existing.sequenceNumber`. When omitted, the stored sequence is used as the expected value — the CAS still passes for the current row (now atomic + safe) and fails if concurrently modified. Same pattern applied to `effectiveIncomingGeneration`.
- Files modified: apps/api/src/ipns/ipns.service.ts

## Known Stubs

None. All behavioral paths are wired. Behavioral proof via sdk-e2e tests 15/16/17/20 is explicitly deferred to plan 66-09 per D-08.

## Threat Flags

No new security-relevant surface beyond the planned tombstone endpoint (already in the threat model as T-66-T4/T-66-A1).

## Self-Check: PASSED
