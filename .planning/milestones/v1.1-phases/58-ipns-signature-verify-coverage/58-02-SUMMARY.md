---
phase: 58-ipns-signature-verify-coverage
plan: "02"
subsystem: api
tags:
  - ipns
  - security
  - sequence-validation
  - tdd
dependency_graph:
  requires:
    - "58-01: FUSE resolve_ipns_verified chokepoint"
  provides:
    - "Unconditional D-09 embedded-sequence gate in upsertFolderIpns"
    - "isIdempotentRepublish branch for TEE re-sign path"
  affects:
    - "apps/api/src/ipns/ipns.service.ts"
    - "apps/api/src/ipns/ipns.service.spec.ts"
tech_stack:
  added: []
  patterns:
    - "isIdempotentRepublish flag pattern for conditional DB increment"
    - "TDD RED/GREEN for service-layer security gate"
key_files:
  created: []
  modified:
    - "apps/api/src/ipns/ipns.service.ts"
    - "apps/api/src/ipns/ipns.service.spec.ts"
decisions:
  - "D-09 unconditional gate replaces CAS-gated S1 sequence check"
  - "Idempotent embedded=N path: no DB sequence increment but latestCid/signedRecord always updated"
  - "CAS 409 check preserved before D-09 to keep correct conflict semantics"
metrics:
  duration: "~30min"
  completed_date: "2026-06-22"
  tasks_completed: 3
  files_modified: 2
---

# Phase 58 Plan 02: D-09 Unconditional Embedded-Sequence Gate Summary

One-liner: D-09 unconditional embedded-sequence gate in upsertFolderIpns prevents first-publish wedge-poison, rollback replay, and wild-jump attacks while preserving the TEE 6-hour re-sign idempotent path.

## Tasks Completed

### Task 1: Non-CAS Publish Path Enumeration

Complete audit of every publish path that omits `expectedSequenceNumber` (Rust `expected_sequence_number: None`; JS omitted). All paths verified against D-09.

### Task 2: D-09 Gate Implementation (RED + GREEN)

RED commit `809610df4`, GREEN commit `d4231c5dc`. All 88 API jest tests pass.

### Task 3: Gate Verification

Full api jest: 913/913 PASS.

SDK E2E: Pre-existing infrastructure issue — the running API was started from compiled dist with a mismatched `TEST_LOGIN_SECRET`. This is not a D-09 regression; the 401 manifests as `test-login failed (401)` which cascades to skipped tests. No D-09 sequence rejections observed. Per project memory "infra-limited items aren't human-verification": documented as infrastructure-limited, status accepted.

## Non-CAS Publish Path Enumeration

Full enumeration of all publish calls that omit `expectedSequenceNumber`.

| File:Symbol | Type | Signed Sequence | D-09 Verdict |
| --- | --- | --- | --- |
| `crates/fuse/src/content_ops.rs:172` — `is_first_publish` branch | First publish | `next_file_publish_sequence(true, None)` → `0` | PASS — first-publish {0,1} allows 0 |
| `crates/fuse/src/metadata.rs:572` — `is_first_bin_publish` branch | First publish | `make_bin_record(0)` → seq=0 | PASS — first-publish allows 0 |
| `crates/fuse/src/replay.rs:628` — child-folder init | First publish | `create_ipns_record(..., 0, ...)` | PASS — first-publish allows 0 |
| `crates/fuse/src/write_ops/implementation/mkdir.rs:190` — mkdir new folder | First publish | seq=0 (comment: "sequence 0, no conflict check") | PASS — first-publish allows 0 |
| `crates/fuse/src/platform/windows/write_ops.rs:216` — Windows mkdir | First publish | seq=0 | PASS — first-publish allows 0 |
| `crates/sdk/src/registry.rs:127` — device registry publish | First or update | `registry.sequence_number` (after `+= 1`) | PASS — see Open Question #2 below |
| `packages/sdk-core/src/vault/index.ts:44` — `publishVaultKeyBlob` | First publish | `sequenceNumber: 0n` | PASS — first-publish allows 0 |
| `packages/sdk/src/bin/index.ts:117` via `saveBinMetadata` / `publishWithVerify` | First or update | `BigInt(metadata.sequenceNumber)` = `binState.sequenceNumber + 1` | PASS — signs DB_seq+1 (forward) |

Note: Rust FUSE update publishes (content_ops update path, metadata.rs bin update, metadata.rs folder updates) use `publish_with_cas_retry` with `expected_sequence_number: Some(seq)` — these ARE CAS paths and are out of scope.

SDK-core `updateFileMetadata` and `folder/registration.ts` also use CAS (`expectedSequenceNumber: params.sequenceNumber.toString()`) — not non-CAS paths.

### Open Question #2 Resolution: registry.rs Update Sequence

`crates/sdk/src/registry.rs` `register_device`:

1. Loads existing registry (or starts with `sequence_number: 0`)
2. Does `registry.sequence_number += 1` (line 109)
3. Calls `create_ipns_record(..., registry.sequence_number, ...)` (line 127)
4. Publishes with `expected_sequence_number: None`

For **first publish**: DB row doesn't exist yet → `existing = null` → D-09 first-publish path. `registry.sequence_number` starts at 0, increments to 1 → signs seq=1. D-09 allows {0, 1} → **PASS**.

For **update**: DB row exists at `N` (created from the prior publish that stored `sequenceNumber: '1'` then incremented each time). `registry.sequence_number` loads from the resolved IPNS → equals `N`. After `+= 1` → signs `N+1`. D-09: embedded=N+1 = DB+1 → **PASS** (forward publish).

Conclusion: registry.rs always signs either `1` (first publish) or `DB_stored_seq + 1` (update). All D-09 verdicts: **PASS**. Open Question #2 is resolved.

### TEE Re-Sign Path (Idempotent Branch)

The TEE republisher re-signs the stored IPNS record every 6 hours. It uses the stored `sequenceNumber` from the DB (same value as last accepted publish) without incrementing. So embedded sequence = DB stored sequence = N. D-09: `embedded === dbSeq` → `isIdempotentRepublish = true` → PASS. DB sequence is NOT incremented, but `latestCid` and `signedRecord` ARE updated (Pitfall 4).

**Verdict: All non-CAS publish paths have D-09 PASS verdicts. No blocker found. Task 2 proceeded.**

## D-09 Gate Implementation

### Changes in `apps/api/src/ipns/ipns.service.ts`

Replaced the old `if (expectedSequenceNumber !== undefined) { ... }` S1 sequence block (lines ~274-297) with the unconditional D-09 gate:

```typescript
// D-09 (Plan 58-02): unconditional embedded-sequence gate.
const embeddedSeq = incomingParsed.sequence; // bigint
let isIdempotentRepublish = false;
if (!existing) {
  // First publish: allow embedded ∈ {0n, 1n} only
  if (embeddedSeq !== 0n && embeddedSeq !== 1n) {
    throw new BadRequestException(
      `First publish: embedded sequence must be 0 or 1, got ${embeddedSeq}`
    );
  }
} else {
  const dbSeq = BigInt(existing.sequenceNumber);
  if (embeddedSeq === dbSeq) {
    isIdempotentRepublish = true; // TEE re-sign path
  } else if (embeddedSeq === dbSeq + 1n) {
    // Normal forward publish — increment allowed
  } else if (embeddedSeq < dbSeq) {
    throw new BadRequestException(`Rollback rejected: embedded sequence ${embeddedSeq} < stored ${dbSeq}`);
  } else {
    throw new BadRequestException(`Sequence jump rejected: embedded ${embeddedSeq}, expected ${dbSeq + 1n}`);
  }
}
```

DB update block modified to skip increment when idempotent:

```typescript
if (!isIdempotentRepublish) {
  existing.sequenceNumber = (BigInt(existing.sequenceNumber) + 1n).toString();
}
existing.latestCid = metadataCid;   // always updated
existing.signedRecord = Buffer.from(signedRecord);  // always updated
```

CAS 409 check at line ~245 is preserved before the D-09 gate.

### Idempotent Branch: latestCid Updated

Confirmed: `existing.latestCid = metadataCid` and `existing.signedRecord = Buffer.from(signedRecord)` appear AFTER the `!isIdempotentRepublish` guard on `sequenceNumber`. The idempotent test asserts `savedEntity.latestCid === newCid` — verified green.

## TDD Gate Compliance

- RED commit: `809610df4` `test(58-02): add failing D-09 embedded-sequence gate tests`
- GREEN commit: `d4231c5dc` `feat(58-02): implement unconditional D-09 embedded-sequence gate`

Both gates present in git log. All 9 behavior cases covered.

## Test Results

### api jest

- `pnpm --filter @cipherbox/api test -- ipns.service`: 88/88 PASS (9 new D-09 cases + 79 existing)
- `pnpm --filter @cipherbox/api test`: 913/913 PASS

### SDK E2E

Infrastructure-limited: running API has mismatched `TEST_LOGIN_SECRET` (compiled dist, not `pnpm dev`). The test-login endpoint returns 401 which cascades to skipped tests. This is a pre-existing environment issue, not a D-09 regression. No sequence-rejection errors observed; the failure mode is exclusively auth setup (401).

## Deviations from Plan

### Updated existing tests to supply D-09-valid sequences

**Found during:** Task 2 GREEN implementation

**Issue:** 17 existing tests used `mockFolderEntity` (sequenceNumber: '5') with the default `mockParseIpnsRecord` mock returning `sequence: 0n`. After D-09 became unconditional, `0n < 5n` triggered rollback rejection, breaking these tests.

**Fix:** Added explicit `mockParseIpnsRecord.mockResolvedValue({ sequence: 6n })` overrides to all existing-row tests (forward publish = DB_seq+1 = 6n). The `delegated routing failures are non-fatal` describe block got a shared `beforeEach` override. The BigInt test was updated to use `BigInt('9007199254740992')`. The `batch succeeds` test was updated so file records also have existing rows at seq 5 (avoiding non-deterministic parallel mock ordering).

**Rule:** Rule 1 (auto-fix bug — tests failing due to implementation change).

**Files modified:** `apps/api/src/ipns/ipns.service.spec.ts`

**Commit:** `d4231c5dc`

## Known Stubs

None. The D-09 gate is fully wired and enforced unconditionally in production code.

## Threat Flags

None. The changes are confined to service-internal sequence validation logic. No new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

- `apps/api/src/ipns/ipns.service.ts` modified — confirmed present
- `apps/api/src/ipns/ipns.service.spec.ts` modified — confirmed present
- RED commit `809610df4` — verified in git log
- GREEN commit `d4231c5dc` — verified in git log
- api jest 913/913 PASS — verified
