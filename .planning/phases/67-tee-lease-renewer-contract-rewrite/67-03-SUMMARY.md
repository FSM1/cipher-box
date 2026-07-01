---
phase: 67-tee-lease-renewer-contract-rewrite
plan: "03"
subsystem: tee-worker/ipns-signer
tags: [tee, ipns, lease-renew, security, tdd]
status: complete

dependency_graph:
  requires: []
  provides:
    - renewIpnsRecord (apps/tee-worker/src/services/ipns-signer.ts)
  affects:
    - apps/tee-worker (adds lease-renew primitive consumed by 67-06 route)

tech_stack:
  added: []
  patterns:
    - Parse-then-re-sign: parseIpnsRecord extracts value+sequence; createIpnsRecord re-signs with same scalars

key_files:
  created:
    - apps/tee-worker/src/__tests__/ipns-signer.test.ts
  modified:
    - apps/tee-worker/src/services/ipns-signer.ts

decisions:
  - renewIpnsRecord sources value and sequence exclusively from parseIpnsRecord — no CID or sequence args (TEE-01/TEE-02)
  - signIpnsRecord kept unchanged for back-compat; renewIpnsRecord added alongside
  - parseIpnsRecord imported from @cipherbox/crypto (already a tee-worker dependency)
  - lifetimeMs defaults to TEE_RECORD_LIFETIME_MS (48h) matching signIpnsRecord convention

metrics:
  duration: 102s
  completed: "2026-07-01"
  tasks_completed: 1
  files_changed: 2
---

# Phase 67 Plan 03: renewIpnsRecord Lease-Renew Transform Summary

**One-liner:** `renewIpnsRecord` re-signs a parsed record's own CID and sequence with only a later EOL — implemented with parse-then-re-sign pattern via `@cipherbox/crypto` and `@cipherbox/core`.

## What Was Built

Added `renewIpnsRecord(ed25519PrivateKey, marshaledExistingRecord, lifetimeMs?)` to `apps/tee-worker/src/services/ipns-signer.ts`. The function:

1. Parses the marshaled existing record with `parseIpnsRecord` from `@cipherbox/crypto`
2. Re-signs using `createIpnsRecord(ed25519PrivateKey, parsed.value, parsed.sequence, lifetimeMs)`
3. Returns `marshalIpnsRecord(record)`

Value and sequence come exclusively from the parsed record — there is no CID argument and no sequence argument, making CID repoint and sequence increment structurally impossible.

`signIpnsRecord` (create-from-scalars) is unchanged for back-compat.

## TDD Gate Compliance

RED commit `6787ed11b` — `test(67-03): add failing tests for renewIpnsRecord lease-renew transform`
GREEN commit `4b8b6d913` — `feat(67-03): implement renewIpnsRecord lease-renew transform`

Gate sequence: RED before GREEN — compliant.

## Test Coverage

5 tests in `apps/tee-worker/src/__tests__/ipns-signer.test.ts`:

| Test | Assertion | Status |
|------|-----------|--------|
| preserves the value (no CID repoint) | `parsedRenewed.value === TEST_VALUE` | PASS |
| preserves the sequence number (no +1) | `parsedRenewed.sequence === 7n` | PASS |
| produces different bytes (later EOL) | `!Buffer.from(renewed).equals(Buffer.from(original))` | PASS |
| produces a valid signature | `verifyIpnsRecordSignature(ipnsName, renewed) === true` | PASS |
| accepts explicit lifetimeMs | value and sequence preserved with custom lifetime | PASS |

## Verification

```
pnpm --filter cipherbox-tee-worker test -- ipns-signer
```

Result: 5/5 ipns-signer tests pass. 1 pre-existing failure in `republish.test.ts` (owned by plan 67-06, introduced by 67-02) — expected and unchanged.

## Acceptance Criteria

- [x] `pnpm --filter cipherbox-tee-worker test -- ipns-signer` exits 0 with 5 tests green
- [x] `export async function renewIpnsRecord` at line 44 of `ipns-signer.ts`
- [x] `parseIpnsRecord` imported and used to source value+sequence
- [x] Tests assert `parseIpnsRecord(renewed).sequence === parseIpnsRecord(original).sequence` and `parseIpnsRecord(renewed).value === parseIpnsRecord(original).value`
- [x] `signIpnsRecord` still exported unchanged

## Deviations from Plan

None — plan executed exactly as written.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The function is a pure in-memory transform.

## Self-Check: PASSED

- `apps/tee-worker/src/__tests__/ipns-signer.test.ts` — FOUND
- `apps/tee-worker/src/services/ipns-signer.ts` (modified) — FOUND
- RED commit `6787ed11b` — FOUND
- GREEN commit `4b8b6d913` — FOUND
