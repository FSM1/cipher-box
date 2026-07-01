---
phase: 67-tee-lease-renewer-contract-rewrite
verified: 2026-07-01T00:00:00Z
status: passed
score: 8/8 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification: null
---

# Phase 67: TEE Lease-Renewer Contract Rewrite Verification Report

**Phase Goal:** The TEE worker is a record-lease-renewer — it receives a marshaled `signedRecord`, verifies its signature, and re-emits the same CID and sequence with only a later EOL; it cannot originate or repoint a CID.
**Verified:** 2026-07-01T00:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (from ROADMAP.md Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| SC1 | `+1n` sequence increment removed; republish re-signs same seq + same CID + later EOL; test asserts equal seq; tombstoned CID never re-signed | ✓ VERIFIED | `republish.ts` L173: `newSequenceNumber: parsed.sequence.toString()`. No `+1n` in route. `ipns-signer.ts` `renewIpnsRecord` uses `parsed.value + parsed.sequence` from the existing record only. `ipns-signer.test.ts` asserts seq===7n; `tee-republish.test.ts` Test B asserts tombstoned name not re-signed. Orchestrator E2E confirmed. |
| SC2 | TEE derives `currentEpoch` from own clock; asserts `publicKeyFromIpnsName(name) == pubkey(decryptedKey)` before emit; tombstoned name rejected at publish gate | ✓ VERIFIED | `tee-keys.ts` L40: `getInternalCurrentEpoch()` reads `EPOCH_ZERO_TIMESTAMP_MS` env (never relay scalar). `republish.ts` L131-133: `deriveEd25519PublicKey(ipnsPrivateKey)` vs `publicKeyFromIpnsName(entry.ipnsName)` byte-compared. `getDueEntries` filters `tombstonedAt IS NULL`; `renewIpnsRecordEol` CAS also filters `tombstoned_at IS NULL`. |
| SC3 | `ipns_records` sole source of signing inputs; 4 duplicated columns collapsed from `ipns_republish_schedule`; no schedule snapshot signing inputs | ✓ VERIFIED | Entity has 7 `@Column` (scheduling metadata only). Migration drops `encrypted_ipns_key`, `key_epoch`, `latest_cid`, `sequence_number`. `getDueEntries` fetches paired `record` from `ipns_records` with tombstone+key filter; `teeEntries` built from `record.*` not schedule. `RepublishEntry` carries `signedRecord + keyEpoch + encryptedIpnsKey + ipnsName` only. |
| SC4 | EOL renewal uses equality CAS (`WHERE sequenceNumber = :loaded`); cannot regress seq; E2E round-trip confirms end-to-end | ✓ VERIFIED | `renewIpnsRecordEol` at line 426: `.where('ipns_name = :ipnsName AND sequence_number = :expected AND tombstoned_at IS NULL', ...)`. No `LessThanOrEqual` on sequence. E2E: orchestrator confirmed 2/2 pass (same CID + same seq + later EOL; tombstoned never re-signed). |

### Plan-Level Must-Have Truths (cross-cut by plan)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| P01-T1 | Schedule entity carries no crypto/signing column (7 @Column scheduling fields only) | ✓ VERIFIED | `grep -c "@Column"` returns 7; grep for `encryptedIpnsKey|keyEpoch|latestCid|sequenceNumber` returns nothing |
| P01-T2 | Forward migration drops the 4 columns; `down()` throws; JOIN index added | ✓ VERIFIED | `1751000000000-ScheduleCollapse.ts` has 4 DROP COLUMNs, `CREATE INDEX IDX_ipns_republish_schedule_ipns_name`, `down()` throws Error (greenfield waiver) |
| P02-T1 | `getInternalCurrentEpoch()` reads TEE clock only; safe fallback = 1 when unset | ✓ VERIFIED | `tee-keys.ts` L41-45: reads `process.env.EPOCH_ZERO_TIMESTAMP_MS` at call time; returns `MIN_EPOCH(1)` when anchor is 0. Tests confirm 3 cases (unset→1, 5-weeks-ago→2, future→1) |
| P02-T2 | `decryptWithFallback(encryptedIpnsKey, keyEpoch)` is 2-arg; throws `ReEnrollRequiredError` BEFORE unwrap when `keyEpoch < internalCurrentEpoch - 1` | ✓ VERIFIED | `key-manager.ts` L77-80: 2-arg signature. L86: `if (keyEpoch < internalCurrentEpoch - 1) throw ReEnrollRequiredError` before any `decryptIpnsKey` call. Test asserts decrypt spy call-count 0 on stale path. |
| P03-T1 | `renewIpnsRecord` re-signs SAME value (CID) + SAME sequence from `parsed`; structurally cannot repoint or increment | ✓ VERIFIED | `ipns-signer.ts` L49-55: `parsed.value + parsed.sequence` passed to `createIpnsRecord`; no CID/seq arg. `ipns-signer.test.ts` asserts `parsedRenewed.value === parsedOriginal.value` and `parsedRenewed.sequence === parsedOriginal.sequence === 7n` |
| P06-T1 | TEE route verifies signature BEFORE decrypt; binding uses `deriveEd25519PublicKey(decryptedKey)` vs `publicKeyFromIpnsName(name)` (never `parsed.pubKey`); `newSequenceNumber == parsedSequence`; `requiresReEnroll` surfaces on `ReEnrollRequiredError`; key zeroed on every path | ✓ VERIFIED | `republish.ts`: `verifyIpnsRecordSignature` at L108 before `decryptWithFallback` at L122. Binding at L131-133 uses `deriveEd25519PublicKey` + `publicKeyFromIpnsName`. `parsed.pubKey` appears only in comments. `newSequenceNumber: parsed.sequence.toString()` at L173. `requiresReEnroll = true` at L201. `fill(0)` at L135, L164, L185. |
| P07-T1 | `getDueEntries` returns `{schedule, record}` pairs filtered for `tombstonedAt IS NULL AND encryptedIpnsPrivateKey NOT NULL`; `renewIpnsRecordEol` uses equality CAS; `enrollFolder` is 2-arg; no schedule-snapshot signing inputs | ✓ VERIFIED | `republish.service.ts`: `getDueEntries` step 2 uses `tombstonedAt: IsNull(), encryptedIpnsPrivateKey: Not(IsNull())`. `renewIpnsRecordEol` equality CAS at L426. `enrollFolder(userId, ipnsName)` signature L263. `teeEntries` built from `record.*` (L129-133). `syncIpnsRecordSequence` is absent. |
| P08-T1 | sdk-e2e `tee-republish.test.ts` exists; proves equal-seq + equal-CID + later-EOL and tombstoned-name-never-resigned; E2E round-trip passed 2/2 | ✓ VERIFIED | File exists at `tests/sdk-e2e/src/suites/tee-republish.test.ts`. Test A at L191 asserts `renewedRecord.sequence === originalRecord.sequence` and `renewedRecord.value === originalRecord.value`. Test B at L236 asserts tombstoned name not re-signed. Orchestrator confirmed live run: processed=1/succeeded=1/failed=0, no key material logged. |

**Score:** 8/8 must-haves verified (0 present, behavior-unverified)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `apps/api/src/republish/republish-schedule.entity.ts` | Schedule-only entity (7 @Column, no crypto columns) | ✓ VERIFIED | 7 @Column; `encryptedIpnsKey/keyEpoch/latestCid/sequenceNumber` absent |
| `apps/api/src/migrations/1751000000000-ScheduleCollapse.ts` | Migration dropping 4 columns, adding JOIN index, `down()` throws | ✓ VERIFIED | 4 `DROP COLUMN IF EXISTS` + `CREATE INDEX IDX_ipns_republish_schedule_ipns_name`; `down()` throws |
| `apps/tee-worker/src/services/tee-keys.ts` | Exports `getInternalCurrentEpoch()` (clock-based, never relay) | ✓ VERIFIED | L40: exported, reads `EPOCH_ZERO_TIMESTAMP_MS` at call time |
| `apps/tee-worker/src/services/key-manager.ts` | 2-arg `decryptWithFallback`; `ReEnrollRequiredError`; stale guard | ✓ VERIFIED | L77: 2-arg; L26: `ReEnrollRequiredError` with `requiresReEnroll = true`; L86: stale guard fires before unwrap |
| `apps/tee-worker/src/services/ipns-signer.ts` | `renewIpnsRecord` uses `parsed.value + parsed.sequence`; `signIpnsRecord` unchanged | ✓ VERIFIED | L44: exported; L49-55: `parseIpnsRecord` → `createIpnsRecord(key, parsed.value, parsed.sequence, lifetime)` |
| `apps/tee-worker/src/routes/republish.ts` | Verify-in-enclave route: no `+1n`, binding via `deriveEd25519PublicKey`, key zeroed all paths | ✓ VERIFIED | No `+1n` or `entry.latestCid/sequenceNumber/currentEpoch/previousEpoch`. Three `fill(0)/null` zeroing points. Binding at L131-133. |
| `apps/api/src/republish/republish.service.ts` | `renewIpnsRecordEol` equality CAS; 2-arg `enrollFolder`; `teeEntries` from `record.*`; no `syncIpnsRecordSequence` | ✓ VERIFIED | All confirmed. `LessThanOrEqual` remains only for time-based `nextRepublishAt` schedule query (not sequence write-back — comment at L57 clarifies). |
| `apps/api/src/tee/tee.service.ts` | `RepublishEntry` carries `signedRecord + keyEpoch + encryptedIpnsKey + ipnsName` only | ✓ VERIFIED | Interface at L13-21: 4 fields, no `latestCid/sequenceNumber/currentEpoch/previousEpoch` |
| `tests/sdk-e2e/src/suites/tee-republish.test.ts` | Round-trip suite: equal-seq, equal-CID, tombstone gate | ✓ VERIFIED | Exists; `queue.add('republish-batch', {})` at L122; assertions at L228-229; Test B at L236 |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `ipns_records.signed_record` | `RepublishEntry.signedRecord` | `getDueEntries` step 2 + `teeEntries` map | ✓ WIRED | `record.signedRecord!.toString('base64')` at `republish.service.ts:133` |
| `parseIpnsRecord(signedRecord)` | `createIpnsRecord(key, parsed.value, parsed.sequence)` | `renewIpnsRecord` in `ipns-signer.ts` | ✓ WIRED | L49-55: parse → re-sign with same value+seq |
| `getInternalCurrentEpoch()` (tee-keys) | `decryptWithFallback` stale guard + epoch-upgrade target (key-manager + republish route) | Import at `key-manager.ts:15`; `republish.ts:45` | ✓ WIRED | Both import and use `getInternalCurrentEpoch()` |
| `publicKeyFromIpnsName(ipnsName)` | `deriveEd25519PublicKey(decryptedKey)` binding check | `republish.ts` L131-133 | ✓ WIRED | Byte-compare on every path; mismatch → fill(0) + reject |
| `ipns_records` (tombstonedAt IS NULL) | Batch pre-filter (defense layer 1) + CAS write guard (defense layer 2) | `getDueEntries` step 2; `renewIpnsRecordEol` WHERE clause | ✓ WIRED | Both filters present |
| `ipns_republish_schedule.ipns_name` | `ipns_records.ipns_name` (JOIN key) | `getDueEntries` paired find + `IDX_ipns_republish_schedule_ipns_name` | ✓ WIRED | Two-query paired find; index in migration |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|--------------------|--------|
| `teeEntries` in `processRepublishBatch` | `record.signedRecord`, `record.encryptedIpnsPrivateKey`, `record.keyEpoch` | `ipns_records` repository `find()` with tombstone+key filter | Yes — DB query returns live rows | ✓ FLOWING |
| `renewIpnsRecord` output | `parsed.value + parsed.sequence` | `parseIpnsRecord(signedRecordBytes)` — live protobuf decode | Yes — decoded from real signed record bytes | ✓ FLOWING |
| `renewIpnsRecordEol` CAS write | `renewedSignedRecord` buffer | `Buffer.from(result.signedRecord, 'base64')` from TEE response | Yes — real TEE-signed record bytes | ✓ FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Evidence | Status |
|----------|----------|--------|
| TEE route: `newSequenceNumber == parsedSequence`, not `parsedSequence + 1` | `republish.ts` L173: `newSequenceNumber: parsed.sequence.toString()`; no `+1n` in file; `republish.test.ts` L208-209 asserts `toBe('5')` | ✓ PASS |
| Stale guard throws before `decryptIpnsKey` | `key-manager.ts` L86: `if (keyEpoch < internalCurrentEpoch - 1) throw`; `key-manager.test.ts` L158-167 asserts `getKeypair` not called | ✓ PASS |
| Signature verify precedes decrypt | `republish.ts` L108 (`verifyIpnsRecordSignature`) before L122 (`decryptWithFallback`); `republish.test.ts` L235 spy asserts decrypt uncalled on verify-fail | ✓ PASS |
| E2E: equal-seq + equal-CID + later-EOL + tombstone-never-resigned | Orchestrator live run: 2/2 passing; processed=1/succeeded=1/failed=0; no key material in logs | ✓ PASS (accepted orchestrator evidence per task brief) |

---

### Probe Execution

Not applicable — no `probe-*.sh` scripts declared or conventional for this phase.

---

### Requirements Coverage

| Requirement | Plans | Description | Status | Evidence |
|-------------|-------|-------------|--------|----------|
| TEE-01 | 67-03, 67-05, 67-06, 67-08 | TEE is a lease-renewer: same CID + same seq + later EOL; cannot originate or repoint | ✓ SATISFIED | `renewIpnsRecord` uses `parsed.value + parsed.sequence`; no relay-supplied CID accepted |
| TEE-02 | 67-03, 67-05, 67-06, 67-08 | Republish never increments the sequence; `+1n` path removed | ✓ SATISFIED | `+1n` absent from route; `newSequenceNumber = parsed.sequence.toString()` |
| TEE-03 | 67-01, 67-04, 67-07, 67-08 | `ipns_records` sole signing source; schedule 4 columns collapsed | ✓ SATISFIED | Entity clean; migration drops 4 cols; `getDueEntries` paired from `ipns_records`; 2-arg `enrollFolder` |
| TEE-06 | 67-02, 67-06, 67-07, 67-08 | Internal epoch self-derivation; name↔key binding; stale-key guard; `ReEnrollRequiredError` | ✓ SATISFIED | `getInternalCurrentEpoch()` clock-based; binding via `deriveEd25519PublicKey`; stale guard at `keyEpoch < currentEpoch-1`; `requiresReEnroll` surfaces |

---

### Anti-Patterns Found

No TBD / FIXME / XXX markers found in any phase-modified file.

One deviation from the plan's stated acceptance criteria is documented and acceptable:

- **`LessThanOrEqual` import in `republish.service.ts`** (line 3): The plan acceptance criteria for 67-07 specified `grep -nE "LessThanOrEqual"` should return nothing. However, `LessThanOrEqual` is present — used for the time-based `nextRepublishAt <= now` schedule query in `getDueEntries`, not for the sequence write-back. The code comment at line 57 explicitly states: "LessThanOrEqual here selects rows due by time; it is NOT the sequence write-back." The prohibition was specifically on `LessThanOrEqual` on `sequence_number` as the renewal write — that is confirmed gone. The two-query find-options approach was adopted because the query-builder `innerJoin` with `take`-pagination triggered a TypeORM metadata error at runtime. The tombstone + key filter guarantees are preserved.

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `republish.service.ts` | 3, 62 | `LessThanOrEqual` on `nextRepublishAt` (time query, not seq write-back) | Info | None — prohibited use (on sequence_number) is absent; this is the scheduling time query |

---

### Human Verification Required

No human verification items. All truths are either structurally verifiable by static analysis or covered by the orchestrator-confirmed E2E live run (accepted per task brief as verified evidence).

---

### Gaps Summary

No gaps. All 4 roadmap success criteria and all plan must-have truths are verified in the codebase.

---

_Verified: 2026-07-01T00:00:00Z_
_Verifier: Claude (gsd-verifier)_
