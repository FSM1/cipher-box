---
phase: 58-ipns-signature-verify-coverage
status: secured
asvs_level: 1
threats_total: 19
threats_closed: 19
threats_open: 0
audited: 2026-06-22
requirement: HARD-09
---

# Phase 58 Security Audit: IPNS Signature Verify Coverage

## Summary

All 19 threats across plans 58-01 through 58-04 are CLOSED. No high-severity unmitigated
threats found. The declared residual risk (DB CID as authoritative trust root; signature
verification as defense-in-depth) is accurate and correctly scoped.

One unregistered attack surface is flagged: 6 bare `resolve_ipns` call sites in
`apps/desktop/src-tauri/` are explicitly deferred in 58-01-SUMMARY.md and lie outside
this phase's declared scope, but they represent a future hardening item.

## ASVS Level 1 Assessment

Controls verified against ASVS L1 categories:

- **V2/V4 (Input Validation):** D-09 gate in `upsertFolderIpns` runs unconditionally; first-publish, rollback, and wild-jump inputs are rejected with 400. CLOSED.
- **V5 (Output Encoding / Crypto):** CBOR binding decodes `Value` as `Bytes` (not `Text`); `Sequence` as `Integer → u64`; type mismatches return `Err`. CLOSED.
- **V7 (Error Handling / Logging):** Error messages in `verify.rs` and `sdk-core/ipns/index.ts` reference `ipns_name`/CID strings only; `signature_v2`, `data`, and `pub_key` bytes are not interpolated. CLOSED.
- **V10 (Malicious Code / Integrity):** Cross-language byte-construction is pinned by the shared 7-case fixture consumed by both `cargo test` and `sdk-core vitest`; drift fails existing CI gates. CLOSED.

## Threat Verification

### Plan 58-01: CBOR Binding and Verified Chokepoint

| Threat ID | Category | Disposition | Status | Evidence |
| --------- | -------- | ----------- | ------ | -------- |
| T-58-01 | Tampering (CID swap) | mitigate | CLOSED | `crates/fuse/src/verify.rs:91-95` — `bind_verified` compares `embedded_value == format!("/ipfs/{}", resp.cid)`; mismatch → `VerifyError::Invalid`. `packages/sdk-core/src/ipns/index.ts:256-258` — throws `"IPNS cid binding mismatch"`. |
| T-58-02 | Tampering (sequence swap) | mitigate | CLOSED | `crates/fuse/src/verify.rs:100-107` — `embedded_seq != resp_seq` → `VerifyError::Invalid`. `packages/sdk-core/src/ipns/index.ts:266-268` — throws `"IPNS sequence binding mismatch"`. |
| T-58-03 | Spoofing (unverified resolve sites) | mitigate | CLOSED | All 9 `crates/fuse/src/` sites route through `resolve_ipns_verified`: `events.rs:90`, `fs.rs:491`, `publish.rs:96`, `publish.rs:180`, `metadata.rs:330`, `metadata.rs:462`, `metadata.rs:660`, `replay.rs:336`, `replay.rs:467`. No cid-trusting `resolve_ipns(` call remains outside `verify.rs`. |
| T-58-04 | Denial of Service (mount wedge) | mitigate | CLOSED | `crates/fuse/src/verify.rs:135-183` — `resolve_ipns_verified` returns `Err(VerifyError::Invalid)` scoped per-operation; poll loop is not wedged. `replay.rs:351-356` keeps `resolve_folder_key` hard fail-closed on `Invalid` (returns `Err`), scoped fail-closed elsewhere. |
| T-58-05 | Tampering (partial-field downgrade) | mitigate | CLOSED | `packages/sdk-core/src/ipns/index.ts:220-224` — partial fields (any but not all three present) → throws `"incomplete signature data"`. `crates/fuse/src/verify.rs:69` — `Some(false)` → `VerifyError::Invalid`. Pinned by `partial-fields` vector in `tests/vectors/ipns/verify.json` (expected_result: "invalid"). |
| T-58-06 | Information Disclosure (key material in logs) | mitigate | CLOSED | `crates/fuse/src/verify.rs` — grep for `resp.data`, `signature_v2`, `pub_key` in error format strings returns only test fixture values (lines 177, 179, 223, 225, 238, 240) and one contract-violation message (line 76) that references field names, not field values. `packages/sdk-core/src/ipns/index.ts` — error messages at lines 256-257 and 266-267 interpolate CID strings and sequence numbers only; no key bytes. |
| T-58-07 | Tampering (CBOR type confusion) | mitigate | CLOSED | `crates/core/src/ipns.rs:81` — `decode_ipns_cbor_data` matches `CborValue::Bytes` for Value and `CborValue::Integer` for Sequence; any other type → `Err(IpnsError::CborEncodingFailed)`. `packages/sdk-core/src/ipns/index.ts:250` — `cborFields['Value'] instanceof Uint8Array` guard; non-Uint8Array → null → mismatch → throw. |

### Plan 58-02: D-09 Unconditional Embedded-Sequence Gate

| Threat ID | Category | Disposition | Status | Evidence |
| --------- | -------- | ----------- | ------ | -------- |
| T-58-08 | Denial of Service (first-publish wedge) | mitigate | CLOSED | `apps/api/src/ipns/ipns.service.ts:281-284` — `embeddedSeq !== 0n && embeddedSeq !== 1n` → `BadRequestException`. Gate is unconditional (not gated on `expectedSequenceNumber`). |
| T-58-09 | Repudiation / Replay (sequence rollback) | mitigate | CLOSED | `apps/api/src/ipns/ipns.service.ts:294-297` — `embeddedSeq < dbSeq` → `BadRequestException("Rollback rejected")`. |
| T-58-10 | Tampering (wild-jump sequence) | mitigate | CLOSED | `apps/api/src/ipns/ipns.service.ts:299-301` — `embeddedSeq > dbSeq + 1n` → `BadRequestException("Sequence jump rejected")`. |
| T-58-11 | Denial of Service (legitimate path regression) | mitigate | CLOSED | 58-02-SUMMARY.md § Non-CAS Publish Path Enumeration: all 8 non-CAS paths (content_ops, metadata bin, replay child-folder, mkdir fuse, mkdir windows, registry, vault publishVaultKeyBlob, sdk bin) have D-09 PASS verdicts. Idempotent branch at `apps/api/src/ipns/ipns.service.ts:288-291` protects TEE 6-hour re-sign. API jest 913/913 PASS. |
| T-58-12 | Tampering (concurrent modification → wrong status) | accept→mitigate | CLOSED | `apps/api/src/ipns/ipns.service.ts:245` — CAS 409 check (`existing && expectedSequenceNumber !== undefined`) precedes D-09 gate at line 277. Ordering pinned by `ipns.service.spec.ts` CAS-409 precedence test. |

### Plan 58-03: Web resolveIpnsRecord Deduplication

| Threat ID | Category | Disposition | Status | Evidence |
| --------- | -------- | ----------- | ------ | -------- |
| T-58-13 | Tampering (lockstep drift) | mitigate | CLOSED | `apps/web/src/services/ipns.service.ts:17` — `import { resolveIpnsRecord as resolveIpnsRecordCore } from '@cipherbox/sdk-core'`. Local `verifyIpnsSignature` function is gone (`grep -c "function verifyIpnsSignature"` returns 0). |
| T-58-14 | Spoofing (wrong-context axios call) | mitigate | CLOSED | `apps/web/src/services/ipns.service.ts:147-150` — `resolveIpnsRecordCore(ipnsName, { apiUrl, getAccessToken, axiosInstance: apiAxios })`. The web axios instance is threaded explicitly. |
| T-58-15 | Tampering (accidental downgrade during deletion) | mitigate | CLOSED | The web local verify body is deleted, not relaxed. The sole remaining path is the sdk-core chokepoint carrying partial-fields fail-closed (PR #529) and the 58-01 CBOR binding. Typecheck confirmed PASS per 58-03-SUMMARY.md. |

### Plan 58-04: Cross-Language Verify Vectors

| Threat ID | Category | Disposition | Status | Evidence |
| --------- | -------- | ----------- | ------ | -------- |
| T-58-16 | Tampering (Rust/JS byte-construction drift) | mitigate | CLOSED | `tests/vectors/ipns/verify.json` exists with 7 cases. Rust consumer `crates/fuse/tests/ipns_verify_vectors.rs:159` (`ipns_verify_cross_language`) calls real `verify_ipns_resolve_signature` + `decode_ipns_cbor_data`. JS consumer `packages/sdk-core/src/__tests__/ipns.test.ts:387` imports the same fixture. Both run in existing CI gates (`cargo test -p cipherbox-fuse`, `pnpm --filter @cipherbox/sdk-core test`). |
| T-58-17 | Tampering (partial-fields regression) | mitigate | CLOSED | `tests/vectors/ipns/verify.json` case `"partial-fields"` has `expected_result: "invalid"`. Both consumers assert this case. Any relaxation of the partial-fields guard fails CI. |
| T-58-18 | Tampering (CID/sequence binding regression) | mitigate | CLOSED | `tests/vectors/ipns/verify.json` cases `"cid-swapped"` and `"seq-mismatch"` carry valid Ed25519 signatures over mismatching CBOR data — only the binding layer can reject them. Both consumers assert `expected_result: "invalid"` for these cases. |
| T-58-SC | Supply chain (npm/cargo installs) | accept | CLOSED | T-58-SC is accepted per plan threat model. `cborg ^4.5.8` was added in 58-01 (not 58-04) as an explicit `sdk-core` direct dependency — this was declared in 58-01 threat register. No new runtime package installs in 58-04; the generator uses dev-time packages from the pnpm virtual store. |

## Residual Risk (Accepted)

The following risks are accepted per the phase threat models and are accurately documented:

1. **DB CID as trust root (Medium):** Signature verification is defense-in-depth, not the primary trust path. The DB CID remains authoritative. This is correct for the DB-backed architecture and is not addressable without architectural change.

2. **Legacy all-absent records (D-04):** Records with all three signature fields absent (`signatureVerified=false`) are allowed and rely on the DB CID trust root. This preserves backward compatibility with pre-signing records and cannot be tightened without breaking existing vaults.

3. **SDK E2E infrastructure gap (58-02 Task 3):** The full SDK E2E gate (D-10) could not be run against a live API due to a pre-existing `TEST_LOGIN_SECRET` mismatch in the local environment (compiled dist vs `pnpm dev`). This is an infrastructure-limited item (per project memory). The API jest suite (913/913 PASS) and the Task 1 non-CAS path enumeration provide the available coverage. No sequence-rejection errors were observed; the failure was exclusively auth (401).

## Unregistered Flags

The following attack surface appeared during implementation with no threat mapping in the phase plans:

**UNREGISTERED:** `apps/desktop/src-tauri/` — 6 unverified `resolve_ipns` call sites:

- `apps/desktop/src-tauri/src/fuse/prepopulate.rs` (4 sites at lines 43, 110, 177, 236)
- `apps/desktop/src-tauri/src/commands/vault.rs` (2 sites at lines 21, 250)

These sites trust the raw response `cid` without routing through `resolve_ipns_verified`. They are documented as explicitly deferred in 58-01-SUMMARY.md ("Out of scope for the 9 enumerated `crates/fuse/src/` sites; tracked for future hardening"). The phase plan scope was `crates/fuse/src/` only.

**Classification:** WARNING (unregistered flag, not a blocker for this phase). The desktop app operates behind the same DB-CID trust root, so the security posture is equivalent to the pre-phase baseline for those paths — no regression introduced. A follow-on phase should route these 6 sites through `crate::verify::resolve_ipns_verified`.
