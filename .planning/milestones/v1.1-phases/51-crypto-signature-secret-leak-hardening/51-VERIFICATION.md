---
phase: 51-crypto-signature-secret-leak-hardening
verified: 2026-06-19T00:00:00Z
status: passed
score: 10/10 must-haves verified
overrides_applied: 0
---

# Phase 51: Crypto-Signature & Secret-Leak Hardening Verification Report

**Phase Goal:** Close the three deferred IPNS signed-record findings (S1/S2/S3) from the PR #448 security review under HARD-02 — publish-time embedded-vs-DTO validation (S1), fail-closed signature verification across web + sdk-core + Rust with callers honoring signatureVerified (S2), and an exhaustive caller-owns-key zeroization convention across the TS SDK and Rust crates with an enforcement guard (S3).
**Verified:** 2026-06-19
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | Publishing an IPNS record whose embedded signed-record CID differs from the DTO metadataCid is rejected with HTTP 400 (S1, D-01) | VERIFIED | `apps/api/src/ipns/ipns.service.ts:267` throws `BadRequestException` with message naming embedded vs dto CID |
| 2  | Publishing an IPNS record whose embedded sequence disagrees with expectedSequenceNumber (offset-aware) on a non-first publish is rejected with HTTP 400 (S1, D-01) | VERIFIED | `ipns.service.ts:289` throws `BadRequestException` for non-first-publish sequence mismatch; `isFirstPublish = !existing` branch at line 276 |
| 3  | First-publish records tolerate embedded sequence 0n or 1n without rejection (S1, D-01) | VERIFIED | First-publish branch at lines 277-287 accepts offset 0n or 1n from expectedSeqBigInt; 6-case test suite green (79/79 passing) |
| 4  | The pre-existing embedded-vs-embedded anti-rollback 409 is preserved (not replaced) | VERIFIED | `ConflictException` (409) at lines 231-235, 248-250; CAS check explicitly placed before S1 sequence check per deviation note |
| 5  | Web resolveIpnsRecord throws (fail-closed) when signature fields are present but verification returns false (S2, D-02) | VERIFIED | `apps/web/src/services/ipns.service.ts:181` throws `'IPNS signature verification failed - record may be tampered'`; 6 vitest cases green |
| 6  | Web resolveIpnsRecord throws when pubKey does not derive to the requested ipnsName (key substitution, D-02) | VERIFIED | `apps/web/src/services/ipns.service.ts:188-191` throws `'IPNS public key does not match requested name - possible key substitution'` |
| 7  | Web resolveIpnsRecord returns signatureVerified=false (allow + warn) when signature fields are absent (S2, D-03) | VERIFIED | `ipns.service.ts:175-177` sets `signatureVerified = false`; absent-fields path enters D-03 branch; outer 404 catch narrowed to `status === 404` only |
| 8  | Rust IpnsResolveResponse deserializes optional sig fields; verify_ipns_resolve_signature returns Ok(None)/Ok(Some(false))/Ok(Some(true)) correctly; FUSE resolve callers honor the result with 4-arm match (S2/D-04) | VERIFIED | `types.rs:138,142` adds `signature_v2`, `pub_key` `Option<String>`; `ipns.rs:64` exports `verify_ipns_resolve_signature`; `lib.rs:1643-1665` four-arm match: warn on None, proceed on Some(true), return Err on Some(false) and Err(e) |
| 9  | ecies::unwrap_key returns Zeroizing\<Vec\<u8\>\>; FUSE BFS queue and get_folder_key hold Zeroizing keys, not raw Vec\<u8\> (S3/D-05 Rust) | VERIFIED | `ecies.rs:38` declares return `Result<Zeroizing<Vec<u8>>, CryptoError>`; `lib.rs:933` `get_folder_key` returns `Option<Zeroizing<Vec<u8>>>`; `lib.rs:1617` BFS queue is `VecDeque<(String, Zeroizing<Vec<u8>>)>`; `cipherbox-crypto` workspace dep in `Cargo.toml:16` |
| 10 | sdk-core createAndPublishIpnsRecord and publishVaultKeyBlob zeroize terminal keys on all exit paths; updateFolderMetadataAndPublish has documented caller-owns-key skip with guard test; enforcement guard tests lock the convention (S3/D-05 TS) | VERIFIED | `ipns/index.ts:98,102` try/finally `params.ipnsPrivateKey.fill(0)`; `vault/index.ts:53,58` try/finally `vaultKeyKeypair.privateKey.fill(0)`; `folder/index.ts:179` "CALLER RETAINS OWNERSHIP — do NOT zero" comment; guard tests at `__tests__/ipns.test.ts:254,275` and `__tests__/vault.test.ts:83`; folder SKIP guard at `__tests__/folder.test.ts:428`; S2 regression guard at `__tests__/ipns.test.ts:204` |

**Score:** 10/10 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `apps/api/src/ipns/ipns.service.ts` | S1 embedded-vs-DTO CID + offset-aware sequence validation | VERIFIED | Contains `BadRequestException` throws at lines 267, 281, 289; `isFirstPublish = !existing` branch; CAS before S1 ordering |
| `apps/api/src/ipns/ipns.service.spec.ts` | S1 test cases: CID mismatch 400, seq mismatch 400, first-publish tolerance, valid pass-through | VERIFIED | 79 tests total, 79 passing; 6 new S1 cases |
| `apps/web/src/services/ipns.service.ts` | Fail-closed web IPNS resolve mirroring sdk-core behavior | VERIFIED | Throws at lines 181, 188-191; outer 404 catch at line 207 narrowed to `status === 404`; no swallowing try/catch |
| `apps/web/src/services/__tests__/ipns.service.test.ts` | NEW vitest file covering present-but-invalid throw, absent-fields allow+flag, 404 null, non-404 propagation | VERIFIED | File exists with `.test.ts` suffix; 15 `it`/`test` entries; 60 web tests passing |
| `crates/api-client/src/types.rs` | IpnsResolveResponse with signature_v2 / data / pub_key Option\<String\> fields | VERIFIED | Lines 138, 142 confirm `signature_v2`, `pub_key` as `Option<String>` with camelCase serde |
| `crates/api-client/src/ipns.rs` | verify_ipns_resolve_signature fn + `#[cfg(test)]` module | VERIFIED | `pub fn verify_ipns_resolve_signature` at line 64; `#[cfg(test)] mod tests` at line 169 with 5+ test cases |
| `crates/crypto/src/ecies.rs` | unwrap_key returning Zeroizing\<Vec\<u8\>\> | VERIFIED | Line 38: `pub fn unwrap_key(...) -> Result<Zeroizing<Vec<u8>>, CryptoError>`; line 7: `use zeroize::Zeroizing;` |
| `crates/fuse/src/lib.rs` | Callers honoring verify result + Zeroizing BFS queue + Zeroizing get_folder_key return | VERIFIED | Line 933: `get_folder_key` returns `Option<Zeroizing<Vec<u8>>>`; line 1617: BFS queue `VecDeque<(String, Zeroizing<Vec<u8>>)>`; line 1643: `verify_ipns_resolve_signature` 4-arm match |
| `crates/api-client/Cargo.toml` | cipherbox-crypto workspace dependency | VERIFIED | Line 16: `cipherbox-crypto = { workspace = true }` |
| `packages/sdk-core/src/ipns/index.ts` | try/finally fill(0) on createAndPublishIpnsRecord ipnsPrivateKey | VERIFIED | Lines 98-102: `} finally { params.ipnsPrivateKey.fill(0); }` |
| `packages/sdk-core/src/vault/index.ts` | try/finally fill(0) on vaultKeyKeypair.privateKey | VERIFIED | Lines 53-58: `} finally { vaultKeyKeypair.privateKey.fill(0); }` |
| `packages/sdk-core/src/folder/index.ts` | Documented zeroization decision for updateFolderMetadataAndPublish | VERIFIED | Line 179: "CALLER RETAINS OWNERSHIP — do NOT zero" comment with documented skip rationale |
| `packages/sdk-core/src/__tests__/ipns.test.ts` | S3 zeroization guard for createAndPublishIpnsRecord + S2 regression test | VERIFIED | Lines 254, 275: `.every((b) => b === 0)` assertions; line 204: S2 regression guard |
| `packages/sdk-core/src/__tests__/vault.test.ts` | S3 zeroization guard for publishVaultKeyBlob | VERIFIED | Line 83: `expect(privateKeyBuf.every((b) => b === 0)).toBe(true)` |
| `packages/sdk-core/src/__tests__/folder.test.ts` | S3 SKIP guard for updateFolderMetadataAndPublish | VERIFIED | Line 428: `'SKIP guard: does NOT zero ipnsPrivateKey or folderKey (caller retains ownership)'` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `ipns.service.ts upsertFolderIpns` | `parseIpnsRecord` | reuse already-parsed record; parse once on first-publish path | WIRED | Lines 222-259 hoist `incomingParsed`; S1 block reuses it |
| `web ipns.service.ts resolveIpnsRecord` | `verifyIpnsSignature + deriveIpnsName` | throw on !valid and on name mismatch | WIRED | Lines 179-191: call verify, throw on false, call deriveIpnsName, throw on mismatch |
| `web ipns.service.ts outer catch` | `null return` | narrow status === 404 only | WIRED | Line 207: `if (error instanceof Error && (error as ...).status === 404)` |
| `crates/fuse/src/lib.rs resolve_folder_key` | `verify_ipns_resolve_signature` | 4-arm match: warn/proceed/error/error | WIRED | Lines 1643-1665: full match with all four arms |
| `crates/api-client/src/ipns.rs verify_ipns_resolve_signature` | `cipherbox_crypto::verify_ed25519 + derive_ipns_name` | Ed25519 verify + name binding | WIRED | Lines 82-118: decode, prepend prefix, verify_ed25519, convert pubkey, derive_ipns_name |
| `packages/sdk-core/src/ipns/index.ts createAndPublishIpnsRecord` | `params.ipnsPrivateKey.fill(0)` | try/finally (T-47-01) | WIRED | Lines 98-103 |
| `packages/sdk-core/src/vault/index.ts publishVaultKeyBlob` | `vaultKeyKeypair.privateKey.fill(0)` | try/finally (T-47-01) | WIRED | Lines 53-58 |

### Behavioral Spot-Checks

Static analysis only — test suites were confirmed green during execution; re-running full concurrent suites is excluded per project constraint (RAM starvation risk). Commit-level evidence is strong:

| Behavior | Commit evidence | Status |
|----------|----------------|--------|
| S1: 79 API ipns.service.spec tests green | `da7e2d2b8` (GREEN commit) | PASS |
| S2 web: 60 web tests green | `6669f6567` (GREEN commit) | PASS |
| S2/S3 Rust: cargo test -p cipherbox-api-client (6) + -p cipherbox-fuse (60) green | `c253b5cc7` (final Rust commit) | PASS |
| S3 TS: 209 sdk-core tests green | `f6319af9f` + `df58bac56` | PASS |

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| (none) | No TBD/FIXME/XXX markers found in any modified file | — | Clean |
| `packages/sdk-core/src/ipns/index.ts:199` | `return null` | Info | Legitimate not-found return (IPNS 404), not a stub |
| `apps/api/src/ipns/ipns.service.ts:526,590` | `return null` | Info | Legitimate not-found returns, not stubs |

No blockers. No unresolved debt markers.

### Human Verification Required

None — all deliverables are verifiable via static analysis and commit evidence. All behaviors are either pure input validation (S1), synchronous throw paths (S2 TS), or type-system enforced (S3 Rust Zeroizing). No visual or real-time behavior involved.

### Requirements Coverage

| Requirement | Plans | Description | Status |
|-------------|-------|-------------|--------|
| HARD-02 | 51-01, 51-02, 51-03, 51-04 | IPNS signedRecord validation, verification, and key zeroization | SATISFIED — all three sub-findings (S1/S2/S3) closed across all surfaces (API, web, sdk-core, Rust crates) |

---

## Deliverable Summary

**S1 (51-01) — Publish-time embedded-vs-DTO validation:** PASS

BadRequestException (400) gate inside `upsertFolderIpns` rejects signed records whose embedded CID differs from DTO `metadataCid` (strict) or whose sequence disagrees with `expectedSequenceNumber` (offset-aware). First-publish tolerance accepts 0n/1n offset. CAS (409) placed before S1 (400) so concurrent-modification errors remain authoritative. Anti-rollback 409 preserved unchanged. 6 new test cases, 79/79 passing.

**S2 web (51-02) — Web fail-closed resolve:** PASS

`resolveIpnsRecord` in `apps/web/src/services/ipns.service.ts` now mirrors sdk-core: throws on present-but-invalid signature (D-02), throws on pubKey→name mismatch (D-02), allows+flags absent fields with `signatureVerified=false` (D-03), outer catch narrows to `status === 404` only. New `.test.ts` test file with 6 cases discovered by vitest.

**S2+S3 Rust (51-03) — Rust verify + Zeroizing:** PASS

`IpnsResolveResponse` gains 3 optional sig fields; `verify_ipns_resolve_signature` implements all three branches (None/Some(false)/Some(true)); FUSE `resolve_folder_key` BFS loop applies 4-arm match gate; `ecies::unwrap_key` returns `Zeroizing<Vec<u8>>`; BFS queue and `get_folder_key` are Zeroizing throughout. `cipherbox-crypto` workspace dep added to `crates/api-client`. 66 Rust tests passing across both crates.

**S3 TS (51-04) — sdk-core key zeroization:** PASS

`createAndPublishIpnsRecord` and `publishVaultKeyBlob` zeroize terminal keys on all exit paths (try/finally fill(0), T-47-01 convention). `updateFolderMetadataAndPublish` documented as deliberate SKIP with caller-ownership rationale (all 9 call sites pass live session keys). Enforcement guard tests lock the convention: zero-assertion on ipns/vault paths, unchanged-buffer SKIP guard on folder path, S2 regression guard on resolve. 209 sdk-core tests passing.

---

_Verified: 2026-06-19_
_Verifier: Claude (gsd-verifier)_
