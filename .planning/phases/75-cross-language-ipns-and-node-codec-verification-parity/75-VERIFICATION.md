---
phase: 75-cross-language-ipns-and-node-codec-verification-parity
verified: 2026-07-11T09:05:00Z
status: passed
score: 3/3 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 75: Cross-Language IPNS and Node-Codec Verification Parity Verification Report

**Phase Goal:** Eliminate the Rust↔TS verification blind spots so the two implementations accept/reject byte-for-byte identically and the KATs actually pin encoding. Strict RFC3339 Validity parsing in TS matches the Rust verifier, `ValidityType==0` (EOL) is bound before Validity is treated as expiry on both sides, the node-codec KAT pins IV string encoding unambiguously, and the AAD UUID acceptance domain is identical in both languages — each locked by a cross-language vector.

**Verified:** 2026-07-11T09:05:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | SC1: malformed/out-of-range RFC3339 Validity AND `ValidityType!=0` records rejected identically by Rust and TS, covered by shared vectors | ✓ VERIFIED | `tests/vectors/ipns/verify.json` has 12 cases (4 new: `expired-valid-sig`, `wrong-validity-type`, `malformed-rfc3339-trailing-component`, `malformed-rfc3339-impossible-date`, all `expected_result: invalid`). Ran `cargo test -p cipherbox-fuse --test ipns_verify_vectors` → 1 passed (all 12 cases classify to `expected_result` via the real `pub fn bind_verified`). Ran `pnpm --filter @cipherbox/sdk-core test -- ipns` → `ipns.test.ts` 50 tests passed, including 4 dedicated per-vector tests (lines 719-800) that each throw on the corresponding malformed/EOL case. TS `resolveIpnsRecord` gates on `cborFields['ValidityType'] === 0` (index.ts:432-440) before treating Validity as expiry, mirroring Rust `bind_verified`'s `match validity_type { Some(0) => {}, ... }` gate (crates/api-client/src/ipns.rs:130-143). `parseRfc3339ToUnixSecs` (index.ts:195-291) branch-mirrors Rust's `parse_rfc3339_to_unix_secs` (crates/api-client/src/ipns.rs:210-...), including leap-year day-of-month and trailing-component rejection. |
| 2 | SC2: a hex-encoded `file_iv` FAILS the node-codec KAT (base64-only sample values, real decode-and-assert, not just a changed sample) | ✓ VERIFIED | `tests/vectors/node-codec.json` file-kind body vectors carry `fileIv` samples `Mo3oQ575VK8KZcAb` (12B GCM, contains uppercase letters — invalid hex) and `PIPKEVif5i10uwJJkNceZQ==` (16B CTR, `==`-padded — invalid hex), each with a sibling `expected_file_iv_len_bytes`. `crates/core/tests/node_codec_vectors.rs::node_codec_kat_file_iv_is_base64_not_hex` base64-decodes and asserts length (verified via direct read, lines 103-171); ran `cargo test -p cipherbox-core --test node_codec_vectors` → 4 passed including this test and the pre-existing round-trip test. `packages/core/src/__tests__/node-codec-vectors.test.ts` has a mirrored "fileIv Encoding Lock" describe block; ran `pnpm --filter @cipherbox/core test -- node-codec-vectors` → 23 tests passed. A hex decoder substituted for base64 would fail on both samples (confirmed programmatically: neither is a valid even-length lowercase-hex string). |
| 3 | SC3: TS and Rust accept exactly the same UUID acceptance domain in the AAD builder, locked by a cross-language KAT | ✓ VERIFIED | `tests/vectors/crypto/uuid-acceptance.json` (11 cases: 2 accept — canonical lower/upper-hyphenated; 9 reject — simple-32-hex, 2 loose-hyphen variants, braced, urn:uuid, non-hex-char, too-short, too-long, empty). TS `uuidToBytes` (packages/crypto/src/utils/encoding.ts:53-75) applies `CANONICAL_UUID_RE` to the raw input before hyphen-stripping. Rust `build_node_aad` (crates/crypto/src/aes.rs:157-209) applies a dependency-free `is_canonical_uuid_form` byte-position pre-check before `Uuid::parse_str`. Ran `pnpm --filter @cipherbox/crypto test -- build-node-aad` → 47 tests passed (build-node-aad.test.ts). Ran `cargo test -p cipherbox-crypto build_node_aad` (7 passed) and `cargo test -p cipherbox-crypto --test cross_language` → 7 passed including `uuid_acceptance_cross_language`. Confirmed no `regex`/`once_cell` dependency added to `crates/crypto/Cargo.toml` (grep empty). |

**Score:** 3/3 truths verified (0 present, behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `scripts/gen-ipns-verify-vectors.ts` | Extended generator, parameterized `buildCborData` | ✓ VERIFIED | Regenerating reproduces the 12-case fixture; idempotency claimed and structurally consistent with current `verify.json` |
| `tests/vectors/ipns/verify.json` | 12-case shared oracle | ✓ VERIFIED | `node -e` confirms 12 entries, 4 new cases all `expected_result: invalid` with correct descriptions |
| `crates/core/src/ipns.rs` | `decode_ipns_cbor_validity` returns `(Option<Vec<u8>>, Option<i64>)` with duplicate-key rejection | ✓ VERIFIED | Read directly, lines 142-181 |
| `crates/api-client/src/ipns.rs` | `bind_verified` widened to `pub`, ValidityType==0 gate | ✓ VERIFIED | `pub fn bind_verified` confirmed (line 66); gate at lines 126-143 |
| `crates/fuse/tests/ipns_verify_vectors.rs` | `classify_vector` delegates to `bind_verified`, count guard 12 | ✓ VERIFIED | No hand-spelled binding logic; calls `cipherbox_api_client::ipns::bind_verified` directly (line 85); `assert_eq!(vectors.len(), 12, ...)` (line 111) |
| `packages/sdk-core/src/ipns/index.ts` | `parseRfc3339ToUnixSecs` + ValidityType gate | ✓ VERIFIED | Both present and wired into `resolveIpnsRecord`; `new Date(validityStr)` absent (grep confirms no match) |
| `packages/sdk-core/src/__tests__/ipns.test.ts` | Malformed-timestamp cases + 12-count guard | ✓ VERIFIED | `toHaveLength(12)` present; 4 dedicated new-vector tests present and passing |
| `tests/vectors/node-codec.json` | Encoding-unambiguous base64 `fileIv` + `expected_file_iv_len_bytes` | ✓ VERIFIED | Confirmed via direct read/decode |
| `crates/core/tests/node_codec_vectors.rs` | base64-decode-and-assert-length block | ✓ VERIFIED | `node_codec_kat_file_iv_is_base64_not_hex` present and passing |
| `packages/core/src/__tests__/node-codec-vectors.test.ts` | base64-decode-and-assert-length it() | ✓ VERIFIED | "fileIv Encoding Lock" describe block present and passing |
| `tests/vectors/crypto/uuid-acceptance.json` | Cross-language accept/reject oracle | ✓ VERIFIED | 11 cases, 2 accept / 9 reject, fixed kind/generation/role params |
| `packages/crypto/src/utils/encoding.ts` | `uuidToBytes` canonical-only | ✓ VERIFIED | Confirmed via direct read |
| `crates/crypto/src/aes.rs` | `build_node_aad` canonical pre-check | ✓ VERIFIED | `is_canonical_uuid_form` wired before `Uuid::parse_str` |
| `packages/crypto/src/__tests__/build-node-aad.test.ts` | oracle-driven consumer | ✓ VERIFIED | 47 tests passing |
| `crates/crypto/tests/cross_language.rs` | oracle-driven consumer | ✓ VERIFIED | `uuid_acceptance_cross_language` passing |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `scripts/gen-ipns-verify-vectors.ts` (`buildCborData`) | `tests/vectors/ipns/verify.json` | committed generator run, real Ed25519 signing | WIRED | 12-case fixture is byte-consistent with generator's own case descriptions |
| `decode_ipns_cbor_validity` (ValidityType read) | `bind_verified` (== 0 gate + expiry) | direct function call | WIRED | Single call site at ipns.rs:120-143 |
| `bind_verified` (now `pub`) | `classify_vector` (thin wrapper) | direct function call, no duplicate logic | WIRED | ipns_verify_vectors.rs:85 |
| `resolveIpnsRecord` | `parseRfc3339ToUnixSecs` + `ValidityType===0` gate | direct call, inline gate | WIRED | index.ts:432-450 |
| `node-codec.json` `fileIv` (base64) | base64-decode assertion (Rust + TS) | `STANDARD.decode` / local `base64ToUint8Array` | WIRED | Confirmed both consumers decode, not merely round-trip |
| `uuid-acceptance.json` | `uuidToBytes` (TS, via `buildNodeAad`) AND `build_node_aad` canonical pre-check (Rust) | direct oracle-driven test consumption | WIRED | Both consumer test files load the same JSON and assert identical accept/reject verdicts |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Rust IPNS cross-language verify (12 cases) | `cargo test -p cipherbox-fuse --test ipns_verify_vectors` | 1 passed; 0 failed | ✓ PASS |
| TS sdk-core IPNS suite (incl. 12-case vector + 4 new-case tests) | `pnpm --filter @cipherbox/sdk-core test -- ipns` | 50/50 tests passed | ✓ PASS |
| Rust node-codec KAT (incl. fileIv encoding lock) | `cargo test -p cipherbox-core --test node_codec_vectors` | 4/4 passed | ✓ PASS |
| TS node-codec KAT (incl. fileIv Encoding Lock) | `pnpm --filter @cipherbox/core test -- node-codec-vectors` | 23/23 passed | ✓ PASS |
| Rust build_node_aad unit tests | `cargo test -p cipherbox-crypto build_node_aad` | 7/7 passed | ✓ PASS |
| Rust crypto cross-language suite (incl. UUID acceptance) | `cargo test -p cipherbox-crypto --test cross_language` | 7/7 passed | ✓ PASS |
| TS build-node-aad suite (incl. UUID acceptance oracle) | `pnpm --filter @cipherbox/crypto test -- build-node-aad` | 47/47 passed | ✓ PASS |
| Vector-parity meta-check (existing, unrelated to this phase's new files, sanity check) | `bash scripts/check-vector-parity.sh` | OK, parity check passed | ✓ PASS |
| Commit hashes referenced in all 5 SUMMARY.md files exist in git history | `git log --oneline -1 <hash>` × 16 | All 16 found | ✓ PASS |

### Requirements Coverage

Phase 75 is an M4-closeout phase mapping no `REQUIREMENTS.md` IDs (confirmed: `REQUIREMENTS.md` has no Phase 75 entries; ROADMAP.md explicitly lists 4 source todos and 3 Success Criteria instead). All 4 source todos are structurally addressed by the code:

| Todo | Status | Evidence |
|------|--------|----------|
| `2026-06-24-ts-resolve-strict-rfc3339-validity-parity` | ✓ SATISFIED | Plan 03 / SC1 (TS half) |
| `2026-06-24-harden-validity-type-and-vector-expiry-lockstep` | ✓ SATISFIED | Plans 01+02+03 / SC1 (both langs) |
| `2026-07-07-node-codec-kat-pin-file-iv-encoding` | ✓ SATISFIED | Plan 04 / SC2 |
| `2026-06-28-harden-uuid-acceptance-parity-aad-builder` | ✓ SATISFIED | Plan 05 / SC3 |

Note (housekeeping, not a code gap): all 4 source-todo files are still present under `.planning/todos/pending/` rather than moved to `.planning/todos/completed/`, despite each carrying `resolves_phase: 75` and being fully resolved in code. Spot-checking other recently-shipped phases (e.g. `resolves_phase: 74`) shows the same pattern — no pending todo for Phase 74 was found in `completed/` either — so this appears to be normal for this repo's workflow (todo retirement happens at a separate housekeeping step, not automatically during phase completion) rather than a Phase-75-specific miss. Flagged for awareness only; does not affect goal achievement.

### Anti-Patterns Found

None. Scanned all 15 files modified across the 5 plans for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER` — zero matches.

### Human Verification Required

None. All three Success Criteria are provable and were actually proven by running the real Rust `#[test]` and TS Vitest suites (not just reading SUMMARY.md claims) — every claimed test file, function, and gate was independently located, read, and its governing test executed in this session with observed pass output.

### Gaps Summary

No gaps. All 3 ROADMAP Success Criteria and all 4 source todos are verified against actual code (not SUMMARY narrative), with passing scoped test runs as evidence:

- SC1: Rust `bind_verified` (now `pub`) gates `ValidityType == 0` before treating `Validity` as expiry, using a strict `parse_rfc3339_to_unix_secs`; TS `resolveIpnsRecord` mirrors both with its own `parseRfc3339ToUnixSecs` and `ValidityType === 0` gate. Both reject the same 4 new fixture cases in the 12-case `verify.json`, proven by both `cargo test -p cipherbox-fuse --test ipns_verify_vectors` and `pnpm --filter @cipherbox/sdk-core test -- ipns`.
- SC2: `node-codec.json`'s `fileIv` samples are valid base64 / invalid hex, with both Rust and TS KATs now performing a real base64-decode-and-length-assert (not just an opaque string round-trip) — proven by `cargo test -p cipherbox-core --test node_codec_vectors` and `pnpm --filter @cipherbox/core test -- node-codec-vectors`.
- SC3: TS `uuidToBytes` and Rust `build_node_aad` both collapsed to canonical-only (Option A) UUID acceptance, locked by a new shared `uuid-acceptance.json` oracle consumed identically by both languages — proven by `cargo test -p cipherbox-crypto --test cross_language` and `pnpm --filter @cipherbox/crypto test -- build-node-aad`.

All 16 task commits referenced across the 5 SUMMARY.md files were confirmed present in git history. No stub code, no debt markers, no orphaned wiring, no regex/once_cell dependency creep in `crates/crypto`.

---

*Verified: 2026-07-11T09:05:00Z*
*Verifier: Claude (gsd-verifier)*
