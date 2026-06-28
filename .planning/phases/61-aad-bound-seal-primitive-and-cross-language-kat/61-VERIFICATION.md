---
phase: 61-aad-bound-seal-primitive-and-cross-language-kat
verified: 2026-06-28T00:00:00Z
status: passed
score: 4/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT — Verification Report

**Phase Goal:** The canonical AES-GCM+AAD seal primitive and its frozen byte encoding exist in both TypeScript and Rust with a committed known-answer test proving byte-identical output.
**Verified:** 2026-06-28
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad` exported from `packages/crypto`, each seal minting a fresh random IV | VERIFIED | `packages/crypto/src/aes/seal.ts` defines all three; barrel chain `aes/index.ts` → `src/index.ts` exports them; `generateIv()` called at top of both seal functions (L143, L51) |
| 2 | Byte-identical Rust twin in `crates/crypto` with domain separator, raw UUID bytes, 4-byte BE generation, role bytes 0x01–0x04 | VERIFIED | `crates/crypto/src/aes.rs::build_node_aad` encodes `b"cipherbox/node-seal/v1"` ‖ `0x00` ‖ `uuid.as_bytes()` (RFC-4122 field order) ‖ kind ‖ `generation.to_be_bytes()` ‖ role; all six AAD variants exported from `lib.rs` |
| 3 | Cross-language KAT asserted by both TS and Rust with length/role-set guard; both pass | VERIFIED | TS: `build-node-aad.test.ts::buildNodeAad cross-language KAT` asserts `aadVectors.length === 4` + sorted roles `[1,2,3,4]` before iterating; Rust: `cross_language.rs::node_aad_cross_language` asserts `aad_vectors.len() == 4`, iterates both `aad_vectors` and `seal_vectors`; both load from the single committed `node-aad.json`; caller confirms all suites green (196 TS, 91 Rust lib + 6 cross-language) |
| 4 | Sealed blob replayed under different `childId`/`role`/`generation` fails to unseal | VERIFIED | TS: eight rejection tests in `AAD transplant-resistance and negative suite (D-02, CRYPTO-03)` — wrong nodeId, wrong role, wrong generation, wrong kind, forged domain version, tampered tag, truncated blob; Rust: `unseal_aad_transplant_fails` + `build_node_aad_invalid_*` tests in `aes.rs` |

**Score:** 4/4 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/crypto/src/aes/seal.ts` | `buildNodeAad`, `sealAesGcmAad`, `unsealAesGcmAad` | VERIFIED | 222-line file; all three exported; implementations in named file, not barrel |
| `packages/crypto/src/utils/encoding.ts` | `uuidToBytes` (16 raw bytes via hex-parse, not UTF-8) | VERIFIED | Strips hyphens, validates 32-char cleaned string, delegates to `hexToBytes`; 16-byte output confirmed |
| `packages/crypto/src/aes/encrypt.ts` | `encryptAesGcmAad` | VERIFIED | Defined at L83 in named file |
| `packages/crypto/src/aes/decrypt.ts` | `decryptAesGcmAad` | VERIFIED | Defined at L87 in named file |
| `packages/crypto/src/__tests__/build-node-aad.test.ts` | TS KAT + transplant suite | VERIFIED | 485-line file at correct `src/__tests__/` path (not `__tests__/` root); discovered by vitest's `src/**` include |
| `tests/vectors/crypto/node-aad.json` | 4 `aad_vectors` (roles 0x01–0x04) + `seal_vectors` | VERIFIED | Valid JSON; 4 aad_vectors with roles 1–4; 1 seal_vector with fixed key/iv/plaintext/ciphertext |
| `crates/crypto/src/aes.rs` | `build_node_aad`, `seal_aes_gcm_aad`, `unseal_aes_gcm_aad`, `encrypt_aes_gcm_aad`, `decrypt_aes_gcm_aad` | VERIFIED | All five present; `build_node_aad` produces identical layout to TS; exported from `lib.rs` |
| `crates/crypto/tests/cross_language.rs` | `node_aad_cross_language` #[test] asserting both `aad_vectors` and `seal_vectors` | VERIFIED | Present; asserts `aad_vectors.len() == 4`; iterates both vector arrays; matches committed hex |
| `docs/adr/0003-aad-bound-node-seal-encoding.md` | Freeze ADR with byte layout table | VERIFIED | 45-byte layout documented; status: accepted; implementation pointers correct |
| `scripts/check-vector-parity.sh` | `node-aad.json` in EXPECTED_VECTORS | VERIFIED | Line 20: `"tests/vectors/crypto/node-aad.json"` in array |

### Key Link Verification

| From | To | Via | Status |
|------|----|-----|--------|
| `packages/crypto/src/index.ts` | `sealAesGcmAad`, `unsealAesGcmAad`, `buildNodeAad` | re-exports from `./aes` → `./seal` | WIRED |
| `packages/crypto/src/index.ts` | `uuidToBytes` | re-exports from `./utils` → `./encoding` | WIRED |
| `build-node-aad.test.ts` | `node-aad.json` | dynamic `import('../../../../tests/vectors/crypto/node-aad.json')` | WIRED |
| `cross_language.rs::node_aad_cross_language` | `node-aad.json` | `vectors_path("crypto/node-aad.json")` + `fs::read_to_string` | WIRED |
| `cross_language.rs::node_aad_cross_language` | `cipherbox_crypto::build_node_aad` | direct call | WIRED |
| `cross_language.rs::node_aad_cross_language` | `cipherbox_crypto::encrypt_aes_gcm_aad` | direct call for seal_vectors | WIRED |
| `crates/crypto/src/lib.rs` | all AAD functions | pub use from `aes` module | WIRED |
| `crates/crypto/Cargo.toml` | `uuid` crate | `uuid = { workspace = true }` | WIRED |

### Data-Flow Trace (Level 4)

Not applicable — this phase produces cryptographic primitives and test fixtures, not components that render dynamic data.

### Behavioral Spot-Checks

Vector-byte correctness is verifiable by static analysis: the committed hex `636970686572626f782f6e6f64652d7365616c2f763100...` decodes to exactly the 45-byte frozen layout (domain 22 ‖ null 1 ‖ UUID 16 ‖ kind 1 ‖ gen-BE 4 ‖ role 1). The Rust inline test `build_node_aad_matches_committed_vectors` hard-codes the same four hex strings independently. Caller confirms CI run: 196 TS tests green, 91 Rust lib tests + 6 cross-language tests green.

### Probe Execution

No phase-declared probes. `bash scripts/check-vector-parity.sh` confirms `node-aad.json` is registered in EXPECTED_VECTORS (line 20).

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| CRYPTO-01 | 61-01, 61-03 | `packages/crypto` exports `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad`, each seal minting fresh random IV | SATISFIED | All three in `seal.ts`, barrel-exported; `generateIv()` called per seal |
| CRYPTO-02 | 61-02, 61-04 | Byte-identical Rust twin with committed cross-language KAT | SATISFIED | `crates/crypto/src/aes.rs::build_node_aad`; `cross_language.rs::node_aad_cross_language` |
| CRYPTO-03 | 61-03 | Sealed blob replayed under different childId/role/generation fails to unseal | SATISFIED | 8-case transplant/negative suite in TS; `unseal_aad_transplant_fails` in Rust |
| TEST-02 | 61-01, 61-02, 61-04 | Single committed fixture asserted by both `packages/crypto/__tests__` and Rust `#[test]` | SATISFIED | `node-aad.json` loaded by both `build-node-aad.test.ts` and `cross_language.rs::node_aad_cross_language` |

Coverage: 4/4 requirements satisfied, 0 orphaned.

### Anti-Patterns Found

Scan of modified files (`packages/crypto/src/aes/seal.ts`, `packages/crypto/src/utils/encoding.ts`, `packages/crypto/src/__tests__/build-node-aad.test.ts`, `crates/crypto/src/aes.rs`, `crates/crypto/tests/cross_language.rs`, `tests/vectors/crypto/node-aad.json`):

No TBD, FIXME, XXX, or HACK markers found. No placeholder implementations, empty returns, or stubs detected. All functions have substantive bodies.

Prohibition checks from PLAN 01 frontmatter:

| Prohibition | Status |
|-------------|--------|
| buildNodeAad must never silently emit wrong-length AAD | NOT VIOLATED — all invalid inputs throw `CryptoError('INVALID_AAD_INPUT')` before returning |
| uuidToBytes must never produce 36 bytes (UTF-8-string-encoding bug) | NOT VIOLATED — strips hyphens, hex-parses, 16 raw bytes confirmed |
| Implementations must NOT live in any index.ts barrel (C-02 coverage exclusion) | NOT VIOLATED — `buildNodeAad`/`sealAesGcmAad`/`unsealAesGcmAad` in `seal.ts`; `uuidToBytes` in `encoding.ts`; barrels only re-export |

### Human Verification Required

None. All four success criteria are verifiable from source and the caller-confirmed CI results.

### Gaps Summary

No gaps. All four ROADMAP success criteria are implemented, wired, and guarded by committed tests. The frozen byte encoding in `node-aad.json` is consistent between the TS implementation, the Rust implementation, and the independently hard-coded hex in the Rust unit test — three independent derivations agree on every byte.

---

_Verified: 2026-06-28_
_Verifier: Claude (gsd-verifier)_
