---
phase: 09-desktop-client
plan: 02
subsystem: desktop
tags: [rust, crypto, aes-gcm, ecies, ed25519, ipns, cbor, protobuf, cross-language]

# Dependency graph
requires:
  - phase: 09-desktop-client
    provides: 'Compilable Tauri v2 desktop app scaffold with all Rust dependencies'
provides:
  - 'Rust crypto module with AES-256-GCM, ECIES, Ed25519, IPNS matching TypeScript output'
  - 'IPNS record creation with CBOR data, V1+V2 signatures, protobuf marshaling'
  - 'IPNS name derivation (CIDv1 base36 k51...) from Ed25519 public key'
  - 'FolderMetadata/FolderEntry/FileEntry structs with serde camelCase serialization'
  - '51 cross-language tests verified against TypeScript @cipherbox/crypto'
affects: [09-03-fuse-filesystem, 09-04-auth-keychain, 09-05-api-client]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [
      Cross-language test vectors generated from TypeScript and hardcoded in Rust,
      Manual protobuf encoding for IPNS records matching ipns npm package,
      Manual CBOR encoding with ciborium matching ipns npm package field order,
      Base36 CIDv1 encoding for IPNS names without external multibase crate,
    ]

key-files:
  created:
    - apps/desktop/src-tauri/src/crypto/mod.rs
    - apps/desktop/src-tauri/src/crypto/aes.rs
    - apps/desktop/src-tauri/src/crypto/ecies.rs
    - apps/desktop/src-tauri/src/crypto/ed25519.rs
    - apps/desktop/src-tauri/src/crypto/utils.rs
    - apps/desktop/src-tauri/src/crypto/folder.rs
    - apps/desktop/src-tauri/src/crypto/ipns.rs
    - apps/desktop/src-tauri/src/crypto/tests.rs
    - apps/desktop/src-tauri/generate-test-vectors.mjs
  modified:
    - apps/desktop/src-tauri/src/main.rs

key-decisions:
  - 'Manual protobuf encoding instead of prost Message derive for exact field number control'
  - 'Manual base36 encoding via big integer division instead of multibase crate'
  - 'CBOR field order TTL,Value,Sequence,Validity,ValidityType matches ipns npm package'
  - 'Test vectors generated once from TypeScript, hardcoded as hex constants in Rust'
  - 'ecies crate v0.2 confirmed cross-compatible with eciesjs npm package'

patterns-established:
  - 'Cross-language crypto verification: generate vectors from TS, assert in Rust'
  - 'IPNS record format: CBOR data + Ed25519 V1+V2 signatures + protobuf envelope'

# Metrics
duration: 10min
completed: 2026-02-08
---

# Phase 9 Plan 2: Rust Crypto Module with Cross-Language Test Vectors Summary

> Rust-native AES-256-GCM, ECIES, Ed25519, IPNS crypto module producing byte-identical output to @cipherbox/crypto TypeScript, verified by 51 cross-language tests

## Performance

- **Duration:** 10 min
- **Started:** 2026-02-07T23:26:28Z
- **Completed:** 2026-02-07T23:36:17Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments

- Implemented complete Rust crypto module mirroring @cipherbox/crypto TypeScript module
- AES-256-GCM encrypt/decrypt/seal/unseal with identical sealed format (IV || ciphertext || tag)
- ECIES wrap/unwrap using `ecies` crate, confirmed cross-compatible with `eciesjs` npm package
- Ed25519 keygen/sign/verify with deterministic signatures identical to @noble/ed25519
- IPNS record creation with CBOR data, V1+V2 Ed25519 signatures, and protobuf marshaling
- IPNS name derivation producing identical CIDv1 base36 strings as TypeScript `deriveIpnsName`
- FolderMetadata with serde camelCase serialization matching TypeScript JSON format
- 51 tests passing including 5 critical cross-language verification tests

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement Rust AES-256-GCM, ECIES, Ed25519, and folder metadata** - `8d5201b` (feat)
2. **Task 2: Implement IPNS record creation and cross-language test vectors** - `d6490c3` (feat)

## Files Created/Modified

- `apps/desktop/src-tauri/src/crypto/mod.rs` - Module declarations and re-exports
- `apps/desktop/src-tauri/src/crypto/aes.rs` - AES-256-GCM encrypt/decrypt/seal/unseal
- `apps/desktop/src-tauri/src/crypto/ecies.rs` - ECIES wrap/unwrap with secp256k1
- `apps/desktop/src-tauri/src/crypto/ed25519.rs` - Ed25519 keygen/sign/verify/get_public_key
- `apps/desktop/src-tauri/src/crypto/utils.rs` - Random generation, hex encoding, zeroize
- `apps/desktop/src-tauri/src/crypto/folder.rs` - FolderMetadata/FolderEntry/FileEntry with camelCase serde
- `apps/desktop/src-tauri/src/crypto/ipns.rs` - IPNS record creation, marshaling, name derivation
- `apps/desktop/src-tauri/src/crypto/tests.rs` - 51 cross-language test vectors
- `apps/desktop/src-tauri/generate-test-vectors.mjs` - TypeScript test vector generator
- `apps/desktop/src-tauri/src/main.rs` - Added `mod crypto;` declaration

## Decisions Made

1. **Manual protobuf encoding for IPNS records** - Used direct byte encoding instead of prost Message derive macro. This gives exact control over field numbers (1-9) matching the IPNS spec, without needing to maintain a .proto file.

2. **Manual base36 encoding** - Implemented base36 using big-integer division rather than adding a `multibase` crate dependency. The algorithm is simple and only used for IPNS name derivation.

3. **CBOR field ordering matches ipns npm package** - The TypeScript `ipns` package encodes CBOR data with fields in order: TTL, Value, Sequence, Validity, ValidityType. The Rust implementation uses `ciborium::Value::Map` with explicit ordering to match this exactly.

4. **Test vector approach: pre-computed from TypeScript** - Rather than running Node.js from cargo test, generated test vectors once using `generate-test-vectors.mjs` and hardcoded the expected hex values in Rust tests. The script is committed for reproducibility.

5. **ecies crate confirmed cross-compatible** - The `ecies` Rust crate (v0.2.9) and `eciesjs` TypeScript package produce compatible output. Verified by wrapping in TypeScript and unwrapping in Rust with the same keypair.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Rust crypto module is complete and verified with 51 tests
- All cross-language format compatibility confirmed for AES, ECIES, Ed25519, and IPNS
- Ready for plan 09-03 (FUSE filesystem) which will use this crypto module for file operations
- Ready for plan 09-05 (API client) which will use IPNS record creation for folder updates

---

_Phase: 09-desktop-client_
_Completed: 2026-02-08_
