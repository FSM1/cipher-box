---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 21
subsystem: crates/core
tags: [vault-blob, codec, cross-language-kat, root-key-recovery, node-v3]
requires:
  - tests/vectors/vault-v3-blob.json (frozen cross-language oracle)
  - packages/core/src/vault/blob.ts (TS port oracle)
provides:
  - cipherbox_core::serialize_vault_blob_v3
  - cipherbox_core::deserialize_vault_blob_v3
  - cipherbox_core::BLOB_V3_VERSION
affects:
  - 69-23 (consumes v3 codec for desktop init/recovery, after ECIES-wrapping)
tech-stack:
  added: []
  patterns:
    - runtime KAT loading via CARGO_MANIFEST_DIR + serde_json (mirrors node_codec_vectors.rs)
    - envelope-only codec (no crypto in the byte layer)
    - owned-copy deserialize (D-09, no aliasing the source blob)
key-files:
  created: []
  modified:
    - crates/core/src/vault_blob.rs
    - crates/core/src/lib.rs
decisions:
  - v3 codec is purely additive; v2 codec + all v2 tests byte-unchanged (live 69-20 desktop path still consumes v2 until 69-23 flips it)
  - deserialize returns OWNED Vec<u8> copies (.to_vec()) so a later blob zeroization cannot corrupt recovered keys (D-09, mirrors blob.ts .slice())
  - KAT vector drives the gate (loaded from disk, not hardcoded) so a future layout drift on either the Rust or TS side fails the test (D-04)
metrics:
  duration: ~10m
  completed: 2026-07-06
  tasks: 2
  files: 2
status: complete
---

# Phase 69 Plan 21: Rust vault-blob-v3 Codec + Cross-Language KAT Summary

Added the Rust `vault-blob-v3` serialize/deserialize codec to `crates/core/src/vault_blob.rs`, byte-identical to the frozen cross-language KAT `tests/vectors/vault-v3-blob.json` and to `packages/core/src/vault/blob.ts`, so a v3 vault minted on web opens on desktop and vice-versa. Purely additive — the legacy v2 codec is untouched.

## What Was Built

- `BLOB_V3_VERSION: u8 = 0x03`.
- `serialize_vault_blob_v3(enc_read, enc_write) -> Result<Vec<u8>, String>` — emits `0x03 | u16_BE(readLen) | enc_read | u16_BE(writeLen) | enc_write`; rejects empty or `> u16::MAX` segments.
- `deserialize_vault_blob_v3(blob) -> Result<(Vec<u8>, Vec<u8>), String>` — fail-closed parse (len >= 5, version check, both u16 length fields, both segment bounds), returns OWNED `(read_key, write_key)` copies (D-09).
- A cross-language KAT (`test_cross_platform_v3_vector`) that loads `tests/vectors/vault-v3-blob.json` at runtime via `env!("CARGO_MANIFEST_DIR")` + `serde_json`, asserts `hex::encode(serialize(...)) == expected_blob_hex` byte-for-byte, then round-trips deserialize back to the two keys.
- 13 additional v3 edge/error tests (empty, too-long, short, wrong-version, zero read/write length, truncated write header/body, minimal round-trip, near-u16 round-trip, owned-copy isolation).
- `crates/core/src/lib.rs` re-export extended with the three v3 symbols alongside the preserved v2 exports.

## v3 Wire Format Encoded (matches KAT byte-for-byte)

```
0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)
```

Big-endian u16 lengths, envelope-only (no crypto — caller supplies already-ECIES-wrapped bytes). Asserted against the frozen vector: `expected_blob_hex` begins `030081aa000102...` (version `0x03`, readLen `0x0081` = 129, read key `0xaa` then `0x00..0x7f`), and the write segment begins `...7f 0081 bb 000102...` (writeLen `0x0081` = 129, write key `0xbb` then `0x00..0x7f`). The KAT asserts the full string, not just the prefix.

## Green Boundary (verified in this worktree)

- `cargo check --workspace` — GREEN.
- `cargo test -p cipherbox-core --lib vault_blob` — 28 tests pass (14 pre-existing v2 + 14 new v3), including `test_cross_platform_v3_vector` (byte-identity + round-trip).
- v2 codec byte-unchanged: `git diff <base> -- crates/core/src/vault_blob.rs` shows no `-`/`+` lines touching any v2 symbol or v2 test.
- Envelope-only: `grep -nE 'ecies|wrap_key|seal|encrypt_aes' crates/core/src/vault_blob.rs` is empty.
- No new dependency: `crates/core/Cargo.toml` has no diff from base.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Reverted out-of-scope rustfmt drift**
- **Found during:** post-Task-2 working-tree check.
- **Issue:** `crates/core/src/ipns.rs` and `crates/core/src/node/decode.rs` (base-tree files, not fmt-clean at the fork point) showed pure-formatting diffs in the worktree, out of this plan's scope.
- **Fix:** `git checkout --` on both files, per the plan's fmt-scope rule (only `vault_blob.rs` + `lib.rs` are in scope). Working tree returned clean; not part of any 69-21 commit.
- **Files modified:** none committed (reverted).

## TDD Gate Compliance

- RED: `test(69-21): add failing vault-blob-v3 cross-language KAT` (300317e80) — KAT fails on stub while all 14 v2 tests stay green.
- GREEN: `feat(69-21): vault-blob-v3 codec byte-matching the cross-language KAT` (0e1f604bf) — KAT + round-trip pass.
- No REFACTOR commit needed.

## Known Stubs

None.

## Self-Check: PASSED

- `crates/core/src/vault_blob.rs` — FOUND (v3 symbols + KAT + edge tests).
- `crates/core/src/lib.rs` — FOUND (v3 re-export).
- Commit 300317e80 — FOUND.
- Commit 0e1f604bf — FOUND.
- Commit 04351dae1 — FOUND.
