---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 15
subsystem: crypto
tags: [rust, aes-gcm, aad, node-seal, node-v3, write-plane, cipherbox-core, P1a-core]

# Dependency graph
requires:
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness (plan 01)
    provides: "Node/NodeWriteBody/WriteChildRef/PublishedNode types in crates/core/src/node/"
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness (plan 04)
    provides: "seal_node/unseal_node (role 0x01 read-body) + build_node_aad composition idiom in crates/core/src/node/seal.rs"
provides:
  - "encode_write_body/decode_write_body — the plaintext write-body codec in crates/core/src/node/{encode,decode}.rs"
  - "seal_published_node(node, read_key, write_key, write_body) — seals BOTH read-body and write-body, populating PublishedNode.write_sealed for the first time"
  - "crates/core/tests/node_write_body_vectors.rs — writeSealed cross-language KAT conformance"
affects: [69-16, 69-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "write_body passed as an EXPLICIT function parameter to seal_published_node rather than a Node-enum field — zero blast radius on existing Node::{Folder,File,Root} constructions, keeps the read-body KAT byte-identical"
    - "write-body seal reuses the SAME role-0x01 (ROLE_BODY) constant and kind_byte helper as the read-body seal, just under write_key instead of read_key — no new AAD role introduced"
    - "writeSealed KAT reproduced via the fixed-IV low-level seal path (encrypt_aes_gcm_aad + build_node_aad), mirroring crates/crypto/tests/cross_language.rs's seal_vectors idiom"

key-files:
  created:
    - crates/core/tests/node_write_body_vectors.rs
  modified:
    - crates/core/src/node/encode.rs
    - crates/core/src/node/decode.rs
    - crates/core/src/node/seal.rs
    - crates/core/src/node/mod.rs

key-decisions:
  - "seal_published_node is NOT re-exported via an explicit `pub use` in node/mod.rs, consistent with the existing precedent for seal_node/seal_child_read_key/seal_child_write_key — all are reached via the already-public `pub mod seal;` path (cipherbox_core::node::seal::seal_published_node)"
  - "Task 2's KAT test (node_write_body_vectors.rs) calls encode_write_body + the crypto-crate primitives directly (not seal_published_node) to reproduce writeSealed via the FIXED IV, since seal_published_node always generates a fresh random IV internally and cannot reproduce a fixed-IV vector"
  - "Verified the writeSealed KAT byte-match against the Python cryptography library independently before writing Rust code, confirming compact (no-whitespace) JSON with ipnsPrivateKey-then-writeChildren field order is the correct wire format"

requirements-completed: [SC-01, SC-04]

coverage:
  - id: D1
    description: "encode_write_body/decode_write_body round-trip a populated (>=1 WriteChildRef) and an empty-write_children NodeWriteBody byte-for-byte"
    requirement: "SC-04"
    verification:
      - kind: unit
        ref: "crates/core/src/node/encode.rs#write_body_tests::write_body_round_trip_populated"
        status: pass
      - kind: unit
        ref: "crates/core/src/node/encode.rs#write_body_tests::write_body_round_trip_empty_children"
        status: pass
    human_judgment: false
  - id: D2
    description: "decode_write_body fails closed (NodeError::DeserializationFailed, never panics) on malformed bytes"
    requirement: "SC-04"
    verification:
      - kind: unit
        ref: "crates/core/src/node/encode.rs#write_body_tests::decode_write_body_malformed_bytes_fail_closed"
        status: pass
    human_judgment: false
  - id: D3
    description: "seal_published_node seals both read-body and write-body when write_body is Some; write_sealed is None when write_body is None"
    requirement: "SC-01"
    verification:
      - kind: unit
        ref: "crates/core/src/node/seal.rs#seal_published_node_tests::both_bodies_populated_when_write_body_some"
        status: pass
      - kind: unit
        ref: "crates/core/src/node/seal.rs#seal_published_node_tests::write_sealed_none_when_write_body_none"
        status: pass
    human_judgment: false
  - id: D4
    description: "The write-body is recoverable via unseal_node(write_key) + decode_write_body; the READ key cannot open write_sealed (AAD-transplant/cross-key negative)"
    requirement: "SC-04"
    verification:
      - kind: unit
        ref: "crates/core/src/node/seal.rs#seal_published_node_tests::write_body_is_recoverable_via_unseal_and_decode"
        status: pass
      - kind: unit
        ref: "crates/core/src/node/seal.rs#seal_published_node_tests::aad_transplant_read_key_cannot_open_write_sealed"
        status: pass
    human_judgment: false
  - id: D5
    description: "The write-body seal is byte-identical to the frozen cross-language KAT (node-codec.json seal_vectors[0].expected_published_node.writeSealed) for the fixed key + fixed IV"
    requirement: "SC-01"
    verification:
      - kind: unit
        ref: "crates/core/tests/node_write_body_vectors.rs#write_body_seal_matches_kat"
        status: pass
    human_judgment: false
  - id: D6
    description: "encode_node/decode_node and the 69-01 read-body body_vectors KAT stay byte-identical (no Node-enum field added, no drift)"
    requirement: "SC-01"
    verification:
      - kind: unit
        ref: "crates/core/tests/node_codec_vectors.rs#node_codec_round_trips_and_byte_matches_kat"
        status: pass
    human_judgment: false
  - id: D7
    description: "No ECIES on the node-to-node write plane (encode_write_body/seal_published_node compose only cipherbox_crypto::aes)"
    requirement: "SC-01"
    verification:
      - kind: other
        ref: "grep -n 'ecies' crates/core/src/node/encode.rs crates/core/src/node/seal.rs (returns empty)"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 15: Node Write-Body Codec + Both-Bodies Seal (P1a-core) Summary

**Additive `crates/core` write-plane emit primitives — `encode_write_body`/`decode_write_body` (plaintext NodeWriteBody codec) and `seal_published_node` (seals BOTH read-body and write-body, populating `PublishedNode.write_sealed` for the first time) — with byte-exact cross-language KAT conformance and zero Node-enum changes.**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-07-06T11:06:00Z
- **Completed:** 2026-07-06T11:21:46Z
- **Tasks:** 2 (each combines RED test-first + GREEN implementation into a single task-scoped commit, per this plan's explicit `<done>` commit directives)
- **Files modified:** 5 (1 created, 4 modified)

## Accomplishments
- `encode_write_body`/`decode_write_body` added to `crates/core/src/node/{encode,decode}.rs` — a deterministic plaintext JSON codec for `NodeWriteBody{ipns_private_key, write_children}` with FIXED field order (`ipnsPrivateKey` then `writeChildren`), the Rust twin of TS `encodeWriteBody`/`decodeWriteBody`
- `seal_published_node(node, read_key, write_key, write_body: Option<&NodeWriteBody>)` added to `crates/core/src/node/seal.rs` — composes `encode_node`+`seal_node` (read-body, role 0x01/readKey) AND, when `write_body` is `Some`, `encode_write_body`+the role-0x01/writeKey seal, populating `PublishedNode.write_sealed` for the first time since its 69-01 introduction
- `write_body` is an explicit function parameter — no field was added to the `Node` enum (per research Pattern 1/Landmine 2), keeping the blast radius to new functions only and the 69-01 read-body KAT byte-identical
- New `crates/core/tests/node_write_body_vectors.rs` reproduces `tests/vectors/node-codec.json` `seal_vectors[0].expected_published_node.writeSealed` byte-for-byte via the fixed-IV low-level seal path (mirroring `crates/crypto/tests/cross_language.rs`), proving Rust `encode_write_body` + the writeKey seal matches the TS oracle (A2 resolved — no follow-up vector needed)
- AAD-transplant negative test: a blob sealed under `write_key` cannot be opened with `read_key` (GCM auth-tag mismatch, `Err` not panic)
- Fail-closed coverage: malformed write-body bytes return `NodeError::DeserializationFailed`, never panic

## Task Commits

1. **Task 1: encode_write_body / decode_write_body — the plaintext write-body codec** - `607dcc0e8` (feat)
2. **Task 2: seal_published_node — seal BOTH bodies + writeSealed KAT conformance** - `fc90bbb46` (feat)

**Plan metadata:** committed as part of this SUMMARY commit (worktree mode — orchestrator merges and updates STATE.md/ROADMAP.md after this wave)

_Note on TDD gate commits: this plan's own `<done>` tags specify a single commit per task (unlike 69-04's explicit RED-then-GREEN two-commit split). Tests were written first internally within each task (confirmed to fail to compile against not-yet-existing functions, then made to pass), but per the plan's authoritative commit instructions, RED and GREEN land in one task-scoped `feat(69-15): ...` commit rather than a separate `test(69-15): ...` commit. See "TDD Gate Compliance" below._

## Files Created/Modified
- `crates/core/src/node/encode.rs` - Added `encode_write_body` + inline `#[cfg(test)] mod write_body_tests` (round-trip populated/empty, malformed fail-closed)
- `crates/core/src/node/decode.rs` - Added `decode_write_body` (fail-closed serde idiom mirroring `decode_node`)
- `crates/core/src/node/seal.rs` - Added `seal_published_node` + inline `#[cfg(test)] mod seal_published_node_tests` (both-bodies, None-case, recovery, AAD-transplant negative)
- `crates/core/src/node/mod.rs` - Re-exported `encode_write_body`/`decode_write_body` from the top-level `pub use`; `seal_published_node` reached via the existing `pub mod seal;` (same precedent as `seal_node`/`seal_child_read_key`)
- `crates/core/tests/node_write_body_vectors.rs` - New: writeSealed cross-language KAT conformance test, non-vacuous vector-count guard

## Decisions Made
- Verified the `writeSealed` KAT byte-match independently via the Python `cryptography` library before writing any Rust code (compact JSON, `ipnsPrivateKey`-then-`writeChildren` field order, standard base64 for the raw key) — this confirmed the exact wire format ahead of implementation and avoided a guess-and-check loop against the frozen vector
- Did not add an explicit `pub use seal::seal_published_node;` re-export in `node/mod.rs`, following the established precedent that `seal.rs` functions are reached via the already-public `pub mod seal;` declaration (matches how `node_seal_vectors.rs` already imports `seal_node`/`seal_child_read_key` etc.)
- The KAT test (`node_write_body_vectors.rs`) calls `encrypt_aes_gcm_aad` + `build_node_aad` directly (the same low-level primitives `seal_published_node` composes internally) rather than calling `seal_published_node` itself, because `seal_published_node` always generates a fresh random IV — only the low-level fixed-IV path can reproduce a byte-exact KAT

## Deviations from Plan

None — plan executed exactly as written. `cargo fmt -p cipherbox-core` was run once during implementation and reformatted unrelated pre-existing files across the crate (a `cargo fmt -p <pkg>` invocation ignores trailing path arguments and reformats the whole package); those out-of-scope reformats were reverted via `git checkout --` before committing, keeping the diff scoped to exactly the plan's `files_modified` allowlist plus the new test file.

### TDD Gate Compliance

This plan's tasks each specify a single `feat(69-15): ...` commit in their `<done>` tag (unlike some other plans in this phase that split RED/GREEN into `test(...)` then `feat(...)` commits). Internally, tests were written before implementation and confirmed to fail (compile error against not-yet-existing `encode_write_body`/`decode_write_body`/`seal_published_node`) before the implementation was added — satisfying the fail-fast RED-before-GREEN discipline — but per the plan's own authoritative commit instructions, no separate `test(69-15): ...` commit exists in git history for this plan. Flagging this per the executor's TDD Gate Compliance protocol, since the plan intentionally deviates from the generic two-commit convention.

## Issues Encountered
None.

## User Setup Required
None — no external service configuration required.

## Next Phase Readiness
- `seal_published_node`/`encode_write_body`/`decode_write_body` are ready for 69-16's `crates/sdk` stateful emit orchestration (`create_folder_node`/`create_file_node`) to call directly
- `crates/fuse` and legacy `crates/core::folder` types remain untouched — this plan is purely additive, per the 69-10 cutover plan's retirement schedule
- No blockers identified

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*

## Self-Check: PASSED
All created/modified files found on disk; both task commits (`607dcc0e8`, `fc90bbb46`) verified present in git history.
