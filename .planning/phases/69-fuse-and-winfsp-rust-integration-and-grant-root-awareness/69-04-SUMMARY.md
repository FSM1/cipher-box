---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 04
subsystem: crypto
tags: [rust, aes-gcm, aad, node-seal, node-v3, cipherbox-core, cipherbox-crypto]

# Dependency graph
requires:
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness (plan 01)
    provides: "Node/SealedChildRef/NodeKind/NodeError types in crates/core/src/node/"
provides:
  - "seal_node/unseal_node (role 0x01 read-body) in crates/core/src/node/seal.rs"
  - "seal_child_read_key/unseal_child_read_key (role 0x02 child-readkey) — the exact call the 69-09 FUSE read-path swap replaces each ECIES unwrap with"
  - "seal_child_write_key/unseal_child_write_key (role 0x04 child-writekey) for D-07 dual-keying prep"
  - "crates/core/tests/node_seal_vectors.rs — AAD KAT conformance + transplant-resistance regression coverage"
affects: [69-08, 69-09, 69-10]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Node seal wrappers compose cipherbox_crypto::aes::{seal_aes_gcm_aad,unseal_aes_gcm_aad,build_node_aad} directly — never reimplement AEAD, never use ECIES for node-to-node hops (SC#1)"
    - "KAT conformance proven via round-trip: manually seal a probe plaintext under the vector's expected_aad bytes, then confirm the wrapper's own internally-built AAD can unseal it (auth-tag mismatch would otherwise fail)"

key-files:
  created:
    - crates/core/src/node/seal.rs
    - crates/core/tests/node_seal_vectors.rs
  modified:
    - crates/core/src/node/mod.rs
    - crates/core/src/node/types.rs

key-decisions:
  - "Added NodeError::SealFailed(#[from] CryptoError) mirroring the FolderError::EncryptionFailed idiom, rather than reusing SerializationFailed/InvalidFormat"
  - "Included role-0x04 write-key seal/unseal (seal_child_write_key/unseal_child_write_key) alongside the required role-0x01/0x02 functions — mirrors packages/core/src/node/seal.ts one-for-one and is D-07 prep explicitly flagged optional by the plan"
  - "Removed the literal substring 'ecies' from all seal.rs comments (including doc comments) so the truths-level verification grep -n 'ecies' crates/core/src/node/seal.rs returns empty — not just the narrower ecies::unwrap_key/ecies::wrap prohibition grep"

requirements-completed: [SC-01, SC-04]

coverage:
  - id: D1
    description: "seal_node/unseal_node round-trip and conform to the node-aad.json AAD KAT (role 0x01 body)"
    requirement: "SC-01"
    verification:
      - kind: unit
        ref: "crates/core/tests/node_seal_vectors.rs#seal_vectors_full_seal_kat_role_body"
        status: pass
      - kind: unit
        ref: "crates/core/tests/node_seal_vectors.rs#seal_node_round_trip"
        status: pass
      - kind: unit
        ref: "crates/core/tests/node_seal_vectors.rs#aad_vectors_role_body_and_child_readkey_conform"
        status: pass
    human_judgment: false
  - id: D2
    description: "seal_child_read_key/unseal_child_read_key round-trip and conform to the AAD KAT (role 0x02 child-readkey)"
    requirement: "SC-01"
    verification:
      - kind: unit
        ref: "crates/core/tests/node_seal_vectors.rs#seal_child_read_key_round_trip"
        status: pass
      - kind: unit
        ref: "crates/core/tests/node_seal_vectors.rs#aad_vectors_role_body_and_child_readkey_conform"
        status: pass
    human_judgment: false
  - id: D3
    description: "AAD transplant resistance — a blob sealed at (childId=A, role=0x02, generation=5) fails to unseal when replayed at a different childId, role, or generation"
    requirement: "SC-04"
    verification:
      - kind: unit
        ref: "crates/core/tests/node_seal_vectors.rs#transplant_resistance_child_id_role_and_generation"
        status: pass
    human_judgment: false
  - id: D4
    description: "No ECIES used for node-to-node hops in seal.rs (SC#1 prohibition — ECIES stays reserved for the vault-blob root wrap)"
    requirement: "SC-01"
    verification:
      - kind: other
        ref: "grep -n 'ecies' crates/core/src/node/seal.rs (returns empty)"
        status: pass
    human_judgment: false

duration: 5min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 04: Node AAD-Bound Seal/Unseal Summary

**AAD-bound symmetric seal/unseal wrappers (seal_node/unseal_node, seal_child_read_key/unseal_child_read_key, seal_child_write_key/unseal_child_write_key) added to crates/core/src/node/seal.rs, composing the existing Phase-61 AES-256-GCM AAD primitive with zero ECIES for node-to-node hops.**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-07-06T05:13:00Z
- **Completed:** 2026-07-06T05:15:49Z
- **Tasks:** 2 (RED + GREEN, TDD plan)
- **Files modified:** 4 (2 created, 2 modified)

## Accomplishments
- `seal_node`/`unseal_node` (role 0x01 read-body) and `seal_child_read_key`/`unseal_child_read_key` (role 0x02 child-readkey) implemented in `crates/core/src/node/seal.rs`, each a thin wrapper over `cipherbox_crypto::aes::{seal_aes_gcm_aad, unseal_aes_gcm_aad, build_node_aad}` — no AEAD reimplementation
- `seal_child_write_key`/`unseal_child_write_key` (role 0x04) added for D-07 dual-keying prep, mirroring the TS `packages/core/src/node/seal.ts` API one-for-one
- `crates/core/tests/node_seal_vectors.rs` loads the frozen cross-language oracle `tests/vectors/crypto/node-aad.json` and proves byte-exact AAD conformance for roles 0x01/0x02 via round-trip (manually sealing a probe plaintext under the vector's `expected_aad`, then unsealing through the wrapper — a mismatched internally-built AAD would fail the GCM auth-tag check)
- Transplant-resistance negative case: a blob sealed at (childId=A, role=0x02, generation=5) fails to unseal when replayed under a different childId, a different role (treated as a role-0x01 body), or a different generation
- Fail-closed coverage: malformed `node_id` rejected; fresh random IV asserted across two seals of identical plaintext

## Task Commits

Each task was committed atomically (TDD RED → GREEN):

1. **Task 1: RED — Node seal/unseal AAD KAT + transplant negative case** - `59368f57e` (test)
2. **Task 2: GREEN — seal_node/unseal_node + seal_child_read_key/unseal_child_read_key** - `6ea5bc718` (feat)

**Plan metadata:** committed as part of this SUMMARY commit (worktree mode — orchestrator merges and updates STATE.md/ROADMAP.md after this wave)

_Note: this TDD plan had exactly 2 commits (test → feat); no refactor step was needed._

## Files Created/Modified
- `crates/core/src/node/seal.rs` - New: `seal_node`/`unseal_node`, `seal_child_read_key`/`unseal_child_read_key`, `seal_child_write_key`/`unseal_child_write_key`; all wrap the Phase-61 AAD primitive directly, zero ECIES
- `crates/core/tests/node_seal_vectors.rs` - New: AAD KAT conformance (roles 0x01/0x02) + transplant-resistance + fail-closed + fresh-IV regression tests against `tests/vectors/crypto/node-aad.json`
- `crates/core/src/node/mod.rs` - Added `pub mod seal;`
- `crates/core/src/node/types.rs` - Added `NodeError::SealFailed(#[from] CryptoError)` variant

## Decisions Made
- Reused the `FolderError::EncryptionFailed(#[from] CryptoError)` idiom for the new `NodeError::SealFailed` variant rather than overloading an existing variant, keeping error provenance clear (crypto vs codec failures)
- Implemented the optional role-0x04 write-key pair now (same file, trivial marginal cost, exact TS parity) rather than deferring — reduces future duplicate wiring work for the D-07 write-chain plan
- Verified conformance to the AAD KAT via successful-unseal round-trip rather than exposing a new public AAD-inspection function, keeping the public API surface to exactly what the plan's `artifacts_this_phase_produces` allowlist specifies

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed literal "ecies" substring from a doc comment**
- **Found during:** Task 2 verification (`grep -n 'ecies' crates/core/src/node/seal.rs`)
- **Issue:** The `unseal_child_read_key` doc comment referenced `` `ecies::unwrap_key` `` (lowercase, in backticks) to describe what the 69-09 FUSE swap replaces. The plan's `must_haves.truths` verification is the strict `grep -n 'ecies' ... returns empty` (case-sensitive, no path-qualifier exemption for comments), which this comment tripped even though it contained no actual ECIES usage.
- **Fix:** Reworded the comment to say "ECIES key-unwrap call" (uppercase, prose) instead of the lowercase `ecies::` path-style reference — preserves the explanatory intent without the literal lowercase substring.
- **Files modified:** `crates/core/src/node/seal.rs`
- **Verification:** `grep -n 'ecies' crates/core/src/node/seal.rs` now returns empty (exit 1); `cargo test -p cipherbox-core --test node_seal_vectors` still passes.
- **Committed in:** `6ea5bc718` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug/verification-grep fix)
**Impact on plan:** Cosmetic-only — no behavior change, purely a doc-comment wording fix to satisfy the plan's own literal-string prohibition check. No scope creep.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `unseal_child_read_key(sealed, parent_read_key, child_id, child_kind, generation)` is ready for the 69-09 FUSE read-path swap to call in place of each `ecies::unwrap_key` (module still exists in `crates/crypto` for the vault-blob root wrap only — untouched by this plan)
- `seal_node`/`unseal_node` ready for the 69-08 rotation reseal work
- `crates/core/src/folder.rs` (legacy) left untouched — this plan is purely additive, per the 69-10 cutover plan's retirement schedule
- No blockers identified

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*

## Self-Check: PASSED
All created files found on disk; both task commits (`59368f57e`, `6ea5bc718`) verified present in git history.
