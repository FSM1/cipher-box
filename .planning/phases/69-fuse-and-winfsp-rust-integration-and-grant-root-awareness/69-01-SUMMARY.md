---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 01
subsystem: crypto
tags: [rust, serde, node-v3, codec, cross-language-kat]

# Dependency graph
requires:
  - phase: 62-unified-node-codec-core-keystone
    provides: "packages/core/src/node/{types,encode,decode}.ts and tests/vectors/node-codec.json (the frozen TS twin + KAT oracle this plan mirrors)"
provides:
  - "cipherbox_core::node::{Node, NodeKind, NodeContent, VersionEntry, SealedChildRef, NodeWriteBody, WriteChildRef, PublishedNode, NodeError}"
  - "cipherbox_core::node::{encode_node, decode_node, encode_published_node, decode_published_node}"
  - "crates/core/tests/node_codec_vectors.rs KAT harness against tests/vectors/node-codec.json body_vectors"
affects: [69-02, 69-10, fuse, sdk]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Wire-format struct pattern: private FolderRootWire/FileWire (encode) and FolderRootWireOwned/FileWireOwned (decode) structs with explicit field declaration order, avoiding serde's internally-tagged-enum ordering (which would force the tag first, conflicting with the schema-before-kind wire order)"
    - "serde `with` module helpers (base64_key, u64_as_string) for Vec<u8>->base64 and u64->decimal-string wire conversions, matching the TS encode.ts/decode.ts conventions"

key-files:
  created:
    - crates/core/src/node/types.rs
    - crates/core/src/node/encode.rs
    - crates/core/src/node/decode.rs
    - crates/core/src/node/mod.rs
    - crates/core/tests/node_codec_vectors.rs
  modified:
    - crates/core/src/lib.rs

key-decisions:
  - "Node enum variants (Folder/File/Root) each carry the full common field set (id, generation, created_at, modified_at) plus their kind-specific field (children or content) — Rust has no cross-variant shared-field mechanism, so duplicating the common fields per variant is the idiomatic way to make impossible states unrepresentable while still round-tripping the TS Node's flat common-field shape"
  - "SealedChildRef implements exactly the frozen NODE-03 five fields (name, ipnsName, generation, versionFloor, readKeySealed) with #[serde(deny_unknown_fields)] — the optional TS size/modifiedAt display mirrors are intentionally NOT added in this plan (out of the plan's stated must-haves; a future plan can add them additively)"
  - "This plan's KAT test exercises only node-codec.json's body_vectors (pure JSON codec, no AEAD) — seal_vectors (full AEAD seal/unseal) is deferred to a later Phase-69 plan that wires cipherbox_core::node to cipherbox-crypto's existing build_node_aad/encrypt_aes_gcm_aad primitives; encode_published_node/decode_published_node in this plan only (de)serialize the PublishedNode envelope treating readSealed/writeSealed as opaque caller-supplied base64 strings"
  - "NodeError is a distinct enum from folder.rs's FolderError (not reused), per the plan's explicit non-reuse instruction"

patterns-established:
  - "Rust Node codec module structure (types.rs/encode.rs/decode.rs/mod.rs) mirroring the TS packages/core/src/node/ layout 1:1, to be repeated by any future per-module Rust/TS twin pairs"

requirements-completed: [SC-04, SC-06]

coverage:
  - id: D1
    description: "Node enum (Folder/File/Root) + SealedChildRef + write-plane types (NodeWriteBody/WriteChildRef) exist in crates/core/src/node/, discriminated by kind so impossible states are unrepresentable"
    requirement: SC-04
    verification:
      - kind: unit
        ref: "crates/core/tests/node_codec_vectors.rs#sealed_child_ref_has_exactly_five_fields"
        status: pass
      - kind: unit
        ref: "crates/core/tests/node_codec_vectors.rs#sealed_child_ref_rejects_unknown_fields"
        status: pass
    human_judgment: false
  - id: D2
    description: "JSON codec (encode_node/decode_node) round-trips every Node variant and byte-matches the frozen cross-language KAT tests/vectors/node-codec.json body_vectors"
    requirement: SC-06
    verification:
      - kind: unit
        ref: "crates/core/tests/node_codec_vectors.rs#node_codec_round_trips_and_byte_matches_kat"
        status: pass
    human_judgment: false
  - id: D3
    description: "The codec is additive — crates/core/src/folder.rs legacy types remain untouched and cargo check --workspace stays green"
    verification:
      - kind: other
        ref: "cargo check --workspace (manual run during execution, all crates compile)"
        status: pass
    human_judgment: false

duration: 11min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 01: Unified Node Codec (Rust Twin) Summary

**Rust `Node`/`SealedChildRef`/`PublishedNode` JSON codec in `crates/core/src/node/` that byte-matches the frozen TS cross-language KAT `tests/vectors/node-codec.json`**

## Performance

- **Duration:** 11 min
- **Started:** 2026-07-06T02:40:09Z
- **Completed:** 2026-07-06T02:51:15Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Introduced `crates/core/src/node/` — the Rust twin of `packages/core/src/node/{types,encode,decode}.ts` — with `Node` (Folder/File/Root discriminated enum), `NodeKind`, `NodeContent`, `VersionEntry`, `SealedChildRef` (frozen NODE-03 five-field set), `NodeWriteBody`/`WriteChildRef` (write-plane types for wave-6 D-07), and `PublishedNode`
- `encode_node`/`decode_node` produce/parse JSON with a FIXED field order (schema, kind, id, generation, kind-specific children/content, createdAt, modifiedAt), verified byte-identical to `tests/vectors/node-codec.json`'s `body_vectors` across all three kinds (folder/file/root) plus GCM and CTR `VersionEntry` variants
- `SealedChildRef` rejects unknown fields (`#[serde(deny_unknown_fields)]`) and structurally excludes any write field, closing off the NODE-03 read/write separation at the type level
- Added `pub mod node;` to `crates/core/src/lib.rs` without touching `crates/core/src/folder.rs` — `cargo check --workspace` stays green across all 5 workspace crates (crypto, core, api-client, fuse, sdk, desktop)

## Task Commits

Each task was committed atomically:

1. **Task 1: RED — Node codec KAT harness against tests/vectors/node-codec.json** - `f4664bcc3` (test)
2. **Task 2: GREEN — Node enum + types + encode/decode codec** - `dca421bd2` (feat)

_TDD tasks: RED (compile-fails, module absent) → GREEN (module created, 3/3 tests pass)_

## Files Created/Modified

- `crates/core/src/node/types.rs` - `Node`/`NodeKind`/`NodeContent`/`VersionEntry`/`SealedChildRef`/`NodeWriteBody`/`WriteChildRef`/`PublishedNode`/`NodeError` + `base64_key`/`u64_as_string` serde wire-format helpers
- `crates/core/src/node/encode.rs` - `encode_node`, `encode_published_node` via private ordered wire structs (`FolderRootWire`, `FileWire`)
- `crates/core/src/node/decode.rs` - `decode_node`, `decode_published_node`, fail-closed on malformed/unknown-schema input (never panics)
- `crates/core/src/node/mod.rs` - re-export barrel for the `node` module
- `crates/core/src/lib.rs` - added `pub mod node;` (additive, no re-export at crate root to avoid `VersionEntry` name collision with the existing `crate::file::VersionEntry` re-export)
- `crates/core/tests/node_codec_vectors.rs` - KAT harness: non-vacuous vector-count guard, decode+re-encode byte-match assertion per vector, SealedChildRef five-field/unknown-field tests

## Decisions Made

- Node enum variants each carry the full common field set (id/generation/created_at/modified_at) alongside their kind-specific field — Rust enums cannot share fields across variants the way a TS flat-object-with-optional-fields can, so duplication is the correct way to preserve "impossible states unrepresentable" while still modeling the same logical shape as the TS `Node` type
- Used private ordered wire structs (`FolderRootWire`/`FileWire` for encode, `FolderRootWireOwned`/`FileWireOwned` for decode) instead of serde's internally-tagged enum representation — an internally-tagged enum would force the `kind` tag to serialize first, which conflicts with the required `schema`-before-`kind` field order in the frozen KAT
- Deferred `seal_vectors` (full AEAD-seal) KAT coverage to a later Phase-69 plan — this plan's `encode_published_node`/`decode_published_node` only (de)serialize the `PublishedNode` JSON envelope; the AEAD sealing itself (which would call `cipherbox-crypto`'s existing `build_node_aad`/`encrypt_aes_gcm_aad`) is out of this plan's stated file scope (`files_modified` lists no `seal.rs`)
- Kept `SealedChildRef` to exactly the five NODE-03 fields (no optional `size`/`modifiedAt` display mirrors) per the plan's literal must-haves — additive scope for a future plan if needed

## Deviations from Plan

None - plan executed exactly as written. One environment fix was required to unblock the commit hook (not a plan deviation, see below).

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Ran `pnpm install` to restore missing `node_modules` in the worktree**
- **Found during:** Task 1 commit (pre-commit hook)
- **Issue:** This worktree was freshly created for a Rust-only plan and had no `node_modules`, so the repo's `husky` pre-commit hook (`lint-staged`) failed with `Command "lint-staged" not found` — unrelated to any code change in this plan
- **Fix:** Ran `pnpm install --prefer-offline` in the worktree root to populate `node_modules` (reused local pnpm store, no new downloads); did not modify any `package.json`/lockfile
- **Files modified:** none (node_modules is gitignored)
- **Verification:** Subsequent `git commit` ran `lint-staged` successfully ("No staged files match any configured task" — expected, since only `.rs` files were staged)
- **Committed in:** N/A (environment-only fix, no commit needed)

---

**Total deviations:** 1 auto-fixed (1 blocking, environment-only)
**Impact on plan:** No code or scope changes. Required to keep pre-commit hooks running (no `--no-verify` used, per CLAUDE.md git workflow rules).

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `cipherbox_core::node::*` is available for downstream crates (`fuse`, `sdk`) to import once their respective Phase-69 plans wire read-chain navigation and rotation logic to the new Node model
- `crates/core/src/folder.rs` legacy types remain in place and fully functional — the 69-10 cutover plan can proceed once every consumer is migrated
- AEAD sealing (`sealNode`/`unsealNode` Rust twin) is the natural next increment: `cipherbox-crypto` already exposes `build_node_aad`/`encrypt_aes_gcm_aad`/`unseal_aes_gcm_aad` (used by `crates/crypto/tests/cross_language.rs`'s `node_aad_cross_language` test), so a follow-on plan can wire these into `cipherbox_core::node` and extend this KAT harness to also assert `node-codec.json`'s `seal_vectors`

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*

## Self-Check: PASSED

All created files verified present on disk (crates/core/src/node/{types,encode,decode,mod}.rs, crates/core/tests/node_codec_vectors.rs, this SUMMARY.md). All commit hashes verified in `git log --oneline --all` (f4664bcc3, dca421bd2, c065a2450).
