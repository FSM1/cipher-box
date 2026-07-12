---
phase: 80-rotation-write-plane-and-re-mint-durability
plan: 01
subsystem: crypto
tags: [node-codec, serde, recipient-pins, cross-language-kat, metadata-schema, d-03b]

# Dependency graph
requires:
  - phase: 62-node-codec
    provides: node/v3 NodeWriteBody codec, tests/vectors/node-codec.json seal_vectors[0]
  - phase: 69-rust-node-twin
    provides: crates/core node codec Rust twin + write-body seal KAT
provides:
  - "NodeWriteBody.recipient_pins (Rust Vec<Vec<u8>>) / recipientPins? (TS string[]) optional pin field"
  - "Conditional-emit codec (omit when empty) preserving frozen seal_vectors[0] bytes"
  - "seal_vectors[1] non-empty-pin cross-language KAT (Rust + TS byte-locked)"
  - "METADATA_SCHEMAS.md NodeWriteBody recipientPins documentation + version-history row"
affects: [80-04, 80-05, 80-06, 80-07, 80-08]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "base64_key_list serde helper: Vec<Vec<u8>> <-> JSON array of base64 strings"
    - "Additive optional metadata field via skip_serializing_if=Vec::is_empty (Rust) + conditional spread (TS)"

key-files:
  created: []
  modified:
    - crates/core/src/node/types.rs
    - crates/core/src/node/encode.rs
    - crates/core/src/node/seal.rs
    - crates/core/tests/node_write_body_vectors.rs
    - packages/core/src/node/types.ts
    - packages/core/src/node/encode.ts
    - packages/core/src/node/decode.ts
    - packages/core/src/__tests__/node-codec-vectors.test.ts
    - tests/vectors/node-codec.json
    - docs/METADATA_SCHEMAS.md

key-decisions:
  - "TS decode attaches recipientPins ONLY when non-empty (symmetric with encode), keeping existing writeBody round-trip toEqual green without mutating prior test literals"
  - "recipient_pins stored as raw pubkey bytes in-memory, base64 array on the wire, matching the existing ipnsPrivateKey base64 convention"
  - "Field order fixed as ipnsPrivateKey, writeChildren, recipientPins in both codecs for byte-identical cross-language wire"

patterns-established:
  - "base64_key_list: sibling of base64_key for a JSON array of base64-encoded byte vectors"
  - "Empty additive list is omitted from the wire on BOTH sides to preserve frozen golden vectors"

requirements-completed: ["SC2 / D-03a / D-03b: recipient-pubkey pin field on NodeWriteBody with Rust/TS wire parity"]

coverage:
  - id: D1
    description: "NodeWriteBody carries an optional recipientPins list that round-trips byte-identically in Rust and TS (non-empty-pin path locked by seal_vectors[1])"
    requirement: "SC2 / D-03a / D-03b: recipient-pubkey pin field on NodeWriteBody with Rust/TS wire parity"
    verification:
      - kind: unit
        ref: "crates/core/tests/node_write_body_vectors.rs#write_body_seal_matches_kat"
        status: pass
      - kind: unit
        ref: "packages/core/src/__tests__/node-codec-vectors.test.ts#folder node writeSealed with non-empty recipientPins matches frozen vector [1] (D-03b)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Frozen empty-pin KAT seal_vectors[0] preserved byte-for-byte via conditional emission (field omitted when empty)"
    verification:
      - kind: unit
        ref: "crates/core/src/node/encode.rs#write_body_round_trip_empty_children"
        status: pass
      - kind: unit
        ref: "packages/core/src/__tests__/node-codec-vectors.test.ts#folder node writeSealed base64 matches frozen vector"
        status: pass
    human_judgment: false
  - id: D3
    description: "Tolerant decode: write-body lacking recipientPins decodes to empty (Rust []) / absent (TS) and never throws"
    verification:
      - kind: unit
        ref: "crates/core/src/node/encode.rs#decode_write_body_defaults_missing_recipient_pins_to_empty"
        status: pass
    human_judgment: false
  - id: D4
    description: "METADATA_SCHEMAS.md documents recipientPins as an additive optional field with a version-history row"
    verification:
      - kind: manual_procedural
        ref: "docs/METADATA_SCHEMAS.md §8 NodeWriteBody + §3 version history; markdownlint pass"
        status: pass
    human_judgment: false

# Metrics
duration: 25min
completed: 2026-07-12
status: complete
---

# Phase 80 Plan 01: NodeWriteBody recipientPins Codec Field Summary

**Additive optional `recipientPins` pin list on `NodeWriteBody` (Rust `Vec<Vec<u8>>` / TS `string[]`) with conditional-emit codec, a new byte-locked cross-language `seal_vectors[1]` KAT, and the frozen empty-pin `seal_vectors[0]` preserved unchanged.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-07-12T17:10:00Z
- **Completed:** 2026-07-12T17:35:30Z
- **Tasks:** 3 (RED fixture + failing KATs; GREEN Rust; GREEN TS + docs)
- **Files modified:** 10

## Accomplishments

- Added `recipient_pins: Vec<Vec<u8>>` to Rust `NodeWriteBody` with a new `base64_key_list` serde helper and `#[serde(default, skip_serializing_if = "Vec::is_empty")]` so an empty list is omitted from the wire (no `deny_unknown_fields`).
- Mirrored `recipientPins?: string[]` in the TS codec: `encodeWriteBody` spreads the key only when non-empty; `decodeWriteBody` validates when present, tolerates absent, and stays symmetric with encode.
- Added `seal_vectors[1]` (two 33-byte compressed secp256k1 pins) to `tests/vectors/node-codec.json` and locked it byte-for-byte in both the Rust KAT and a new TS assertion block; `seal_vectors[0]` bytes unchanged.
- Documented the additive field in `docs/METADATA_SCHEMAS.md` (§8 NodeWriteBody) plus a §3 Node version-history row, per METADATA_EVOLUTION_PROTOCOL §3.1.

## Task Commits

Executed TDD-style locally (RED fixture + failing KATs observed to fail; GREEN Rust; GREEN TS + docs) and landed as a single atomic commit per orchestrator constraint 6 (SUMMARY rides with the code):

1. **Tasks 1-3 (RED→GREEN Rust→GREEN TS + docs + SUMMARY)** - see PLAN COMPLETE hash below (feat)

_RED was confirmed before implementing: the extended Rust KAT failed to compile against the pin-unaware struct (`E0560: NodeWriteBody has no field recipient_pins`), and the placeholder `writeSealed` forced an assertion mismatch that produced the committed ciphertext value._

## Files Created/Modified

- `crates/core/src/node/types.rs` - `NodeWriteBody.recipient_pins` field + `base64_key_list` serde module
- `crates/core/src/node/encode.rs` - round-trip tests: populated pins, empty-omission byte guard, tolerant-decode default
- `crates/core/src/node/seal.rs` - `sample_write_body()` construction updated with `recipient_pins: vec![]` (blocking-compile fix)
- `crates/core/tests/node_write_body_vectors.rs` - SealVector gains `recipient_pins`; loop decodes pins into the KAT write-body
- `packages/core/src/node/types.ts` - optional `recipientPins?: string[]`
- `packages/core/src/node/encode.ts` - conditional emission of `recipientPins` (only when non-empty)
- `packages/core/src/node/decode.ts` - validate-when-present, attach-when-non-empty (symmetric with encode)
- `packages/core/src/__tests__/node-codec-vectors.test.ts` - new `seal_vectors[1]` writeSealed assertion block
- `tests/vectors/node-codec.json` - `seal_vectors[1]` non-empty-pin fixture (frozen `seal_vectors[0]` untouched)
- `docs/METADATA_SCHEMAS.md` - `recipientPins` schema row + prose + Node version-history row

## Decisions Made

- **TS decode is symmetric with encode (attach `recipientPins` only when non-empty).** The plan text said "default absent/empty to `[]`", but unconditionally adding `recipientPins: []` broke the existing `folder node with writeBody seal→unseal` round-trip (`toEqual` treats `{recipientPins: []}` as unequal to a literal that omits the key). Omitting on empty preserves that test with zero test-literal edits, keeps encode/decode symmetric, and still satisfies the hard requirement "tolerate absent field, never throw" (Rust still yields an empty `Vec` via `#[serde(default)]`; the Rust-`[]`-vs-TS-`undefined` asymmetry is the accepted divergence called out in METADATA_EVOLUTION_PROTOCOL §6.2).
- **Reused the fixed key/IV of `seal_vectors[0]`** for `seal_vectors[1]`; only the added `recipientPins` changes the plaintext, so the differing `writeSealed` directly demonstrates the pin bytes flow into the seal.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated `sample_write_body()` in seal.rs for the new required struct field**

- **Found during:** Task 2 (Rust GREEN)
- **Issue:** Adding `recipient_pins` to `NodeWriteBody` broke compilation of an existing helper in `crates/core/src/node/seal.rs` (`E0063: missing field recipient_pins`). Not listed in `files_modified`.
- **Fix:** Added `recipient_pins: vec![]` to the `sample_write_body()` constructor.
- **Files modified:** crates/core/src/node/seal.rs
- **Verification:** `cargo test -p cipherbox-core --lib node` → 10 passed.
- **Committed in:** part of the plan commit.

---

**Total deviations:** 1 auto-fixed (1 blocking). No scope creep — required for the crate to compile.

## Issues Encountered

- **Worktree had no installed dependencies / crypto dist.** `pnpm --filter @cipherbox/core test` failed resolving `@cipherbox/crypto`. Resolved by `pnpm install --frozen-lockfile` (workspace links present) + `pnpm --filter @cipherbox/crypto build` (dist was unbuilt). Blocking-environment setup, not a code change.

## Notes / Verification

- **Test pass counts:** Rust `node_write_body_vectors` = 1 passed; Rust lib `node` unit = 10 passed, 0 failed; TS `node-codec-vectors` = 24 passed; `pnpm --filter @cipherbox/core typecheck` = ok.
- **cross_language.rs untouched:** `grep -c "node-codec.json" crates/crypto/tests/cross_language.rs` = 0 (it reads `crypto/node-aad.json`; its line-310 `seal_vectors.len() == 1` guard is a different oracle and stays green).
- **Recovery-tool tolerance (D-03b no-op):** `grep -rn "writeKey|writeSealed|NodeWriteBody|recipientPins" apps/web/recovery-src/` returns a single COMMENT match (`main.ts:126`, "read-only — no writeKey argument"), not a parse. The plan AC expected literally zero matches; the intent (recovery tool never parses `NodeWriteBody`, so it tolerates the new field by construction) holds. Minor AC-literal vs actual mismatch, no behavior impact.
- **No API/DB change:** client-side owner-sealed metadata field only; `pnpm api:generate` and migrations intentionally not run.

## Next Phase Readiness

- `NodeWriteBody.recipientPins` (both codecs) and `seal_vectors[1]` are available for the pin-issuance write (80-04) and the fail-closed enforcement consumers (80-06/07/08).

---

_Phase: 80-rotation-write-plane-and-re-mint-durability_
_Completed: 2026-07-12_
