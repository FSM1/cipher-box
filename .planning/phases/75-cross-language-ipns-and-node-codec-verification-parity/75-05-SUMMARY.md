---
phase: 75-cross-language-ipns-and-node-codec-verification-parity
plan: 05
subsystem: crypto
tags: [uuid, aad, aes-gcm, cross-language, ts, rust, kat]

# Dependency graph
requires:
  - phase: 61-node-seal-aad-hardening
    provides: buildNodeAad / build_node_aad (frozen "cipherbox/node-seal/v1" AAD encoding, D-00/D-03/D-04) and the node-aad.json byte-identity KAT
provides:
  - Canonical-only (Option A) UUID acceptance domain on both TS uuidToBytes (via buildNodeAad) and Rust build_node_aad
  - tests/vectors/crypto/uuid-acceptance.json shared accept/reject oracle
  - Cross-language KAT proving identical accept/reject verdicts (build-node-aad.test.ts + cross_language.rs)
affects: [phase-75-remaining-plans, any-future-aad-boundary-work]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Canonical-form pre-check applied to the RAW input before any normalization (hyphen-stripping in TS, byte-position scan in Rust) — closes the acceptance-domain gap rather than syncing two looser domains"
    - "Dependency-free byte-position UUID shape check in Rust (no regex/once_cell) to avoid adding a new crate dependency"
    - "Shared JSON oracle (accept/reject verdict, not byte output) as a cross-language parity KAT — distinct from node-aad.json's byte-identity KAT"

key-files:
  created:
    - tests/vectors/crypto/uuid-acceptance.json
  modified:
    - packages/crypto/src/utils/encoding.ts
    - packages/crypto/src/__tests__/build-node-aad.test.ts
    - crates/crypto/src/aes.rs
    - crates/crypto/tests/cross_language.rs

key-decisions:
  - "Option A (canonical-only) chosen over syncing the two looser domains — closes the AAD-transplant surface entirely rather than picking a common looser superset"
  - "Rust tightening implemented as a dependency-free byte-position check (is_canonical_uuid_form) rather than adding regex/once_cell, since neither was already a workspace dependency in crates/crypto"

patterns-established:
  - "UUID canonical-form pre-check: raw-input regex in TS (before hyphen-stripping), raw-input byte-position scan in Rust (before Uuid::parse_str) — apply this shape to any future node_id/UUID acceptance surface"

requirements-completed:
  - "SC3 (single canonical UUID acceptance domain in TS uuidToBytes and Rust build_node_aad, locked by a cross-language KAT)"
  - "todo:2026-06-28-harden-uuid-acceptance-parity-aad-builder"

coverage:
  - id: D1
    description: "tests/vectors/crypto/uuid-acceptance.json shared cross-language acceptance oracle exists with canonical accepts and non-canonical rejects"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "node -e vector-shape check (>=2 accept, >=6 reject) — see task 1 verify command"
        status: pass
    human_judgment: false
  - id: D2
    description: "TS uuidToBytes tightened to canonical-only (Option A); rejects simple-32-hex and loose-hyphen forms; agrees with the oracle for every case"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "packages/crypto/src/__tests__/build-node-aad.test.ts#uuidToBytes and #UUID acceptance-domain oracle (uuid-acceptance.json, SC3)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Rust build_node_aad gets a dependency-free canonical-form pre-check; rejects simple-32-hex, braced, and urn:uuid forms; agrees with the oracle and with TS for every case"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "crates/crypto/src/aes.rs#build_node_aad_* tests and crates/crypto/tests/cross_language.rs#uuid_acceptance_cross_language"
        status: pass
    human_judgment: false

duration: 8min
completed: 2026-07-11
status: complete
---

# Phase 75 Plan 05: UUID Acceptance-Domain Cross-Language Parity Summary

**Collapsed TS `uuidToBytes` and Rust `build_node_aad` onto a single canonical-only (Option A) UUID acceptance domain, locked by a new shared JSON oracle consumed by both languages.**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-07-11T06:08:00Z (approx, first commit 08:08:51+02:00)
- **Completed:** 2026-07-11T06:16:00Z (approx, last commit 08:14:52+02:00)
- **Tasks:** 3
- **Files modified:** 5 (1 created, 4 modified)

## Accomplishments

- Authored `tests/vectors/crypto/uuid-acceptance.json`, a shared accept/reject oracle covering canonical lower/upper-hyphenated UUIDs (accept) and simple-32-hex, loose-hyphen, braced `{…}`, `urn:uuid:…`, non-hex, wrong-length, and empty-string forms (reject).
- Tightened TS `uuidToBytes` (`packages/crypto/src/utils/encoding.ts`) to validate the canonical 8-4-4-4-12 hyphenated shape against the raw input BEFORE hyphen-stripping — closes the prior over-acceptance of simple-32-hex and loose-hyphen forms.
- Added a dependency-free canonical-form pre-check (`is_canonical_uuid_form`, byte-position scan) to Rust `build_node_aad` (`crates/crypto/src/aes.rs`), applied before `Uuid::parse_str` — closes the prior over-acceptance of simple-32-hex, braced, and `urn:uuid:` forms without adding a `regex`/`once_cell` dependency.
- Added oracle-driven cross-language consumers on both sides (`build-node-aad.test.ts` describe block, `cross_language.rs#uuid_acceptance_cross_language`) proving TS and Rust now produce the identical accept/reject verdict for every case in the shared oracle.
- Followed RED→GREEN TDD for both language tightenings (Tasks 2 and 3): failing tests were committed first against the pre-tightening implementations, confirmed to fail for the expected reasons, then the implementation change turned them green.

## Task Commits

Each task was committed atomically (Tasks 2 and 3 used RED→GREEN TDD, two commits each):

1. **Task 1: Author tests/vectors/crypto/uuid-acceptance.json** - `8c84330e6` (feat)
2. **Task 2 RED: failing canonical-only UUID acceptance tests** - `03ac0f675` (test)
2. **Task 2 GREEN: tighten TS uuidToBytes to canonical-only** - `6cd57ad6f` (feat)
3. **Task 3 RED: failing cross-language UUID acceptance oracle test** - `1362a3ed7` (test)
3. **Task 3 GREEN: canonical-form pre-check in Rust build_node_aad** - `f25450fcf` (feat)

**Plan metadata:** (this commit) `docs(75-05): complete UUID acceptance-domain parity plan`

## Files Created/Modified

- `tests/vectors/crypto/uuid-acceptance.json` - New shared accept/reject oracle (11 cases: 2 accept, 9 reject) with a fixed kind/generation/role triple reused from `node-aad.json`
- `packages/crypto/src/utils/encoding.ts` - `uuidToBytes` now validates canonical form against the raw input before hyphen-stripping
- `packages/crypto/src/__tests__/build-node-aad.test.ts` - Added direct-rejection tests (simple-32-hex, loose-hyphen) plus an oracle-driven accept/reject block
- `crates/crypto/src/aes.rs` - Added `is_canonical_uuid_form` byte-position pre-check, wired into `build_node_aad` before `Uuid::parse_str`
- `crates/crypto/tests/cross_language.rs` - Added `uuid_acceptance_cross_language` test driving `build_node_aad` over every oracle case

## Decisions Made

- **Option A (canonical-only) over syncing looser domains:** the RESEARCH.md finding was that TS was too loose in one direction (simple-32-hex, loose-hyphen) and Rust too loose in the other (braced, urn:uuid). Rather than picking a common looser superset that both would accept, both sides were tightened to accept *only* the canonical 8-4-4-4-12 hyphenated form — this closes the AAD-transplant surface entirely instead of just aligning it. Verified safe because no production caller or pre-existing test in the repo passes a non-canonical form; `crypto.randomUUID()` / `generate_uuid_v4()` always produce canonical lowercase-hyphenated output.
- **Dependency-free Rust pre-check:** `crates/crypto/Cargo.toml` has neither `regex` nor `once_cell` as a dependency. Per PATTERNS.md Pattern 6 guidance, a hand-rolled byte-position check (`is_canonical_uuid_form`) was used instead of adding either dependency — confirmed via `git diff crates/crypto/Cargo.toml` showing no changes.

## Deviations from Plan

None - plan executed exactly as written, including TDD RED→GREEN gates for Tasks 2 and 3.

## Issues Encountered

None. Both RED phases failed for the expected reasons before the corresponding GREEN implementation:
- TS RED: `uuidToBytes('550e8400e29b41d4a716446655440000')` and loose-hyphen forms did not throw (confirmed the strip-then-check implementation was over-accepting).
- Rust RED: `build_node_aad` with a simple-32-hex `node_id` returned `Ok` (confirmed `Uuid::parse_str` was over-accepting) before `is_canonical_uuid_form` was added.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC3 is fully met: TS `uuidToBytes` (via `buildNodeAad`) and Rust `build_node_aad` now accept exactly the canonical-only UUID acceptance domain, locked by `tests/vectors/crypto/uuid-acceptance.json`.
- Pre-existing byte-identity KAT (`node-aad.json`) and the full `@cipherbox/crypto` / `cipherbox-crypto` test suites remain green — no regressions.
- No new dependencies added; `cargo fmt -p cipherbox-crypto -- --check` and `cargo clippy -p cipherbox-crypto --tests` show only pre-existing, out-of-scope drift in unrelated files (`ipns_name.rs`), not in any file this plan touched.
- todo `2026-06-28-harden-uuid-acceptance-parity-aad-builder` is resolved by this plan.

---
*Phase: 75-cross-language-ipns-and-node-codec-verification-parity*
*Completed: 2026-07-11*

## Self-Check: PASSED

All 5 created/modified files verified present on disk; all 5 task commit hashes (8c84330e6, 03ac0f675, 6cd57ad6f, 1362a3ed7, f25450fcf) verified in git log.
