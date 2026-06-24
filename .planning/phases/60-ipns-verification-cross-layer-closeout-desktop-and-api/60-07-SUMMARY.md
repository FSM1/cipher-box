---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
plan: 07
subsystem: infra
tags: [ipns, rust, typescript, ed25519, cbor, test-vectors, cross-language, parity-gate]

requires:
  - phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
    provides: plan 01 strict verifier (D-04 Legacy removed, strict seq equality, no skew disjunct)

provides:
  - tests/vectors/ipns/verify.json regenerated with legacy-absent and first-publish-skew both "invalid"
  - scripts/gen-ipns-verify-vectors.ts with D-04/D-05 strict expected_result values
  - crates/fuse/tests/ipns_verify_vectors.rs with strict classifier (None->invalid, no skew disjunct)
  - cross-language parity gate green (ipns_verify_cross_language passes)

affects:
  - Any future vector regeneration — generator is now the single source of truth for strict semantics

tech-stack:
  added: []
  patterns:
    - Vector generator as single source of truth — expected_result in generator, never hand-edited JSON
    - Strict cross-language parity gate: Rust classifier mirrors api-client bind_verified semantics exactly

key-files:
  created: []
  modified:
    - scripts/gen-ipns-verify-vectors.ts
    - tests/vectors/ipns/verify.json
    - crates/fuse/tests/ipns_verify_vectors.rs

key-decisions:
  - 'D-04 legacy-absent: expected_result "legacy" -> "invalid" in generator; absent fields fail-closed'
  - 'D-05 first-publish-skew: expected_result "valid" -> "invalid" in generator; skew disjunct removed'
  - 'Rust classifier: None arm -> "invalid".to_string() (was "legacy")'
  - 'Rust classifier: seq_ok = embedded_seq == resp_seq (strict; skew disjunct removed)'

patterns-established:
  - 'Generator-only reclassification: update generator source, regenerate JSON via npx tsx, commit both atomically'

requirements-completed: [HARD-11]

duration: 3min
completed: 2026-06-24
---

# Phase 60 Plan 07: Cross-Language Vector Reclassification Summary

**Cross-language IPNS verify vectors aligned to strict regime: legacy-absent and first-publish-skew reclassified to "invalid" in the generator, verify.json regenerated, and Rust classifier updated to strict equality + absent-fields-invalid so the parity gate is green**

## Performance

- **Duration:** 3 min
- **Started:** 2026-06-24T01:22:30Z
- **Completed:** 2026-06-24T01:25:30Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Reclassified `legacy-absent` from `"legacy"` to `"invalid"` in the generator (D-04: absent fields fail-closed)
- Reclassified `first-publish-skew` from `"valid"` to `"invalid"` in the generator (D-05: strict seq equality, skew disjunct removed)
- Regenerated `tests/vectors/ipns/verify.json` via `npx tsx scripts/gen-ipns-verify-vectors.ts` — only the 2 target cases changed, regeneration is idempotent
- Updated Rust classifier in `ipns_verify_vectors.rs`: `None => "invalid"` and strict `seq_ok = embedded_seq == resp_seq`
- `cargo test -p cipherbox-fuse --test ipns_verify_vectors` passes (1/1 — `ipns_verify_cross_language`)
- Scripts typecheck passes (`npx tsc -p tsconfig.scripts.json --noEmit`)

## Task Commits

1. **Task 1: Reclassify two vector cases in generator and regenerate verify.json** - `16bc518ea` (feat)
2. **Task 2: Update Rust vector-test classifier to strict semantics** - `ba39ff11f` (feat)

## Files Created/Modified

- `scripts/gen-ipns-verify-vectors.ts` — cases 7 and 8 expected_result updated; sanity-check array updated
- `tests/vectors/ipns/verify.json` — regenerated; legacy-absent and first-publish-skew now "invalid"
- `crates/fuse/tests/ipns_verify_vectors.rs` — None arm -> invalid; skew disjunct removed; doc comments updated

## Decisions Made

- Generator-only changes: no hand-editing of verify.json. The diff to verify.json comes entirely from running `npx tsx scripts/gen-ipns-verify-vectors.ts`.
- 2 vector cases reclassified: `legacy-absent` (was `"legacy"`) and `first-publish-skew` (was `"valid"`), both now `"invalid"`.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## Self-Check

- `grep -n "first-publish-skew\|legacy-absent"` in verify.json: both carry `"invalid"` — confirmed
- `grep -n 'None => "legacy"'` in ipns_verify_vectors.rs: not found — confirmed
- `grep -n 'resp_seq == 1 && embedded_seq == 0'` in ipns_verify_vectors.rs: not found — confirmed
- `cargo test -p cipherbox-fuse --test ipns_verify_vectors`: 1 passed, 0 failed — confirmed
- `npx tsc -p tsconfig.scripts.json --noEmit`: clean — confirmed

## Self-Check: PASSED

All acceptance criteria met. Git commits `16bc518ea` and `ba39ff11f` exist. Parity gate green.

## Next Phase Readiness

- Cross-language vector parity gate is the final code gate of the HARD-11 cutover
- All 8 vector cases have consistent semantics between the Rust verifier (plan 01) and the shared fixture
- Plan 08 (if any) or phase closeout can proceed

---

_Phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api_
_Completed: 2026-06-24_
