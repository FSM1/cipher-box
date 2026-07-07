---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 05
subsystem: rotation
tags: [rust, rotation, grant-root, sc3, rot-02, sdk]

# Dependency graph
requires:
  - phase: 69-02
    provides: crates/sdk/src/rotation/ module (RotationHighWater, RotationError)
provides:
  - "has_covering_grant pure predicate (leaf-first ancestry scan, dual-source cross-check)"
  - "maybe_rotate_on_scope_exit gating composition (ROT-02 zero-rotation short-circuit)"
affects: [69-07 (FUSE grant_scope module), 69-11 (delete/rename gating)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Injected async rotate closure (FnOnce() -> Future<Output = Result<(), RotationError>>) for testability, mirroring TS vi.fn() spy injection"
    - "AtomicUsize call-counter spy pattern for async closure invocation-count assertions"

key-files:
  created: [crates/sdk/src/rotation/scope.rs]
  modified: [crates/sdk/src/rotation/mod.rs, crates/sdk/src/rotation/high_water.rs, crates/sdk/src/lib.rs]

key-decisions:
  - "maybe_rotate_on_scope_exit's rotate closure returns Result<(), RotationError> directly (rather than a bespoke error type), so a rotate failure propagates via the ? operator without inventing a new error type at the call site"
  - "Added RotationError::RotateFailed(String) variant to carry rotate-closure failures distinctly from the existing generation/sequence-regression variants"

requirements-completed: [SC-03]

coverage:
  - id: D1
    description: "has_covering_grant pure predicate: leaf-first ancestry scan, true if any ancestor is in the relay-supplied active_grant_root_ipns_names OR equals local_grant_record.root_ipns_name (T-63-17 anti-malicious-relay cross-check)"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/scope.rs#tests (9 has_covering_grant cases including empty-ancestry, relay-only match, local-record-only match with empty relay set, leaf-is-root, non-covering combination)"
        status: pass
    human_judgment: false
  - id: D2
    description: "maybe_rotate_on_scope_exit invokes the injected rotate closure exactly once for a covered scope exit and zero times for a private mutation (ROT-02 short-circuit); rotate errors propagate as Err"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/sdk/src/rotation/scope.rs#tests (sc4_rot02_private_delete_triggers_zero_rotations, sc4_rot02_private_move_with_non_matching_sources_triggers_zero_rotations, calls_rotate_exactly_once_when_an_ancestor_is_a_relay_grant_root, calls_rotate_exactly_once_when_the_node_itself_is_the_relay_grant_root, does_not_call_rotate_more_than_once_when_multiple_ancestors_are_grant_roots, t63_17_relay_omits_grant_root_but_local_record_covers_ancestor_still_rotates, rotate_error_propagates_as_err_and_is_not_swallowed)"
        status: pass
    human_judgment: false

# Metrics
duration: 6min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 05: Grant-Root Scope-Exit Predicate Summary

**Ported `has_covering_grant` + `maybe_rotate_on_scope_exit` from `packages/sdk-core/src/rotation/scope.ts` to `crates/sdk/src/rotation/scope.rs` — the pure zero-rotation-vs-rotate decision at the heart of SC#3, with the anti-malicious-relay cross-check (T-63-17) intact.**

## Performance

- **Duration:** 6 min
- **Started:** 2026-07-06T03:13:24Z
- **Completed:** 2026-07-06T03:19:30Z
- **Tasks:** 1
- **Files modified:** 4 (1 created, 3 modified)

## Accomplishments
- `has_covering_grant(CoverageParams) -> bool`: pure, no-I/O, leaf-first ancestry scan cross-checking both the relay-supplied `active_grant_root_ipns_names` set and the client's own `local_grant_record` — either source covering an ancestor returns `true` (T-63-17 anti-malicious-relay defense)
- `maybe_rotate_on_scope_exit`: async gating composition that invokes an injected `rotate` closure exactly once when covered, zero times when private, and propagates a `rotate` failure as `Err` (fail-closed, never swallowed)
- 16 unit tests (9 for `has_covering_grant`, 7 for `maybe_rotate_on_scope_exit`) directly mirroring the shipped TS `scope.test.ts` spy-based assertions, including the SC#4/ROT-02 zero-rotation invariant and the T-63-17 cross-check case

## Task Commits

Each task was committed following the mandatory RED/GREEN TDD gate sequence for `type: tdd` plans:

1. **Task 1 RED: has_covering_grant + maybe_rotate_on_scope_exit (failing test)** - `ee1a24eb8` (test) — added `crates/sdk/src/rotation/scope.rs` with `todo!()` stubs and the full 16-case test module; confirmed all 16 tests fail (panic) before any implementation existed
2. **Task 1 GREEN: has_covering_grant + maybe_rotate_on_scope_exit (implementation)** - `3ac5b5240` (feat) — replaced the stubs with the real leaf-first scan and gating logic; all 16 tests pass, `cargo check --workspace` green

**Plan metadata:** (this commit, made by execute-plan step after SUMMARY.md)

_Note: this TDD plan produced a test → feat commit pair per the mandatory RED/GREEN gate sequence; no refactor commit was needed._

## Files Created/Modified
- `crates/sdk/src/rotation/scope.rs` - new module: `CoverageParams`, `LocalGrantRecord`, `ScopeExitResult`, `has_covering_grant`, `maybe_rotate_on_scope_exit`, plus 16 unit tests
- `crates/sdk/src/rotation/mod.rs` - added `pub mod scope;` and re-exported the new scope symbols
- `crates/sdk/src/rotation/high_water.rs` - added `RotationError::RotateFailed(String)` variant to carry rotate-closure failures
- `crates/sdk/src/lib.rs` - re-exported `has_covering_grant`, `maybe_rotate_on_scope_exit`, `CoverageParams`, `LocalGrantRecord`, `ScopeExitResult` from the crate root

## Decisions Made
- `maybe_rotate_on_scope_exit`'s `rotate: F where F: FnOnce() -> Fut, Fut: Future<Output = Result<(), RotationError>>` signature makes the closure itself responsible for producing a `RotationError` on failure, so the composition function can simply `?`-propagate it — no new error-conversion boundary was needed at this call site.
- Reused the existing `RotationError` enum (from 69-02's `high_water.rs`) rather than introducing a second rotation error type, adding one new `RotateFailed(String)` variant. This keeps a single error type flowing through the whole `rotation` module, matching the plan's specified `Result<ScopeExitResult, RotationError>` signature.

## Deviations from Plan

None - plan executed exactly as written. The plan's recommended Rust signature (from 69-RESEARCH.md Pattern 1) specified `Result<ScopeExitResult, String>` as a sketch, but the task's own `<action>` text explicitly calls for `Result<ScopeExitResult, RotationError>` — implemented exactly as the task specified, using the already-existing `RotationError` type from 69-02 plus one additive variant (Rule 2: minimal missing-functionality addition needed to make the specified signature compile — `RotationError` had no generic "closure failed" case).

## Issues Encountered
- An IDE/environment auto-formatter reformatted unrelated pre-existing lines in `crates/sdk/src/rotation/high_water.rs` (wrapping two `#[error(...)]` attributes to multi-line) as a side effect of running `rustfmt` on the touched files. This was out-of-scope drift unrelated to this task's changes, so it was reverted via `git checkout -- crates/sdk/src/rotation/high_water.rs` before committing, keeping only the intentional `RotateFailed` variant addition in that file.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `has_covering_grant`/`maybe_rotate_on_scope_exit` are ready for 69-07's FUSE `grant_scope` module (single shared call site, per Pitfall 1) and 69-11's delete/rename gating.
- The consuming FUSE code still needs to supply the mounted-tree ancestor walk (leaf-first `Vec<String>` of IPNS names) and the actual `rotate_read_from_node` closure — both out of scope for this plan per its `files_modified` list.
- No blockers identified for downstream plans.

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*
