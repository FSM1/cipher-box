---
phase: 74-rust-and-fuse-rotation-revocation-soundness
plan: 05
subsystem: fuse
tags: [rust, fuse, rotation, sharing, grant-remint, sc2, rotation-transport-seam]

# Dependency graph
requires:
  - phase: 74-rust-and-fuse-rotation-revocation-soundness
    provides: "crates/api-client/src/shares.rs update_grant/revoke_share wire functions (74-04)"
provides:
  - "RotationTransport trait extended with collect_sent_shares/update_grant/revoke_share, implemented on both ApiClientTransport (production) and FakeTransport (test)"
  - "FuseRotationDeps::query_grants_rooted_at/update_grant/delete_grant real overrides (ROT-04 no-op default removed) delegating to the transport seam"
affects: [74-desktop-e2e, share-revocation, fuse-rotation]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "RotationTransport seam extension pattern: new grant ops mirror the existing resolve/fetch/publish trio, implemented once on ApiClientTransport (real) and once on FakeTransport (test), with FuseRotationDeps delegating generically over T: RotationTransport without ever reaching for a concrete ApiClient"

key-files:
  created: []
  modified:
    - crates/fuse/src/write_ops/rotation_deps.rs
    - crates/fuse/src/write_ops/implementation/delete.rs

key-decisions:
  - "RotationTransport::update_grant's new_generation param is typed u32 to match RotationDeps::update_grant's own generation param exactly (no conversion needed at the FuseRotationDeps delegation site); ApiClientTransport converts u32 -> u64 only at the final cipherbox_api_client::shares::update_grant call boundary"
  - "delete_grant is implemented for engine-contract completeness even though this query source's is_revoked is always false (revoked shares are hard-deleted server-side, per SentShareResponse's own doc comment) - no test asserts the is_revoked==true -> delete_grant branch firing through this path (RESEARCH Pitfall 2)"
  - "hex_to_bytes lives at cipherbox_crypto::utils::hex_to_bytes, not re-exported at the crate root - used via the full path"

patterns-established:
  - "Grant-seam adapter delegation: FuseRotationDeps's RotationDeps overrides never reach for self.transport.api directly (not reachable over generic T: RotationTransport); instead the seam trait itself grows the three grant methods, keeping the whole change inside rotation_deps.rs and leaving grant_scope.rs's ApiClientTransport construction site untouched"

requirements-completed: [SC2]

coverage:
  - id: D1
    description: "RotationTransport trait gains collect_sent_shares/update_grant/revoke_share, implemented on ApiClientTransport (forwards to the 74-04 wire functions) and FakeTransport (in-memory, test-only)"
    requirement: SC2
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#query_grants_rooted_at_filters_by_root_node_id_and_hex_decodes_recipient_key"
        status: pass
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#update_grant_forwards_through_the_transport_seam"
        status: pass
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#delete_grant_forwards_through_the_transport_seam"
        status: pass
    human_judgment: false
  - id: D2
    description: "FuseRotationDeps::query_grants_rooted_at filters collect_sent_shares by root_node_id == node_id and hex-decodes recipient_public_key (0x stripped, 04 prefix kept), always reporting is_revoked: false from this source"
    requirement: SC2
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#query_grants_rooted_at_filters_by_root_node_id_and_hex_decodes_recipient_key"
        status: pass
    human_judgment: false
  - id: D3
    description: "update_grant/delete_grant map transport errors to RotationError::RotateFailed and forward without re-wrapping key material"
    requirement: SC2
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#update_grant_transport_error_maps_to_rotate_failed"
        status: pass
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#delete_grant_transport_error_maps_to_rotate_failed"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-11
status: complete
---

# Phase 74 Plan 05: FuseRotationDeps Grant Re-mint Wiring Summary

**Wires the RotationTransport seam with three new grant operations (collect_sent_shares/update_grant/revoke_share) and replaces FuseRotationDeps's ROT-04 no-op grant methods with real overrides, so a desktop scope-exit rotation re-mints retained recipients instead of de-authorizing everyone**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-11T04:00:00Z (approx.)
- **Completed:** 2026-07-11T04:25:59Z
- **Tasks:** 2 (RED + GREEN)
- **Files modified:** 2

## Accomplishments

- `RotationTransport` trait extended with `collect_sent_shares`/`update_grant`/`revoke_share`, mirroring the existing `resolve`/`fetch_node`/`publish` seam pattern, implemented on both `ApiClientTransport` (forwards to the 74-04 `cipherbox_api_client::shares::{update_grant, revoke_share}` wire functions and `collect_sent_shares`) and the test `FakeTransport` (in-memory seed/capture, matching how it already captures `publish`).
- `FuseRotationDeps::query_grants_rooted_at` now calls `self.transport.collect_sent_shares()`, client-side-filters by `root_node_id == node_id`, and hex-decodes `recipient_public_key` (`0x` stripped, `04` uncompressed-key prefix kept) via `cipherbox_crypto::utils::hex_to_bytes`, always reporting `is_revoked: false` from this source.
- `FuseRotationDeps::update_grant` forwards the already-ECIES-wrapped key + generation through the seam without re-wrapping; `delete_grant` forwards `share_id` through `revoke_share`. Both map transport errors to `RotationError::RotateFailed`.
- Closes source todo `2026-07-08-desktop-query-grants-rooted-at-remint-noop` and advances SC2 — a desktop shared-scope-exit rotation now preserves access for still-authorized sharees instead of cutting off every recipient until re-shared.

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): FakeTransport unit tests for the three grant-seam methods** - `a9e18abf1` (test) — extended the `RotationTransport` trait with the three new required methods and `FakeTransport`'s implementation, plus 5 new tests driving `FuseRotationDeps::{query_grants_rooted_at, update_grant, delete_grant}`. `ApiClientTransport` did not yet implement the new trait methods, so `cipherbox-fuse` genuinely failed to compile (`E0046: not all trait items implemented`) — confirmed RED via `cargo test -p cipherbox-fuse write_ops::rotation_deps::`.
2. **Task 2 (GREEN): Implement query_grants_rooted_at / update_grant / delete_grant** - `4efdc35a9` (feat) — implemented the three methods on `ApiClientTransport` (delegating to the 74-04 wire functions) and replaced the `FuseRotationDeps` ROT-04 no-op comment block with real overrides delegating to `self.transport.*`. Scoped suite green: `cargo test -p cipherbox-fuse write_ops::rotation_deps::` (10/10) and the full crate suite (`cargo test -p cipherbox-fuse`, 117/117 + doc/integration tests).

_TDD plan: RED (Task 1) → GREEN (Task 2). No REFACTOR commit needed — the GREEN implementation matched the plan's target shape with no further cleanup required._

## Files Created/Modified

- `crates/fuse/src/write_ops/rotation_deps.rs` — `RotationTransport` trait gains `collect_sent_shares`/`update_grant`/`revoke_share`; `ApiClientTransport` and `FakeTransport` implement them; `FuseRotationDeps`'s three `RotationDeps` grant overrides replace the ROT-04 no-op defaults; 5 new `#[cfg(test)]` unit tests.
- `crates/fuse/src/write_ops/implementation/delete.rs` — the pre-existing `unlink_shared_scope_exit_fails_closed_until_rotation_wired` test's mock rotation server now routes `GET /shares/sent` to an empty page (see Deviations below).

## Decisions Made

- `RotationTransport::update_grant`'s `new_generation` param is typed `u32` — matching `RotationDeps::update_grant`'s own generation param exactly — so `FuseRotationDeps::update_grant` forwards without any conversion; `ApiClientTransport::update_grant` converts `u32 -> u64` only at the final `cipherbox_api_client::shares::update_grant` call boundary (that wire function's own `root_generation: u64` param, per 74-04).
- `delete_grant` is implemented for engine-contract completeness even though `is_revoked` is structurally always `false` from `collect_sent_shares` (revoked shares are hard-deleted server-side). No test asserts the `is_revoked == true -> delete_grant` branch firing through this particular query path (RESEARCH Pitfall 2) — that threat is dispositioned `accept` in the plan's threat register (T-74-14), not `mitigate`.
- `cipherbox_crypto::hex_to_bytes` is not re-exported at the crate root (only `clear_bytes`/`generate_file_key`/`generate_iv`/`generate_random_bytes` are) — called via the full path `cipherbox_crypto::utils::hex_to_bytes` instead.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Pre-existing `delete.rs` rotation test's mock server didn't route `GET /shares/sent`**
- **Found during:** Task 2 (GREEN implementation), full-crate verification
- **Issue:** `crates/fuse/src/write_ops/implementation/delete.rs`'s `unlink_shared_scope_exit_fails_closed_until_rotation_wired` test relied on `query_grants_rooted_at`'s ROT-04 no-op default never hitting the network. Once GREEN wired `query_grants_rooted_at` to genuinely call `self.transport.collect_sent_shares()` (→ `GET /shares/sent`), this test's `spawn_mock_rotation_server` fixture — which only routed `/ipns/resolve`, `/ipfs/upload`, `/ipfs/*`, and `/ipns/publish` — fell through to its 404 default for the new `/shares/sent` call, propagating a `RotationError::RotateFailed` and flipping the test's expected success (`reply_error_code == 0`) to EIO (`-5`).
- **Fix:** Added a `GET /shares/sent` route to the mock server's dispatch, returning an empty page (`{"shares":[],"total":0}`) — mirroring the ROT-04 no-op's `Vec::new()` behavior this test was originally written against, so the test's own pre-existing intent (a shared-scope-exit unlink succeeds) is preserved rather than altered.
- **Files modified:** `crates/fuse/src/write_ops/implementation/delete.rs`
- **Verification:** `cargo test -p cipherbox-fuse` — 117/117 passing (was 116/117 before this fix, with `unlink_shared_scope_exit_fails_closed_until_rotation_wired` the sole failure).
- **Committed in:** `4efdc35a9` (Task 2 GREEN commit)

**2. [Rule 1 - Bug] Fixed cargo fmt drift introduced by this task's own edits**
- **Found during:** Task 2 (GREEN implementation), post-implementation formatting check
- **Issue:** Manually-authored multi-line `map_err`/tuple blocks in the new `ApiClientTransport`/mock-server code didn't match `rustfmt`'s canonical single-line collapsing for short expressions.
- **Fix:** Ran `rustfmt --edition 2021` scoped to only the two files this plan touched (`rotation_deps.rs`, `delete.rs`) — confirmed via `cargo fmt -p cipherbox-fuse -- --check` that no diff remains for either file (the crate has substantial PRE-EXISTING fmt drift elsewhere, e.g. `file_handle.rs`/`helpers.rs`/`platform/*`, left untouched as out of scope per the executor's scope-boundary rule).
- **Files modified:** `crates/fuse/src/write_ops/rotation_deps.rs`, `crates/fuse/src/write_ops/implementation/delete.rs`
- **Verification:** `cargo fmt -p cipherbox-fuse -- --check` shows zero diff for both files; `cargo test -p cipherbox-fuse` remained 117/117 green after formatting.
- **Committed in:** `4efdc35a9` (Task 2 GREEN commit)

---

**Total deviations:** 2 auto-fixed (1 blocking-issue, 1 bug/formatting)
**Impact on plan:** Both auto-fixes were directly caused by this task's own wiring and stayed inside the two files already in scope (`rotation_deps.rs` was the plan's declared `files_modified`; `delete.rs`'s one-line mock-route addition was the minimal fix for a regression this task's own change introduced). No scope creep — `grant_scope.rs` was never touched.

## Issues Encountered

None beyond the deviations above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `grant_scope.rs` and `FuseRotationDeps::new`'s signature confirmed unchanged via `git diff --name-only` across both task commits (verified: `grant_scope.rs` never appears in either commit's file list).
- `cargo test -p cipherbox-fuse` is green (117/117 lib tests + 1 integration test + 0 doc tests).
- The desktop-e2e retained-vs-revoked recipient scenario (Pitfall 2's scoping guidance: a recipient with a grant on a DIFFERENT untouched node, proving `update_grant` fires) is a natural follow-up for a live-stack e2e leg, not covered by this plan's unit-level `FakeTransport` tests.
- No blockers for subsequent 74-xx plans.

---
*Phase: 74-rust-and-fuse-rotation-revocation-soundness*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: `.planning/phases/74-rust-and-fuse-rotation-revocation-soundness/74-05-SUMMARY.md`
- FOUND: commit `a9e18abf1` (RED)
- FOUND: commit `4efdc35a9` (GREEN)
- FOUND: `RotationTransport::{collect_sent_shares, update_grant, revoke_share}` in `crates/fuse/src/write_ops/rotation_deps.rs`
- FOUND: `FuseRotationDeps::{query_grants_rooted_at, update_grant, delete_grant}` real overrides in `crates/fuse/src/write_ops/rotation_deps.rs`
- CONFIRMED: `crates/fuse/src/write_ops/grant_scope.rs` absent from both task commits' file lists
