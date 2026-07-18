---
phase: 80-rotation-write-plane-and-re-mint-durability
plan: 02
subsystem: infra
tags: [rust, fuse, rotation, ipns, node-v3, write-body, seal, aead, caching]

# Dependency graph
requires:
  - phase: 80-01
    provides: NodeWriteBody.recipient_pins field on the Rust/TS node codec
provides:
  - reconstruct_write_body helper — rebuilds a rotated node's write-body from the in-memory InodeTable and re-seals it under the node's own write key at the NEW generation (ROLE_BODY 0x01)
  - ApiClientTransport::publish now injects a populated write_sealed for materialized rotated nodes (was always None), restoring owned-walkability and replay signing-seed durability
  - Job-scoped GET /shares/sent cache on FuseRotationDeps (<=1 fetch per rotation job)
  - FakeTransportInner collect_sent_shares call-counter test infra (reused by 80-06)
  - replay.rs rotation-then-replay signing-seed-recovery regression test
affects: [80-05, 80-06]

# Tech tracking
tech-stack:
  added: [tokio::sync::OnceCell]
  patterns:
    - "Reconstruct-and-reseal: rebuild a node's write plane from local InodeTable key material (read-key-rotation-independent) and re-seal at the node's new generation, never mutating the write plane"
    - "Job-scoped interior-mutable cache (OnceCell) on the once-per-job FuseRotationDeps to fetch-once/reuse across an immutable-borrow walk"

key-files:
  created:
    - .planning/phases/80-rotation-write-plane-and-re-mint-durability/80-02-SUMMARY.md
  modified:
    - crates/fuse/src/write_ops/rotation_deps.rs
    - crates/fuse/src/replay.rs
    - crates/sdk/src/emit.rs
    - crates/sdk/src/listing.rs
    - crates/fuse/src/content_ops.rs
    - crates/fuse/src/journal_helpers.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/write_ops/implementation/delete.rs
    - crates/fuse/src/platform/windows/write_ops.rs

key-decisions:
  - "Cache lives on FuseRotationDeps (generic over T), not ApiClientTransport as the plan text stated — Test C's locked contract (the FAKE transport's collect_sent_shares called <=1) can only be satisfied by caching at the layer that wraps transport.collect_sent_shares(). FuseRotationDeps is the once-per-job instance, so it is still job-scoped, not static/global."
  - "OnceCell (not RefCell) for the cache because query_grants_rooted_at is async — get_or_try_init never holds a borrow across .await and keeps the future Send."
  - "Child WriteChildRef.write_key_sealed is sealed at AAD generation 0, matching the established build_folder_metadata / build_child_refs write-splice convention (child write plane is not rotated here); only the node's own write-body ROLE_BODY seal uses the new generation."
  - "recipient_pins emitted empty by reconstruct_write_body — pin preservation (D-03b) is 80-05's concern once the field is populated on the inode; this reconstruction handles keys + children only."

patterns-established:
  - "reconstruct-and-reseal write body from InodeTable at a new generation, fail-open to None for non-materialized nodes"
  - "job-scoped OnceCell cache for a per-node fan-out relay fetch"

requirements-completed:
  - "SC1 / D-01: rotation republish reconstructs write_sealed from InodeTable; owned-walk + replay signing-seed recovery survive rotation"
  - "SC2-perf / D-02: cache GET /shares/sent once per rotation job instead of once per rotated node"

coverage:
  - id: D1
    description: "Rotation republish reconstructs a populated write_sealed for a materialized rotated node (D-01): write-body carries the node's own signing seed + child WriteChildRefs, re-sealed under the node's own write key at the new generation."
    requirement: "SC1 / D-01: rotation republish reconstructs write_sealed from InodeTable; owned-walk + replay signing-seed recovery survive rotation"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#reconstruct_write_body_round_trips_ipns_key_and_child_write_refs"
        status: pass
    human_judgment: false
  - id: D2
    description: "reconstruct_write_body fails open to None (never Err/panic) for a node not locally materialized (D-01b)."
    requirement: "SC1 / D-01: rotation republish reconstructs write_sealed from InodeTable; owned-walk + replay signing-seed recovery survive rotation"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#reconstruct_write_body_fails_open_to_none_for_a_non_materialized_node"
        status: pass
    human_judgment: false
  - id: D3
    description: "replay.rs::recover_signing_seed recovers a rotated node's signing seed from the reconstructed write_sealed — the 'no write_sealed body' fail path no longer fires after rotation+remount (T-80-04)."
    requirement: "SC1 / D-01: rotation republish reconstructs write_sealed from InodeTable; owned-walk + replay signing-seed recovery survive rotation"
    verification:
      - kind: unit
        ref: "crates/fuse/src/replay.rs#rotation_reconstructed_write_sealed_recovers_signing_seed"
        status: pass
    human_judgment: false
  - id: D4
    description: "A rotation walk over N (>=3) nodes fetches GET /shares/sent at most once, with root_node_id filtering + per-share parsing unchanged (D-02, T-80-06)."
    requirement: "SC2-perf / D-02: cache GET /shares/sent once per rotation job instead of once per rotated node"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#rotation_walk_fetches_sent_shares_at_most_once"
        status: pass
    human_judgment: false

# Metrics
duration: 45min
completed: 2026-07-12
status: complete
---

# Phase 80 Plan 02: Rotation write-plane reconstruction + sent-shares cache Summary

**Rotation republish reconstructs a populated write_sealed from the in-memory InodeTable (restoring owned-walkability and replay signing-seed durability) and caches GET /shares/sent to at most one fetch per rotation job.**

## Performance

- **Duration:** ~45 min
- **Tasks:** 3 (TDD: RED → GREEN → GREEN)
- **Files modified:** 9 (2 in-scope + 7 Rule-3 compile-unblock)

## Accomplishments
- **D-01:** `ApiClientTransport::publish` now reconstructs the write-body from the locally-materialized `InodeTable` (own write key + `ipns_private_key` + child `WriteChildRef`s copied verbatim from child inodes) and re-seals it via `seal_node` under the node's own write key at its NEW generation, injecting a populated `write_sealed` where the rotation engine emitted `None`. Fails open to `None` for a non-materialized node; never rotates/mutates the write plane. This removes the `list_folder_owned` "no write_sealed body" flood (T-80-05) and closes the `replay.rs::recover_signing_seed` durability hole (T-80-04).
- **D-02:** Added a job-scoped `tokio::sync::OnceCell` cache on `FuseRotationDeps` so a rotation walk fetches `GET /shares/sent` at most once instead of once per rotated node — per-share `root_node_id` filter and 0x-strip/hex-decode/error parsing are byte-for-byte unchanged.
- Locked all four contracts with regression tests (reconstruct round-trip, None fallback, <=1 sent-shares fetch, rotation-then-replay recovery).

## Task Commits

1. **Task 1: RED tests + compile-unblock** - `eaed02937` (test)
2. **Task 2: GREEN — reconstruct-and-reseal write body (D-01)** - `5c1ee8409` (feat)
3. **Task 3: GREEN — job-scoped sent-shares cache (D-02) + SUMMARY** - this commit (perf)

## Files Created/Modified
- `crates/fuse/src/write_ops/rotation_deps.rs` - `reconstruct_write_body` helper, `publish` wiring, job-scoped `OnceCell` sent-shares cache, `FakeTransportInner` call-counter, tests A/B/C
- `crates/fuse/src/replay.rs` - rotation-then-replay signing-seed-recovery regression test (Test D) + Rule-3 constructor fixes
- `crates/sdk/src/emit.rs`, `crates/sdk/src/listing.rs`, `crates/fuse/src/content_ops.rs`, `crates/fuse/src/journal_helpers.rs`, `crates/fuse/src/fs.rs`, `crates/fuse/src/write_ops/implementation/delete.rs`, `crates/fuse/src/platform/windows/write_ops.rs` - Rule-3 compile-unblock (`recipient_pins: Vec::new()` in downstream `NodeWriteBody` constructors)

## Decisions Made
- **Cache placement:** The plan text said "cache on `ApiClientTransport`", but Test C (the locked acceptance contract) asserts the FAKE transport's `collect_sent_shares` is called `<= 1`. That can only hold if caching happens at the layer wrapping `transport.collect_sent_shares()` — i.e. `FuseRotationDeps::query_grants_rooted_at`. `FuseRotationDeps` is the once-per-job instance (grant_scope.rs:488), so the cache remains job-scoped and instance-local, satisfying the "not static/global" prohibition. Bonus: no construction-site literal changes at grant_scope.rs:489 (the field is initialized inside `new()`).
- **`OnceCell` over `RefCell`:** the fetch is async; `get_or_try_init` holds no borrow across `.await`, keeping the deps future `Send` (a `RefCell` field would break `Send` for the spawned rotation walk).
- **Child splice generation 0:** child `WriteChildRef.write_key_sealed` is sealed at AAD generation `0`, matching the existing `build_folder_metadata` / `build_child_refs` convention. The node's own write-body ROLE_BODY seal uses the node's NEW generation (this is what `recover_signing_seed` rebuilds). The child write plane is not rotated here.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Downstream NodeWriteBody constructors left non-compiling by 80-01**
- **Found during:** Task 1 (initial `cargo check`)
- **Issue:** Plan 80-01 added the required `recipient_pins` field to `NodeWriteBody` but only fixed its own core-crate constructor. Every downstream `NodeWriteBody` constructor in `crates/sdk` and `crates/fuse` failed to compile (`E0063: missing field recipient_pins`), so the whole workspace — including the `cargo test -p cipherbox-fuse` target this plan must run — would not build. No sibling 80-x plan lists these constructors in its `files_modified`.
- **Fix:** Added `recipient_pins: Vec::new()` to all 11 downstream constructors across 7 files. Byte-identical wire behavior (the field is `skip_serializing_if = "Vec::is_empty"`, so an empty list is omitted). This mirrors the same "blocking-compile fix" deviation 80-01 itself applied to `crates/core`.
- **Files modified:** crates/sdk/src/emit.rs, crates/sdk/src/listing.rs, crates/fuse/src/content_ops.rs, crates/fuse/src/journal_helpers.rs, crates/fuse/src/fs.rs, crates/fuse/src/write_ops/implementation/delete.rs, crates/fuse/src/platform/windows/write_ops.rs, crates/fuse/src/replay.rs (2 constructors)
- **Verification:** `cargo check -p cipherbox-fuse --features fuse` and `cargo check -p cipherbox-sdk` clean; full `cargo test -p cipherbox-fuse` green (124 passed).
- **Committed in:** `eaed02937` (Task 1) for 7 files; the two `replay.rs` constructor fixes rode the same commit as replay Test D.

**2. [Plan-text divergence] Cache on FuseRotationDeps, not ApiClientTransport**
- **Found during:** Task 3
- **Issue:** The plan's `key_links`/action placed the cache on `ApiClientTransport`, but the locked Test C exercises the `FakeTransport` path and asserts its `collect_sent_shares` is called `<= 1`.
- **Fix:** Implemented the cache on the generic `FuseRotationDeps` (the once-per-job instance wrapping either transport) so both the production and fake paths fetch-once/reuse. Still job-scoped and interior-mutable (`OnceCell`); satisfies every prohibition (no static/global). Grep-check for `RefCell|OnceCell` in rotation_deps.rs is satisfied.
- **Verification:** Test C passes; full fuse suite green.
- **Committed in:** this commit (Task 3).

---

**Total deviations:** 2 (1 Rule-3 blocking compile-unblock; 1 plan-text divergence forced by the locked acceptance test).
**Impact on plan:** The compile-unblock was mandatory for the plan's own tests to build (same class of fix 80-01 applied). The cache-placement divergence keeps the behavior identical and the prohibitions intact. No scope creep beyond the unavoidable compile-unblock.

## Issues Encountered
- The workspace did not compile at plan start (see Deviation 1). Resolved by the Rule-3 compile-unblock before RED.

## Known Gaps / Notes for 80-05
- `reconstruct_write_body` emits an empty `recipient_pins` list. Pin preservation (D-03b) is 80-05's job once the pins are cached on the inode — this is a planned handoff, NOT a scope reduction of D-01 (the plan's own note).
- `replay.rs::fetch_splice_publish_parent` re-seals the parent write-body with `recipient_pins: Vec::new()` (it decodes only `write_children` from the parent's current write-body). If a rotated/shared parent carries pins, a replay re-splice would drop them. This is out of scope for 80-02 (which owns rotation republish + the replay regression test, not replay pin preservation) and no 80-x plan currently lists `replay.rs` for pin work — flagged here for triage.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- 80-05 (wave 2, depends on 80-02) can extend `reconstruct_write_body` to thread cached `recipient_pins`; the helper signature and seal path are in place.
- 80-06 (wave 3) can reuse the `FakeTransportInner` call-counter test infra.

---
*Phase: 80-rotation-write-plane-and-re-mint-durability*
*Completed: 2026-07-12*
