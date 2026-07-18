---
phase: 80-rotation-write-plane-and-re-mint-durability
plan: 05
subsystem: infra
tags: [rust, fuse, ipns, rotation, recipient-pins, node-v3, zeroize]

# Dependency graph
requires:
  - phase: 80-01
    provides: NodeWriteBody.recipient_pins wire field
  - phase: 80-02
    provides: reconstruct_write_body helper + job-scoped sent-shares cache in rotation_deps.rs
provides:
  - "ResolvedOwnedChild.recipient_pins surfaced from the unsealed write-body (listing.rs)"
  - "InodeKind::{Root,Folder,File}.recipient_pins cache field + apply_owned_children population (inode.rs)"
  - "reconstruct_write_body now carries cached recipient_pins into the resealed write-body (rotation_deps.rs)"
affects: [80-06]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-03a pin plumbing: issuance data (recipient pins) surfaced once at materialization from the same unsealed write-body, cached on the inode for offline verification"
    - "D-01↔D-03e durability: rotation republish reconstruction re-emits cached pins verbatim so a later re-mint after re-materialize still finds them"

key-files:
  created:
    - .planning/phases/80-rotation-write-plane-and-re-mint-durability/80-05-SUMMARY.md
  modified:
    - crates/sdk/src/listing.rs
    - crates/fuse/src/inode.rs
    - crates/fuse/src/write_ops/rotation_deps.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/replay.rs
    - crates/fuse/src/test_support.rs
    - crates/fuse/src/write_ops/grant_scope.rs
    - crates/fuse/src/write_ops/implementation/delete.rs
    - crates/fuse/src/write_ops/implementation/file_data.rs
    - crates/fuse/src/write_ops/implementation/mkdir.rs
    - crates/fuse/src/write_ops/implementation/rename.rs
    - crates/fuse/src/platform/windows/write_ops.rs

key-decisions:
  - "Recipient pins are PUBLIC keys, not secret material — surfaced as recipient_pins_count in Debug impls, NOT redacted like read_key/write_key/ipns_private_key"
  - "Fresh nodes (mkdir, new file, root init, test fixtures) default to an empty pin list; only materialized owned nodes carry real pins"
  - "reconstruct_write_body reads pins from the SAME inode it reads write_key/ipns_private_key from — copied verbatim, never rotated (read plane / generation untouched)"

patterns-established:
  - "Pin plumbing mirror of the ipns_private_key path: read from the unsealed write-body at ResolvedOwnedChild construction, moved onto InodeKind at apply_owned_children, re-emitted by reconstruction"

requirements-completed:
  - "SC2 / D-03a: surface + cache the shared node's owner-sealed recipient pins so the FUSE re-mint can verify them offline"
  - "SC1 / D-01: rotation republish must PRESERVE the recipient pins in the reconstructed write-body (else a later re-mint hard-fails D-03e)"

coverage:
  - id: D1
    description: "ResolvedOwnedChild.recipient_pins populated from the already-unsealed write-body (listing.rs)"
    requirement: "SC2 / D-03a"
    verification:
      - kind: unit
        ref: "crates/fuse/src/inode.rs#apply_owned_children_caches_recipient_pins_on_the_inode (exercises pins flowing from ResolvedOwnedChild onto the inode)"
        status: pass
    human_judgment: false
  - id: D2
    description: "InodeKind::{Root,Folder,File}.recipient_pins cache field populated in apply_owned_children; key-material Debug redaction preserved"
    requirement: "SC2 / D-03a"
    verification:
      - kind: unit
        ref: "crates/fuse/src/inode.rs#apply_owned_children_caches_recipient_pins_on_the_inode"
        status: pass
    human_judgment: false
  - id: D3
    description: "reconstruct_write_body carries cached recipient_pins into the resealed write-body so a rotation republish preserves them (D-01↔D-03e)"
    requirement: "SC1 / D-01"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#reconstruct_write_body_preserves_cached_recipient_pins"
        status: pass
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#reconstruct_write_body_round_trips_ipns_key_and_child_write_refs (80-02 no-regression)"
        status: pass
    human_judgment: false

# Metrics
duration: 30min
completed: 2026-07-12
status: complete
---

# Phase 80 Plan 05: Recipient-Pin Plumbing for Offline Re-Mint + Rotation Durability Summary

**D-03a recipient pins now flow from the shared node's owner-sealed write-body onto the materialized inode and are preserved verbatim by rotation republish, making them available offline to the FUSE re-mint (80-06) and durable across a scope-exit rotation.**

## Performance

- **Duration:** ~30 min
- **Started:** 2026-07-12
- **Completed:** 2026-07-12
- **Tasks:** 3 (TDD RED → GREEN → GREEN)
- **Files modified:** 12

## Accomplishments
- `ResolvedOwnedChild.recipient_pins: Vec<Vec<u8>>` read from the SAME already-decoded `write_body` as `ipns_private_key` in `resolve_owned_child` (listing.rs) — no second unseal.
- `InodeKind::{Root,Folder,File}` gained a `recipient_pins: Vec<Vec<u8>>` cache field, populated in `apply_owned_children` by moving `owned.recipient_pins` onto the materialized inode; empty default at root init and all fresh-node/test construction sites.
- `reconstruct_write_body` (from 80-02) now reads the node's cached `recipient_pins` from the InodeTable and sets `NodeWriteBody.recipient_pins` before `seal_node`, so a scope-exit rotation republish PRESERVES the pins (closes the D-01↔D-03e self-destruct gap where a post-rotation re-mint would hard-fail).
- Debug discipline held: recipient pins (public keys) surface as `recipient_pins_count`; `read_key`/`write_key`/`ipns_private_key` remain `<redacted>`.

## Task Commits

Single squashed commit per execution constraint (SUMMARY committed alongside code):

1. **Task 1: RED — reconstruction-preserves-pins + materialization-caches-pins tests** (test)
2. **Task 2: GREEN — surface recipient_pins on ResolvedOwnedChild + cache on the inode** (feat)
3. **Task 3: GREEN — reconstruct_write_body carries cached recipient_pins** (feat)

RED was confirmed as a non-vacuous compile failure (`no field recipient_pins on ResolvedOwnedChild`; `variant InodeKind::Folder/File does not have a field named recipient_pins`) before implementation.

## Files Created/Modified
- `crates/sdk/src/listing.rs` — `ResolvedOwnedChild.recipient_pins` field + Debug + populated from `write_body.recipient_pins` at construction
- `crates/fuse/src/inode.rs` — `InodeKind` variant field + Debug (non-secret count) + `apply_owned_children` destructure/population + root init + test fixtures + Test A
- `crates/fuse/src/write_ops/rotation_deps.rs` — `reconstruct_write_body` reads cached pins into the resealed `NodeWriteBody` + doc comment + Test B + test-helper fixture
- `crates/fuse/src/{fs.rs,replay.rs,test_support.rs}` — construction sites updated (empty default)
- `crates/fuse/src/write_ops/{grant_scope.rs,implementation/{delete,file_data,mkdir,rename}.rs}` — construction sites updated (empty default)
- `crates/fuse/src/platform/windows/write_ops.rs` — winfsp construction sites updated (empty default) to keep the Windows CI build green

## Decisions Made
- Recipient pins are public keys → shown as `recipient_pins_count` in Debug, not redacted. Key material redaction unchanged (crypto rule #2).
- Fresh/newly-created nodes and all test fixtures default to an empty pin list; only materialized owned nodes carry real pins.
- Read plane / generation untouched — pins live only in the write-body and are copied, never rotated.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated all InodeKind construction sites across the fuse crate (incl. winfsp)**
- **Found during:** Task 2 (adding the `recipient_pins` field to the `InodeKind` variants)
- **Issue:** Adding a required struct-variant field forces every literal construction site to supply it, or the crate (and its test build) will not compile. The plan named only listing.rs/inode.rs/rotation_deps.rs, but the compiler flagged additional lib + test construction sites in fs.rs, replay.rs, test_support.rs, grant_scope.rs, delete.rs, file_data.rs, mkdir.rs, rename.rs, and the winfsp platform module.
- **Fix:** Supplied `recipient_pins: Vec::new()` at each fresh-node/test construction site (no share grants at creation → empty pins). The winfsp `platform/windows/write_ops.rs` sites were updated by inspection to avoid breaking the Windows-only CI build (local cargo does not compile `windows/*`).
- **Files modified:** fs.rs, replay.rs, test_support.rs, grant_scope.rs, delete.rs, file_data.rs, mkdir.rs, rename.rs, platform/windows/write_ops.rs
- **Verification:** `cargo build -p cipherbox-fuse -p cipherbox-sdk` compiles; `cargo test -p cipherbox-fuse` = 126 passed / 0 failed.
- **Committed in:** same plan commit

---

**Total deviations:** 1 auto-fixed (1 blocking — mechanical fan-out of a required field addition, explicitly anticipated by the plan's "Fix all construction sites the compiler flags").
**Impact on plan:** No scope creep — all changes are the direct compile-required consequence of the specified `InodeKind` field. No behavior changed at the empty-default sites.

## Issues Encountered
None. The winfsp sites cannot be compiled locally (macOS/CI split, per project memory), so they were updated by inspection matching the fuse-side pattern — budget a CI round-trip for the Windows build.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- 80-06 (Rust enforcement seam) can now read the recipient pins from the InodeTable cache and verify them offline; pins survive a scope-exit rotation republish.
- No API change, no DB migration, no `pnpm api:generate` (Rust-only, write-body-internal).

---
*Phase: 80-rotation-write-plane-and-re-mint-durability*
*Completed: 2026-07-12*
