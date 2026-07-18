---
phase: 80-rotation-write-plane-and-re-mint-durability
plan: 06
subsystem: infra
tags: [rust, fuse, rotation, ecies, recipient-pins, fail-closed, sharing]

# Dependency graph
requires:
  - phase: 80-01
    provides: NodeWriteBody.recipient_pins field (owner-sealed pin list)
  - phase: 80-05
    provides: InodeTable recipient_pins cache + FuseRotationDeps pin surfacing groundwork
provides:
  - "RotationDeps::get_recipient_pubkey_pins seam (required, no permissive default)"
  - "FuseRotationDeps + ApiClientTransport offline pin resolution from the InodeTable cache"
  - "Fail-closed recipient-pin compare before wrap_key in re_mint_grants_rooted_at (D-03d)"
  - "Pin-absent hard fail-closed at re-mint (D-03e no-legacy)"
affects: [rotation, sharing, re-mint, D-03d-consumer-2-typescript, D-03d-consumer-3]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Fail-closed pin binding: verify grant.recipient_public_key against the node's OWN owner-sealed pins before ECIES-wrapping a rotated read key; abort the whole node's re-mint (not a per-grant skip) on mismatch or empty pins"
    - "Offline authorization anchor via the RotationTransport seam reading the in-memory InodeTable pin cache (no extra network fetch)"

key-files:
  created: []
  modified:
    - crates/sdk/src/rotation/engine.rs
    - crates/fuse/src/write_ops/rotation_deps.rs

key-decisions:
  - "get_recipient_pubkey_pins is a REQUIRED trait method (no default) so a relay-substituted recipient can never slip through an implementor that forgot to wire the pin source"
  - "FuseRotationDeps resolves pins through the existing RotationTransport seam (ApiClientTransport reads the InodeTable pin cache offline), mirroring query_grants_rooted_at — not by holding an InodeTable directly"
  - "Empty pin list is a legitimate method return; the CALLER (re_mint) treats empty-at-re-mint as the D-03e hard fail-closed, keeping the method free of policy"
  - "Raw-byte equality compare — both pins (base64-decoded) and grant key (0x-stripped + hex-decoded) are already normalized to raw ECIES pubkey bytes at their decode boundaries (PATTERNS straight-equality idiom)"

patterns-established:
  - "Pattern 1: authorization anchor = node's own owner-sealed write-body pin, never the relay-supplied /shares/sent pubkey"
  - "Pattern 2: fail-closed compare aborts the whole node's re-mint (RotateFailed), never a per-grant skip-and-continue like the is_revoked branch"

requirements-completed:
  - "SC2 / D-03d (consumer 1 of 3): Rust re-mint verifies grant.recipient_public_key against the node's owner-sealed pin before wrap_key, fail-closed on mismatch"
  - "SC2 / D-03e: pin absent at re-mint is a hard fail-closed invariant violation (no-legacy, no TOFU, no backfill)"

coverage:
  - id: D1
    description: "re_mint_grants_rooted_at fails the whole node's re-mint closed when grant.recipient_public_key is not among the node's owner-sealed pins (relay-substituted recipient)"
    requirement: "SC2 / D-03d (consumer 1 of 3)"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#re_mint_fails_closed_when_recipient_is_not_pinned"
        status: pass
    human_judgment: false
  - id: D2
    description: "An absent/empty pin list at re-mint is a hard RotateFailed (D-03e no-legacy), not a silent skip"
    requirement: "SC2 / D-03e"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#re_mint_fails_closed_when_pin_list_is_empty"
        status: pass
    human_judgment: false
  - id: D3
    description: "A pinned recipient re-mints exactly once — the pre-80-06 success path is preserved"
    requirement: "SC2 / D-03d (consumer 1 of 3)"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/rotation_deps.rs#re_mint_succeeds_when_recipient_is_pinned"
        status: pass
      - kind: unit
        ref: "crates/sdk/src/rotation/engine.rs#high3_inner_grant_at_a_child_is_re_minted_and_revoked_recipient_is_cut"
        status: pass
    human_judgment: false
  - id: D4
    description: "get_recipient_pubkey_pins seam on FuseRotationDeps/ApiClientTransport resolves the pin list OFFLINE from the InodeTable pin cache (no extra network fetch)"
    requirement: "SC2 / D-03d (consumer 1 of 3)"
    verification:
      - kind: unit
        ref: "cargo test -p cipherbox-fuse rotation_deps (17 passed) + cargo build -p cipherbox-fuse"
        status: pass
    human_judgment: false

# Metrics
duration: 18min
completed: 2026-07-12
status: complete
---

# Phase 80 Plan 06: Rust Re-Mint Fail-Closed Recipient-Pin Binding Summary

**Rust FUSE re-mint now verifies `grant.recipient_public_key` against the node's OWN owner-sealed recipient pins (read offline from the InodeTable cache) before ECIES-wrapping the rotated read key, and fails the whole node's re-mint closed on a non-member (D-03d) or an absent/empty pin list (D-03e).**

## Performance

- **Duration:** 18 min
- **Started:** 2026-07-12
- **Completed:** 2026-07-12
- **Tasks:** 2 (TDD RED + GREEN)
- **Files modified:** 2

## Accomplishments
- Added `RotationDeps::get_recipient_pubkey_pins(node_id)` as a REQUIRED trait method (no permissive default), plus the matching `RotationTransport` seam method — so no implementor can silently trust a relay-substituted recipient.
- Implemented offline pin resolution: `FuseRotationDeps` delegates through the transport seam; `ApiClientTransport::get_recipient_pubkey_pins` reads the already-materialized `InodeTable` pin cache (80-05) via a new `find_recipient_pins` find_map — no extra `GET /shares/sent` or network fetch (D-03a).
- Inserted the fail-closed compare immediately before `wrap_key(new_read_key, &grant.recipient_public_key)` in `re_mint_grants_rooted_at`: a non-member recipient OR an empty/absent pin list returns `RotateFailed`, aborting the WHOLE node's re-mint (never a per-grant skip-and-continue).
- Added the two mandated negative tests (pin-mismatch fail-closed, pin-absent fail-closed) plus the positive match test; both negatives are non-vacuous RED (they failed against pre-change code) and now green.

## Task Commits

Single commit (per execution constraint — SUMMARY committed alongside code):

1. **Task 1+2 (TDD RED→GREEN): fail-closed recipient-pin binding at Rust re-mint** — see commit below (feat)

## Files Created/Modified
- `crates/sdk/src/rotation/engine.rs` — new required `RotationDeps::get_recipient_pubkey_pins` trait method; `recipient_is_pinned` helper; fail-closed compare in `re_mint_grants_rooted_at` before `wrap_key`; `FakeDeps` pin fixture (`pins_by_node` + `seed_pins` + impl); updated the existing `high3_inner_grant_...` test to pin the surviving recipient.
- `crates/fuse/src/write_ops/rotation_deps.rs` — `RotationTransport::get_recipient_pubkey_pins`; `FuseRotationDeps` delegate impl; `ApiClientTransport` offline impl + `find_recipient_pins`; `FakeTransport` pin fixture (`pins_by_node` + `seed_pins` + impl); Tests A/B/C.

## Decisions Made
- **Required trait method, no default:** a permissive empty-returning default would defeat the entire mitigation on a mis-wired implementor (T-80-15). The empty list is a legitimate value; only the caller decides it is a hard fail (D-03e), keeping the seam policy-free.
- **Delegate through the transport seam** rather than giving `FuseRotationDeps` an `InodeTable` handle — `FuseRotationDeps` never held one, and `ApiClientTransport` already owns `&inodes`. This mirrors `query_grants_rooted_at` exactly and keeps resolution offline.
- **Raw-byte equality compare:** both sides are normalized to raw ECIES pubkey bytes at their decode boundaries, so the D-03d check is a straight `==` with no 0x/hex mismatch (PATTERNS idiom).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated the existing engine re-mint success test to seed a pin**
- **Found during:** Task 2 (GREEN)
- **Issue:** Making `re_mint` fail-closed on unpinned recipients broke the pre-existing `high3_inner_grant_at_a_child_is_re_minted_and_revoked_recipient_is_cut` test, whose surviving recipient had no pin seeded (empty pins → new D-03e hard fail).
- **Fix:** Seeded the node's owner-sealed pin list with the active recipient's pubkey (`deps.seed_pins(&child_uuid(0), vec![active_pk...])`); the revoked recipient needs no pin (deleted before any pin check). This is the correct post-change behavior — the survivor IS legitimately pinned.
- **Files modified:** crates/sdk/src/rotation/engine.rs
- **Verification:** `cargo test -p cipherbox-sdk rotation` — 54 passed.
- **Committed in:** part of the plan commit.

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary to keep the existing re-mint success path green under the new fail-closed invariant. No scope creep — same recipient, now explicitly pinned. engine.rs was already in the plan's `files_modified`.

## Issues Encountered
None.

## Out-of-Scope / Follow-ups
- **D-03d consumer 3 (co-writer re-wrap):** the 4th co-writer re-wrap site (TS `rotateWriteFromNode`, the write-revocation path) still trusts the server-supplied pubkey. CONTEXT names exactly 3 consumers; this write-revocation site is OUT OF SCOPE for this plan and recorded as a phase-owner follow-up (RESEARCH Open Question 2 / A3, threat T-80-17 disposition = accept). Confirmed no `rotate_write_from_node`/`rotateWriteFromNode` symbol exists in `crates/sdk/src/rotation/engine.rs` and it was not touched.
- **Pre-ship:** `tests/sdk-e2e` (live client→API IPNS round-trip) must be green before ship — this is a key-lifecycle change. NOT run here per scoped-tests constraint.

## Verification (scoped)
- `cargo test -p cipherbox-sdk rotation` → **test result: ok. 54 passed; 0 failed; 99 filtered out**
- `cargo test -p cipherbox-fuse rotation_deps` → **test result: ok. 17 passed; 0 failed; 112 filtered out** (includes the 3 new pin tests A/B/C; pin-mismatch and pin-absent are the mandated negatives)
- `cargo build -p cipherbox-sdk -p cipherbox-fuse` → Finished (only upstream `fuser` dep warnings)
- RED proof (pre-GREEN): `re_mint_fails_closed_when_recipient_is_not_pinned` and `re_mint_fails_closed_when_pin_list_is_empty` both FAILED against pre-change code (non-vacuous).

## Next Phase Readiness
- D-03d consumer 1 (Rust re-mint) is complete and fail-closed. Consumers 2 (TypeScript re-mint) and 3 remain for their own plans.
- Co-writer re-wrap follow-up recorded above for the phase owner.

---
*Phase: 80-rotation-write-plane-and-re-mint-durability*
*Completed: 2026-07-12*
