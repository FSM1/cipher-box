---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 06
subsystem: sdk
tags: [rust, ipns, node-v3, rotation, read-chain, listing, sc6]

requires:
  - phase: 69-02
    provides: RotationHighWater::enforce_resolved gate + HighWaterStore seam
  - phase: 69-04
    provides: unseal_node / unseal_child_read_key node codec+crypto primitives
  - phase: 69-01
    provides: Node / SealedChildRef / PublishedNode types
provides:
  - "crates/sdk::listing — ResolvedChild type + list_folder/list_shared_folder gated read entrypoints"
  - "pub(crate) resolve_published_node: the single gate-first raw-resolve seam, crate-internal only"
  - "FolderUpdatedEvent (folder:updated analog) callback fired on successful listing"
affects: [69-09-fuse-read-path-swap, 69-fuse-write-ops]

tech-stack:
  added: []
  patterns:
    - "Gate-first resolve: enforce_resolved runs BEFORE decode_published_node/unseal_node on every resolve"
    - "Parent-mirror generation source for cold-child gating (Pitfall 4 / M1)"
    - "Injected NodeFetcher trait for live-API-free unit testing (mirrors HighWaterStore's injection pattern)"

key-files:
  created:
    - crates/sdk/src/listing.rs
  modified:
    - crates/sdk/src/lib.rs

key-decisions:
  - "list_shared_folder delegates to list_folder verbatim (single internal resolver for owned+shared listings, per 69-CONTEXT.md Claude's Discretion) rather than duplicating the gated walk"
  - "The folder's own top-level resolve in list_folder gates using high_water.get_generation_floor(ipns_name).unwrap_or(0) — mirroring TS ensureRootFolderState's self-referential floor read, since there is no parent mirror for the folder being listed directly (only for its children)"
  - "folder:updated-analog delivered via an Option<&(dyn Fn(&FolderUpdatedEvent) + Send + Sync)> callback parameter rather than a persistent event-bus/registration API, since listing.rs has no daemon/client-lifecycle state in this plan"

requirements-completed: [SC-06]

coverage:
  - id: D1
    description: "ResolvedChild type + list_folder/list_shared_folder gated read API"
    requirement: "SC-06"
    verification:
      - kind: unit
        ref: "crates/sdk/src/listing.rs#list_folder_returns_resolved_children_for_file_and_folder"
        status: pass
      - kind: unit
        ref: "crates/sdk/src/listing.rs#list_shared_folder_uses_the_same_gated_chain_as_list_folder"
        status: pass
    human_judgment: false
  - id: D2
    description: "Gate-first ordering + fail-closed generation-regression rejection before any decode/unseal"
    requirement: "SC-06"
    verification:
      - kind: unit
        ref: "crates/sdk/src/listing.rs#gate_rejects_regression_before_touching_undecodable_bytes"
        status: pass
    human_judgment: false
  - id: D3
    description: "Cold-child generation sourced from the parent SealedChildRef mirror, not the child's own envelope generation (Pitfall 4 / M1)"
    requirement: "SC-06"
    verification:
      - kind: unit
        ref: "crates/sdk/src/listing.rs#cold_child_generation_sourced_from_parent_mirror_not_child_envelope"
        status: pass
    human_judgment: false
  - id: D4
    description: "folder:updated-analog event fires with the resolved children on a successful listing"
    requirement: "SC-06"
    verification:
      - kind: unit
        ref: "crates/sdk/src/listing.rs#folder_updated_event_fires_with_resolved_children"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 06: SDK-Owned Gated Read Chain (list_folder/ResolvedChild) Summary

**Gate-first `list_folder`/`list_shared_folder` in `crates/sdk::listing` returning `Vec<ResolvedChild>`, with raw IPNS resolve made crate-internal-only (D-05/SC#6).**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-07-06T02:50:00Z (approx.)
- **Completed:** 2026-07-06T03:34:30Z
- **Tasks:** 1
- **Files modified:** 2 (1 created, 1 modified)

## Accomplishments
- `ResolvedChild { ipns_name, name, kind, size: Option<u64>, modified_at, sequence }` — the Rust twin of 68.2's `ResolvedChild`, six fields exactly as specified.
- `list_folder(fetcher, high_water, ipns_name, folder_read_key, on_updated)` — resolves the target folder Node (gated), unseals it, and resolves every `SealedChildRef` child through the same gated chain, returning one `ResolvedChild` per child. A regressed child fails the WHOLE listing closed (`Err`, no partial `Vec`).
- `list_shared_folder(...)` — delegates to the identical gated chain for a grantee scope root (one ECIES root unwrap already done upstream by the caller).
- `resolve_published_node` — the crate-private (`pub(crate)`) gate-first primitive: fetch → `enforce_resolved` (BEFORE any decode) → `decode_published_node`. Raw resolve is never `pub` beyond the crate (D-05/SC#6 — the single gated read entrypoint invariant).
- Pitfall 4 / M1 generation-source rule implemented exactly: for a child hop, `enforce_resolved`'s `generation`/`version_floor` and `unseal_child_read_key`'s AAD generation both come from the PARENT's `SealedChildRef.generation`/`.version_floor` mirror — never the child's own on-wire `PublishedNode.generation`. The child's own body unseal (`unseal_node`) correctly uses the child's OWN envelope generation (a distinct, frozen AAD role per ADR 0003).
- `FolderUpdatedEvent { ipns_name, children }` fired via an injected callback on every successful listing (68.2 imperative-pull + event-push mirror).
- `NodeFetcher` trait — an injected resolve+fetch seam so unit tests exercise the full gate/generation-source logic with a fake in-memory fetcher, with zero live API/IPFS calls (per project memory: GSD subagents must not run live integration).

## Task Commits

1. **Task 1: ResolvedChild + gate-first resolve + list_folder/list_shared_folder** - `3ff8548c9` (feat)

**Plan metadata:** (this commit, docs completion commit follows)

## Files Created/Modified
- `crates/sdk/src/listing.rs` - `ResolvedChild`, `FolderUpdatedEvent`, `NodeFetcher`/`FetchedRecord`, `ListingError`, `pub(crate) resolve_published_node`, `pub async fn list_folder`/`list_shared_folder`, private `resolve_child` helper, 6 unit tests
- `crates/sdk/src/lib.rs` - added `pub mod listing;` + re-exports (`list_folder`, `list_shared_folder`, `FetchedRecord`, `FolderUpdatedCallback`, `FolderUpdatedEvent`, `ListingError`, `NodeFetcher`, `ResolvedChild`)

## Decisions Made
- `list_shared_folder` is a thin delegation to `list_folder` (same gated chain, same code path) rather than a parallel implementation — matches 69-CONTEXT.md's "Claude's Discretion: whether the owned and shared listing paths share one internal resolver or two thin wrappers."
- The top-level folder-being-listed's OWN gate uses `high_water.get_generation_floor(ipns_name).unwrap_or(0)` (self-referential, mirrors TS `ensureRootFolderState`) since there is no parent mirror for the folder itself — only its children have one. This is a self-check/no-op-safety-net by construction (an already-passing floor is read back and re-compared to itself), consistent with the TS reference's identical behavior.
- The `folder:updated`-analog is a plain `Option<&(dyn Fn(&FolderUpdatedEvent) + Send + Sync)>` parameter rather than a stored `Arc`/registered listener, since `listing.rs` in this plan is a set of free functions with no persistent client/daemon state (unlike `crate::sync::SyncDaemon`'s `Arc<dyn Fn(SyncStatus)>` convention, which owns a long-lived task).

## Deviations from Plan

None — plan executed exactly as written. (Test-fixture node IDs required real hyphenated UUIDs, since `build_node_aad` fail-closed rejects non-UUID `node_id` strings — an implementation detail of the already-shipped 69-01/69-04 AAD primitive, not a deviation from this plan's own scope.)

## Issues Encountered
- Initial test fixtures used human-readable node IDs (e.g. `"file-1"`) which `cipherbox_crypto::aes::build_node_aad` rejects (`CryptoError::InvalidAadInput` — it requires a parseable UUID). Fixed by generating real UUIDv5 strings for all test node IDs; no production-code change was needed since real callers always pass genuine node UUIDs.
- An initial `cargo fmt -p cipherbox-sdk -- crates/sdk/src/listing.rs` invocation reformatted the WHOLE `cipherbox-sdk` package (rustfmt via `cargo fmt` ignores path filters after `--`), touching `client.rs`/`queue.rs`/`registry.rs`/`rotation/high_water.rs`/`state.rs`/`sync.rs` with pre-existing formatting drift unrelated to this task. Reverted those files (`git checkout --`) and instead ran plain `rustfmt` directly on `crates/sdk/src/listing.rs` only, keeping the diff scoped to this plan's two files (scope-boundary discipline — pre-existing formatting drift in sibling files is out of scope for this task).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `crates/sdk::listing::{list_folder, list_shared_folder}` are ready for the 69-09 FUSE read-path swap to consume as the single read entrypoint (replacing the inline `ecies::unwrap_key` + BFS resolve in `crates/fuse/src/replay.rs`/`inode.rs`).
- The raw-resolve grep gate (SC#6, wired in 69-09) will find `resolve_published_node` as `pub(crate)` — not `pub` — satisfying the "FUSE never calls raw resolve" prohibition ahead of time.
- No blockers. The rotation *engine* (full DFS write-chain recovery, `crates/sdk/src/rotation/engine.rs`) is explicitly out of this plan's scope and remains a separate dominant-effort cluster per 69-CONTEXT.md D-05 sequencing.

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*

## Self-Check: PASSED
- FOUND: crates/sdk/src/listing.rs
- FOUND: .planning/phases/69-fuse-and-winfsp-rust-integration-and-grant-root-awareness/69-06-SUMMARY.md
- FOUND commit: 3ff8548c9
