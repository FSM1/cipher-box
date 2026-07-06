---
status: verifying
trigger: "list_folder_owned fails: parent READ plane has SealedChildRef for uuid_from_ino(7) but WRITE plane has no paired WriteChildRef (D-07 read/write pairing failed). FUSE write path publishes a parent whose two planes disagree about the child set."
created: 2026-07-07T00:00:00Z
updated: 2026-07-07T00:00:00Z
---

## Current Focus

reasoning_checkpoint:
  hypothesis: "The child node identity (published.id / WriteChildRef.child_id / seal AAD) is derived from the client-LOCAL inode number via uuid_from_ino(ino). When a child is materialized from a remote listing (apply_owned_children, inode.rs:456) it is assigned a FRESH local ino via allocate_ino(). A subsequent parent re-publish (build_folder_metadata, fs.rs:213) seals the WriteChildRef with child_id = uuid_from_ino(fresh_local_ino), which does NOT equal the child file node's real published.id = uuid_from_ino(original_creator_ino). list_folder_owned's D-07 pairing (find w.child_id == published.id) then fails."
  confirming_evidence:
    - "fs.rs:213 build_folder_metadata: child_id = uuid_from_ino(child_ino) — recomputed from the LOCAL ino for BOTH planes; and fs.rs:235 the folder's own id = uuid_from_ino(folder_ino)."
    - "inode.rs:456 apply_owned_children: ino = existing_ino.unwrap_or_else(|| self.allocate_ino()) — a re-materialized child (fresh mount / cross-client / move) gets a NEW local ino, decoupled from the ino encoded in its published.id."
    - "SDK emit.rs:172/239 mints node ids via generate_uuid_v4() (stable, portable) — that is the intended identity; uuid_from_ino(local_ino) is a client-local substitute that is not stable across clients/remounts."
    - "listing.rs:448 resolve_owned_child pairs by published.id (read from the fetched child node, correct) but the parent's write plane was sealed with the wrong local-ino-derived child_id."
    - "Failing e2e groups are Cross-client sync + Move (both operate on trees re-materialized with different local inos); passing groups (create/API round-trip/recycle bin) are single-session with stable inos."
  falsification_test: "If build_folder_metadata used a STORED stable node_id (== child's published.id) instead of uuid_from_ino(local_ino), a parent published after re-materialization would carry a WriteChildRef whose child_id equals the child's published.id, and list_folder_owned would pair successfully. Regression test: materialize a child whose stored node_id differs from uuid_from_ino(local_ino), publish the parent, run list_folder_owned/resolve_owned_child, assert Ok (fails before fix, passes after)."
  fix_rationale: "Stop deriving node identity from the local ino at publish time. Persist the node's real id (node_id) on InodeData: uuid_from_ino(ino) at creation (zero behavior change for same-session nodes), published.id on materialization. Use node_id in build_folder_metadata + journal + per-file publish. Same-session nodes (all currently-passing paths) are unaffected because node_id == uuid_from_ino(ino) for them; only re-materialized nodes change (from buggy fresh-ino id to correct remote id)."
  blind_spots: "delete.rs / grant_scope.rs / windows write_ops also build WriteChildRefs keyed by uuid_from_ino(child_ino) — must switch to node_id for full consistency (delete of a materialized file). winfsp is CI-only locally. Root's node_id must stay uuid_from_ino(ROOT_INO) to preserve root read behavior."

test: implement stored node_id; add regression test in crates/fuse reproducing a materialized child (node_id != uuid_from_ino(local_ino)) -> build_folder_metadata -> list_folder_owned pairs OK.
next_action: read remaining InodeData construction + publish sites (mkdir.rs, file_data.rs, grant_scope.rs, delete.rs, windows), then implement node_id field.

## Symptoms

expected: Every SealedChildRef the parent publishes has a paired WriteChildRef with child_id == child node's published.id (uuid_from_ino).
actual: list_folder_owned fails with "no WriteChildRef paired with child node id 00000000-0000-4007-8007-000000000007 (D-07 read/write pairing failed)" on every metadata refresh for minutes.
errors: cipherbox_fuse::events: Metadata refresh failed for k51...: list_folder_owned: node codec/crypto error: Invalid node format: no WriteChildRef paired with child node id 00000000-0000-4007-8007-000000000007 (D-07 read/write pairing failed)
reproduction: live desktop-e2e; write a file via FUSE mount -> parent re-publish -> subsequent list_folder_owned fails. uuid_from_ino(7) = file created via mount.
started: node/v3 FUSE write path (phase 69).

## Eliminated

## Evidence

- timestamp: init
  checked: crates/sdk/src/listing.rs resolve_owned_child (:448)
  found: D-07 pairing is `parent_write_children.iter().find(|w| w.child_id == published.id)`. published.id = child's own node id (uuid_from_ino). Fails closed if no match.
  implication: The FUSE write path must publish the parent WRITE body (write_children) containing a WriteChildRef with child_id == uuid_from_ino(child_ino). Somewhere it publishes the read ref without the write ref.

## Resolution

root_cause: |
  FUSE node identity (published.id / WriteChildRef.child_id / seal AAD) was derived
  from the client-LOCAL inode number via uuid_from_ino(ino) at PUBLISH time
  (fs.rs build_folder_metadata:213/235, read_ops flush:825, journal_helpers:300,
  delete.rs:128/330, grant_scope:318). But a child materialized from a remote
  listing is assigned a FRESH local ino by apply_owned_children (inode.rs:456), which
  differs from the ino its creator used. So a parent re-published after cross-client
  sync / move / remount sealed the child's WriteChildRef with child_id =
  uuid_from_ino(fresh_local_ino), which no longer equals the child file node's real
  published.id = uuid_from_ino(creator_ino). list_folder_owned's D-07 pairing
  (listing.rs:448, find w.child_id == published.id) then failed for minutes on every
  refresh. The SDK's own emit.rs mints stable generate_uuid_v4() ids — uuid_from_ino
  was a client-local substitute that is not portable across clients/remounts.
fix: |
  Persist the node's stable id on the inode and use it (never uuid_from_ino(local_ino))
  in all publish/pairing paths:
  - SDK: added ResolvedOwnedChild.node_id (= published.id) so the mount can recover
    a materialized child's real id (listing.rs).
  - FUSE: added InodeData.node_id. Set uuid_from_ino(ino) at creation (zero behavior
    change for same-session nodes) and the remote published.id on materialization
    (apply_owned_children). Root keeps uuid_from_ino(ROOT_INO).
  - Publish paths now key by the stored node_id: build_folder_metadata (child_id AND
    the folder's own id), the per-file publish (read_ops flush), the upload journal
    (journal_helpers), the recycle-bin refs (delete.rs), and the grant scope-exit
    (grant_scope.rs). mkdir keeps uuid_from_ino (always a fresh folder).
  Minimal + correct: same-session nodes are unaffected (node_id == uuid_from_ino(ino));
  only re-materialized nodes change from the buggy fresh-ino id to their real id. The
  list_folder_owned pairing invariant (security property) is untouched.
verification: |
  - Added regression test crates/fuse/src/fs.rs::d07_write_plane_pairing_tests::
    build_folder_metadata_pairs_a_materialized_child_by_its_real_node_id — drives the
    REAL build_folder_metadata for a materialized child (node_id != uuid_from_ino(ino))
    then runs cipherbox_sdk::list_folder_owned against the published parent.
    FAILS BEFORE fix with the exact live error ("no WriteChildRef paired with child
    node id 00000000-0000-4007-8007-000000000007 (D-07 read/write pairing failed)"),
    PASSES AFTER.
  - cargo test -p cipherbox-fuse: 96 passed / 0 failed (95 prior + 1 new).
  - cargo test -p cipherbox-sdk: 132 passed / 0 failed.
  - cargo check --workspace (default): Finished, no errors, no new warnings.
  - --features winfsp RED locally: fails in third-party winfsp-sys build script
    (windows_registry::LOCAL_MACHINE) — a macOS platform-dep limitation, CI-only,
    unrelated to this change (our fuse code never compiled). node_id was added to the
    two windows InodeData literals for consistency when windows is ported.
  - Terminal-owner zeroization preserved (SDK still returns raw keys, caller-owned;
    node_id is a non-secret String). D-07 (write=childId / read=ipnsName) preserved
    and hardened. No new Cargo dependency.
  - PENDING: orchestrator rebuilds the FUSE-T binary and re-runs the live desktop-e2e
    (Cross-client sync + Move) to confirm end-to-end.
files_changed:
  - crates/sdk/src/listing.rs
  - crates/fuse/src/inode.rs
  - crates/fuse/src/fs.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/journal_helpers.rs
  - crates/fuse/src/write_ops/implementation/file_data.rs
  - crates/fuse/src/write_ops/implementation/mkdir.rs
  - crates/fuse/src/write_ops/implementation/delete.rs
  - crates/fuse/src/write_ops/grant_scope.rs
  - crates/fuse/src/platform/windows/write_ops.rs
