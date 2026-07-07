# Phase 69 — Write-Owner Materialization Design (P1a-2 / P1a-3, drives 69-17/69-18 + 69-09 rewrite)

> Third re-scope. Verified against the live tree (queue.rs, listing.rs, inode.rs, emit.rs) on 2026-07-06.
> Consumed by gsd-planner to author 69-17-PLAN.md + 69-18-PLAN.md and revise 69-09-PLAN.md.

## The verified gap (why 69-09/P1b halted)

The FUSE mount is a **read-WRITE vault owner**, not a read-only client (unlike the web 68.2 mirror
this phase ported). Evidence:

- `crates/fuse/src/inode.rs` `InodeKind::{Root,Folder,File}` each store the node's **write** material:
  `ipns_private_key: Option<Zeroizing<Vec<u8>>>` (to SIGN this node's IPNS records — "Critical for
  write operations"), plus `folder_key`/`encrypted_file_key`. Legacy `populate_folder` (inode.rs:285+)
  recovers these by ECIES-unwrapping each child's `folder_key_encrypted` + `ipns_private_key_encrypted`
  (both wrapped under the **user's** private key) at inode.rs:434 / 451.
- The gated listing (`crates/sdk/src/listing.rs`) is a **read-only, keyless projection**:
  `ResolvedChild { ipns_name, name, kind, size, modified_at, sequence }` carries NO key material.
  `resolve_child` (listing.rs:279) unseals the child read-key via `unseal_child_read_key` and
  **immediately zeroizes it** (listing.rs:307–315); it NEVER unseals the write-body
  (`NodeWriteBody { ipns_private_key, write_children }`).
- `crates/sdk/src/emit.rs` only **mints fresh single nodes** (`create_folder_node`/`create_file_node`);
  it does not walk an existing tree.
- `crates/sdk/src/queue.rs` `JournalOp::{UploadFile,MkdirPublish,...}` wire format is **hex-string,
  user-ECIES-under-`self.public_key`** (`wrapped_key_hex`, `parent_ipns_key_hex`,
  `filename_encrypted_hex`, `child_folder_key_hex`) — NOT node/v3-symmetric-under-parent-key. The
  `parent_metadata: FolderMetadata` the old 69-09 plan called the "cross-crate weld / landmine 1" does
  NOT exist in queue.rs — it lives fuse-side in `journal_helpers.rs:97 MkdirJournalResult`. **That
  weld framing is stale and must be dropped from 69-09.**

Net: flipping `InodeKind` to node/v3 strictly requires (a) a way to materialize per-node
`{read_key, write_key, ipns_private_key}` for an EXISTING tree, and (b) a node/v3-shaped journal.
Neither was built by P1a (69-15/69-16). These are 69-17 and 69-18.

## node/v3 key-recovery map (the InodeKind fields, per source)

| InodeKind field | legacy source | node/v3 source |
|---|---|---|
| child `read_key` (folder_key) | ECIES unwrap `folder_key_encrypted` under user key | `unseal_child_read_key(parent.SealedChildRef.read_key_sealed, parent_read_key)` — already computed by `resolve_child`, currently DISCARDED |
| child `write_key` | (n/a in legacy — user-key model) | `unseal_child_write_key(parent.WriteChildRef.write_key_sealed, parent_write_key)` — the write-plane half listing omits |
| node `ipns_private_key` | ECIES unwrap `ipns_private_key_encrypted` under user key | `unseal_node(node.write_sealed, node_write_key)` → `NodeWriteBody.ipns_private_key` |

Root: the mount already holds root read+write keys (AppState). The owned walk starts there.

## 69-17 (P1a-2) — gated write-plane tree-materialization API (additive, crates/sdk, GREEN)

Mirror `resolve_children`/`resolve_child` but recover the write plane too. Additive — no fuse edits.

- New `ResolvedOwnedChild { child: ResolvedChild, read_key: Zeroizing<[u8;32]>, write_key:
  Zeroizing<[u8;32]>, ipns_private_key: Zeroizing<Vec<u8>> }` (or equivalent) — the mount is the
  **terminal owner** (D-09): these are returned RAW/Zeroizing to the caller; the SDK does NOT zero them.
  Redacting `Debug` (mirror emit.rs FolderEmission).
- New `resolve_owned_child(fetcher, high_water, parent_read_key, parent_write_key, child SealedChildRef,
  child WriteChildRef) -> ResolvedOwnedChild`: unseal read_key (parent_read_key) + write_key
  (parent_write_key) + fetch the child node and `unseal_node(write_sealed, child_write_key)` to recover
  its `ipns_private_key`. Fail-closed on any unseal/length mismatch (Err, never panic).
- New public entrypoint `list_folder_owned(...)` paralleling `list_folder` — takes parent read+write
  keys, routed through the SAME `NodeFetcher` + `RotationHighWater::enforce_resolved` gate (SC#6: no raw
  resolve; `resolve_published_node` stays `pub(crate)`). Pairs `SealedChildRef` (read plane, by ipnsName)
  with `WriteChildRef` (write plane, by childId UUID) — **D-07: match children across the two planes by
  the dual keys, never conflate ipnsName and childId.**
- Terminal-owner zeroization (project memory, broke 48/89 sdk-e2e): `parent_read_key`/`parent_write_key`
  are caller-supplied borrows — NEVER zeroed here. Only SDK-minted scratch is zeroed. Add a test
  asserting caller buffers are unchanged (mirror emit.rs test).
- Unit tests: round-trip an emitted 2-level tree (build via emit.rs create_*_node + build_child_refs)
  back through `list_folder_owned`, assert recovered read_key/write_key/ipns_private_key match what was
  minted; D-07 pairing test; caller-buffer-unchanged test; high-water floor gate enforced test.
- Verify: `cargo check --workspace` + `cargo test -p cipherbox-sdk` green. Additive, crates/fuse UNTOUCHED.

## 69-18 (P1a-3) — JournalOp node/v3 wire reshape + replay reinterpret (crates/sdk/queue.rs + replay)

D-04 clean flag-day, **no prod vaults** → NO dual-format migration, NO compat deserializers for the
node/v3 fields. A stale pre-cutover on-disk entry that fails serde under the new shape is
`log::warn!` + SKIP (fail-closed, never unwrap/panic) — mirror queue.rs's existing Err-skip idiom.
Document the one-time `~/.cipherbox/journal` clear in the SUMMARY.

- Reshape `JournalOp::{UploadFile,MkdirPublish, delete/rename variants}` off the hex-ECIES-under-user-key
  fields onto node/v3-shaped fields: the freshly emitted child `PublishedNode` bytes + the updated parent
  `SealedChildRef`/`WriteChildRef` (D-07 dual-keyed) + the parent node identity to re-publish, such that
  replay re-seals/re-publishes via the node/v3 seal path (NOT ECIES). Keep the sidecar-ciphertext
  mechanism (D-01, WR-06) for file bodies — only the KEY/metadata fields change shape.
- Replay (`crates/fuse/src/replay.rs` reader + `crates/sdk` if it owns any) reinterprets the reshaped
  ops through the node/v3 publish path. Fail-closed skip on deserialize failure.
- Retained ECIES keepers (crypto rule #7 / NODE-06): TEE ipnsPrivateKey wrap, vault-blob root wrap,
  genuine folder/file-NAME blobs. Node-to-node KEY hops only migrate to symmetric.
- This plan MAY compile RED until 69-09 consumes it (queue.rs is cross-crate with fuse). Decide at plan
  time: either (a) keep 69-18 additive+green by adding the new variants alongside (fuse migrates in
  69-09), or (b) fold the queue.rs reshape INTO 69-09's atomic unit. **Prefer (a) if it can stay green;
  fall back to folding into 69-09 if the enum reshape is inseparable from the fuse constructor sites.**
- Verify: green boundary per whichever split; `cargo test -p cipherbox-sdk` covers the fail-closed skip.

## 69-09 (P1b) rewrite delta

- `depends_on += ["69-17","69-18"]`.
- DROP the stale "JournalOp weld / landmine 1 / `parent_metadata: FolderMetadata` in queue.rs" language
  and its acceptance criterion (already trivially satisfied — the field isn't there). Replace with:
  read path consumes `list_folder_owned` (69-17) to populate InodeKind with recovered
  read_key/write_key/ipns_private_key; write path emits node/v3 + enqueues the reshaped JournalOp (69-18).
- Everything else stands: atomic InodeKind flip, SC#1 read symmetric unseal, SC#6 single gated
  entrypoint (now `list_folder`/`list_folder_owned`), fail-closed replay, desktop construction sites,
  SC#6 CI gate, keeper ECIES list. Green boundary unchanged.

## Constraints (carry into every plan)
Terminal-owner zeroization (never zero caller-owned borrows); D-07 write=childId / read=ipnsName;
keeper ECIES = TEE(content_ops:134) + vault-root + name blobs(replay:839) + cfg(test); no new Cargo dep
(sdk already has api-client/crypto/core); SC#6 gate (no raw resolve in crates/fuse/src);
read 68.2 branch via `git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings:<path>` only.
