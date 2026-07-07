# Phase 69 — Legacy-Type Retirement Design (bin + vault-creation → node/v3, then 69-10 delete)

> Fourth expansion (user: "expand scope: migrate bin/export now"). Verified against the live tree post-69-13
> (HEAD e72021281). Drives new plans 69-19 (bin), 69-20 (vault-creation), and the re-scoped 69-10 (delete).

## Verified scope (what actually blocks the D-04 legacy-type delete)
The atomic flip (69-09) + grant gate (69-13) migrated the FUSE read/write/replay/delete/rename paths to node/v3.
The legacy types `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` (crates/core/src/{folder,file}.rs) survive
ONLY in subsystems the flip intentionally skipped. Verified LIVE users:
- **Recycle-bin** (crates/core/src/bin.rs): `BinEntry.file_pointer: Option<FilePointer>` + `folder_entry: Option<FolderEntry>`.
  Live fuse consumers: metadata.rs(4), write_ops/implementation/delete.rs(4), platform/windows/write_ops.rs(2).
- **Vault-creation** (apps/desktop/src-tauri/src/commands/vault.rs:147-159): seals an empty `FolderMetadata{version:"v2",children:[]}`
  via `encrypt_folder_metadata` → {iv,data} envelope → upload → publish root IPNS at seq 1. LIVE (no stub markers).
- **DEAD (delete, don't migrate):** `crates/core/src/decrypt.rs` `decrypt_metadata_from_ipfs_public` +
  `decrypt_file_metadata_from_ipfs_public` — NO live consumer (self + lib.rs export only). `merge_folder_children`
  (fuse metadata.rs) — now TEST-ONLY (re-exported for desktop tests). `encrypt_metadata_to_json` (fuse metadata.rs) —
  verify dead post-flip; if uncalled in live code, delete.
- **NOT wired (nothing to migrate):** vault export/import (no export_vault/import_vault/VaultExport symbols on branch).

## D-04 clean flag-day: no prod vaults → reshape freely, no dual-format/compat. Cross-lang TS BinEntry parity NOT required
on this branch (web is a separate impl; node/v3 is greenfield here).

## 69-19 (P4a) — Recycle-bin → node/v3 (crates/core/src/bin.rs + fuse consumers)
- Reshape `BinEntry`: REPLACE `file_pointer: Option<FilePointer>` + `folder_entry: Option<FolderEntry>` with node/v3 restore
  data sufficient to re-link a deleted node into a parent: the deleted node's `child_published_node: String` (b64
  encode_published_node) + its `SealedChildRef` (read plane) + `WriteChildRef` (write plane, D-07) captured at delete time,
  keyed off `original_parent_ipns_name`. Drop `original_folder_key_encrypted` (was for re-encrypt-on-restore under the old
  parent-key model — node/v3 restore re-splices the sealed child ref, no per-file re-encrypt; SC#2-consistent).
- KEEP the bin-metadata ENVELOPE as ECIES-under-user-key (`encrypt_bin_metadata`/`decrypt_bin_metadata`) — this is a
  user-level keeper (like vault-export root wrap, NODE-06), NOT a node-to-node hop. Only the BinEntry CONTENTS change.
- fuse: delete.rs bin-write (capture the node/v3 child refs + published node at delete time — they're already computed by
  the node/v3 delete path) + the restore path (re-splice SealedChildRef/WriteChildRef into the target parent, republish
  parent). metadata.rs bin helpers. platform/windows/write_ops.rs (cfg(winfsp), edit-for-correctness, 69-14 CI).
- Additive-ish but touches BinEntry shape (cross-crate core→fuse) → may be RED until fuse consumers update in the same plan.
  Boundary: cargo check --workspace green + cargo test -p cipherbox-fuse/-core green.

## 69-20 (P4b) — Vault-creation → node/v3 (apps/desktop/src-tauri/src/commands/vault.rs)
- Replace the empty-`FolderMetadata` seal+publish with an empty node/v3 ROOT Node: build `Node::Root` (no children) +
  `NodeWriteBody{ipns_private_key: root seed, write_children: []}`, `seal_published_node(node, root_read_key, root_write_key,
  Some(write_body))` → `encode_published_node` → upload → publish root IPNS record at seq 1 (reuse the existing IPNS
  create/marshal/publish tail). Use the SAME root read/write keys the mount derives (today the placeholder bridge from
  root_folder_key, mod.rs:186) so create+mount are consistent — real node/v3 root-key persistence/recovery is the separate
  phase-63 desktop-runtime work (out of scope; document the coupling). Consider reusing `cipherbox_sdk::build_folder_emission`
  (is_root=true) if it fits, else the core seal path directly.
- Boundary: cargo check --workspace green; a vault-creation unit/integration test if practical (else document manual/E2E).

## 69-10 (re-scoped, P4c) — DELETE the now-dead legacy types
After 69-19+69-20 remove the last live consumers: delete from crates/core `FolderMetadata`/`FolderChild`/`FolderEntry`/
`FilePointer` (folder.rs), `FileMetadata` (file.rs), `encrypt_folder_metadata`/`decrypt_folder_metadata`, the dead
decrypt.rs helpers, their lib.rs exports; fuse metadata.rs `merge_folder_children`/`encrypt_metadata_to_json` (+ their
lib.rs re-exports + desktop test uses). Update apps/desktop/src-tauri/src/fuse/mod.rs tests that used merge_folder_children.
Boundary: cargo check --workspace green + all crate tests green + `grep -rn 'FolderMetadata\|FilePointer\|FolderEntry\|
FileMetadata' crates/ apps/ ` returns only cfg(winfsp)/genuinely-unreachable (document any residual). SC-04 satisfied.

## Sequencing: 69-19 → 69-20 → 69-10 (each cargo-workspace-green; standard worktree, merge per plan).
Then phase 69 non-Windows work COMPLETE; 69-14 WinFsp = user's Windows box.
## Constraints: keep ECIES keepers (bin envelope, TEE wrap, vault-root); D-07 write=childId/read=ipnsName; terminal-owner
zeroization; no new Cargo dep; --no-verify commits in worktrees; desktop-e2e deferred (root-key recovery phase-63, accepted).
