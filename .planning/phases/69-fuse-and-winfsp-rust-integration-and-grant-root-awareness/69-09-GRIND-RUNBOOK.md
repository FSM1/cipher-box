# 69-09 Atomic FUSE Flip — Multi-Session Grind Runbook

> User decision (4th checkpoint): **Atomic grind + live E2E merge-gate.** Keep 69-09 atomic; land it
> across bounded per-session executor slices on ONE branch (RED intermediate commits OK); gate the FINAL
> MERGE on a real local sdk-e2e + desktop-e2e run (docker + TEE), NOT cargo-check-green.
> Verified scale: ~12,300 LOC, folder_key 232 refs / ipns_private_key 204, 15 ecies sites, InodeKind has
> NO write plane today, 6 CipherBoxFS construction sites. No compiling sub-unit — RED until the last slice.

## Working location (ALL slices)
- Branch: `worktree-agent-aad501548bf8c685c` (carries 69-17 in base + 69-18 queue reshape). HEAD a0986b337.
- Worktree: `/Users/myankelev/Code/random/cipher-box/.claude/worktrees/agent-aad501548bf8c685c`
- Non-isolated executors: git via `git -C <worktree>`, cargo via `--manifest-path <worktree>/Cargo.toml` or cd.
- If interrupted: resume a FRESH executor on this SAME branch (per-slice commits persist).

## Authoritative target InodeKind shape (all slices consume THIS — do not re-invent per slice)
node/v3 owner state, sourced from 69-17 `ResolvedOwnedChild { read_key, write_key, ipns_private_key }`:
```
enum InodeKind {
  Root   { ipns_name: String, read_key: Zeroizing<[u8;32]>, write_key: Zeroizing<[u8;32]>,
           ipns_private_key: Zeroizing<Vec<u8>> },              // mount holds root R/W from AppState
  Folder { ipns_name: String, read_key: Zeroizing<[u8;32]>, write_key: Zeroizing<[u8;32]>,
           ipns_private_key: Zeroizing<Vec<u8>>, children_loaded: bool },
  File   { ipns_name: String, cid: String, size: u64, encryption_mode: String, iv: String,
           read_key: Zeroizing<[u8;32]>, write_key: Zeroizing<[u8;32]>,
           ipns_private_key: Zeroizing<Vec<u8>> },
}
```
- `read_key` replaces legacy `folder_key`/`encrypted_folder_key`+`encrypted_file_key` (node-to-node symmetric).
- `write_key` is NEW (no legacy analog) — from parent WriteChildRef, needed to build reshaped JournalOp.
- `ipns_private_key` stays (signing seed) but now recovered via list_folder_owned/unseal_node, NOT user-ECIES.
- Drop legacy hex fields for node-to-node keys. KEEP file `cid`/`size`/`iv`/`encryption_mode`.
- Finalize exact field set in Slice 1; later slices treat it as frozen (note deviations back to this file).

## Slices (sequential, same branch; each: commit even if crate RED elsewhere, that's expected)
1. **Types + CipherBoxFS wiring** (keystone 1+2): reshape `InodeKind` (inode.rs enum def + its constructors);
   add `high_water: RotationHighWater<JsonSidecarFloorStore>` + `fetcher: ApiNodeFetcher` (or the wired gate)
   to `CipherBoxFS` (fs.rs), constructed via `cipherbox_sdk::new_journal_high_water(journal.journal_dir)` +
   `ApiNodeFetcher::new(api)`. Update ALL 6 CipherBoxFS struct-literal sites: fs.rs, operations.rs,
   journal_helpers.rs, test_support.rs, desktop mod.rs, desktop windows/mod.rs (windows behind cfg(winfsp) —
   edit but it won't locally compile; that's 69-14's CI, fine). Commit RED.
2. **Read path** (keystone 3): inode.rs `populate_folder` → `cipherbox_sdk::list_folder_owned(fetcher,
   high_water, ipns_name, &read_key, &write_key)` → fill children InodeKind from ResolvedOwnedChild
   (move Zeroizing keys in, mount = terminal owner, NEVER zero borrows). content_ops.rs:52 file content-key
   → `unseal_node(file node write/read-body)` → NodeContent.file_key (NOT ecies). Remove node-to-node
   `ecies::unwrap_key` in inode.rs/content_ops.rs. KEEP content_ops.rs:134 TEE wrap. Commit RED.
3. **Write path** (keystone 4): journal_helpers.rs + write_ops/implementation/{mkdir,file_data(upload),
   delete,rename}.rs → emit Node via emit.rs create_*_node/build_folder_emission + `build_child_refs`
   (parent read_key+write_key from InodeKind), splice SealedChildRef(read)/WriteChildRef(write) into parent,
   construct reshaped `JournalOp::{UploadFile,MkdirPublish}` (child_published_node b64 + parent_child_ref +
   parent_write_child_ref, D-07). LEAVE revoke_shares_blocking (delete 159/329) + spawn_file_meta_reencrypt
   (rename 248) UNTOUCHED — that's 69-13. Commit RED.
4. **Replay** (keystone 5): replay.rs (1612 LOC) → reinterpret reshaped JournalOp via node/v3 publish path;
   recover parent ipns_private_key via list_folder_owned at replay (the deferred field — NOT a journal ECIES
   field). Fail-closed log::warn!+skip on stale/deser failure (mirror queue.rs Err-skip). replay.rs:839
   folder-NAME blob: keep if genuine name wrap (assess). Commit RED.
5. **Glue + desktop + SC#6 gate → GREEN BOUNDARY** (keystone 6+7): read_ops.rs, dir_ops.rs, operations.rs,
   cache.rs, events.rs, poll.rs, metadata.rs (DON'T delete spawn_file_meta_reencrypt:777 or lib.rs:67
   re-export — 69-13), lib.rs re-exports; desktop prepopulate.rs root population → list_folder_owned +
   Node populate_folder sig. Add SC#6 grep gate to ci.yml Rust lane (no raw resolve/resolve_published_node/
   resolve_ipns_verified in crates/fuse/src outside list_folder/list_shared_folder/list_folder_owned).
   MUST reach: cargo check --workspace green + cargo test -p cipherbox-fuse green + -p cipherbox-sdk green
   + grep ecies::unwrap_key inode.rs/content_ops.rs EMPTY. Write 69-09-SUMMARY.md.

## Keeper ECIES (never migrate): content_ops.rs:134 TEE wrap, vault-blob root, name blobs (replay:839,
journal name wraps if genuine), #[cfg(test)] fixtures. Node-to-node KEY hops only → symmetric.
## Out of scope: revoke_shares_blocking, spawn_file_meta_reencrypt (69-13); platform/windows/* runtime (69-14);
legacy crates/core/src/folder.rs DELETION (69-10 — repoint off, don't delete). D-07: write=childId/read=ipnsName.

## FINAL MERGE GATE (orchestrator, after Slice 5 cargo-green) — NOT compile-green alone:
1. Local sdk-e2e (project memory: SDK-E2E recipe — redis 6380, real client→API IPNS round-trip).
2. Local desktop-e2e / headless FUSE UAT (project memory: headless-desktop-fuse-uat + tee-republish-e2e-stack
   recipes — docker stack, DB=cipherbox, rebuilt dists, --dev-key, macFUSE-vs-FUSE-T link gotcha).
3. ONLY if both green → merge combined branch (brings 69-18 + 69-09), update progress for BOTH, prune worktree.
If E2E red → do NOT merge; diagnose on branch. This is the whole point of the user's chosen safety gate.
