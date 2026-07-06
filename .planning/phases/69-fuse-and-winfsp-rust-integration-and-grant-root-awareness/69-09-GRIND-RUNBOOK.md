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

## SLICE 1 OUTCOME (commit 4efcc3ef9) — carry-forward facts for Slices 2-5
- InodeKind reshaped to the target shape above (all 3 ipns_private_key now NON-Option). Also dropped:
  file_meta_ipns_name, file_meta_resolved, file_ipns_private_key, file_ipns_key_encrypted_hex, `versions`.
  ⚠️ `versions` (file versioning, in-scope v1.0) dropped from InodeKind — FLAG for final E2E: confirm version
  handling isn't regressed (may now live in NodeContent / SealedChildRef.version_floor). Not blocking the grind.
- CipherBoxFS: added ONE field `pub high_water: cipherbox_sdk::RotationHighWater<cipherbox_sdk::JsonSidecarFloorStore>`,
  built at each site via `cipherbox_sdk::new_journal_high_water(&journal_dir)` (capture journal_dir before it moves
  into WriteQueue::new; WriteQueue.journal_dir is pub(crate)-unreachable from fuse). NO `fetcher` field added.
- ApiNodeFetcher is a BORROW adapter `struct ApiNodeFetcher<'a> { pub api: &'a ApiClient }` — NO ::new. Construct
  INLINE at each read call site: `let fetcher = cipherbox_sdk::ApiNodeFetcher { api: self.api.as_ref() };`
  (self.api is Arc<ApiClient>; field wants &ApiClient). Pass parent keys as `&*read_key`/`&*write_key` (deref Zeroizing).
- Only 3 real CipherBoxFS construction sites: test_support.rs:128, desktop mod.rs (~173), windows/mod.rs:75/207
  (the runbook's fs.rs/operations.rs/journal_helpers.rs are impl blocks, not constructions).
- InodeTable::new() Root uses empty placeholders (String::new(), [0u8;32] keys, empty Vec); desktop root-population
  overwrites in Slice 5. Desktop mod.rs + windows/mod.rs `InodeKind::Root` overrides left RED for Slice 5.
- 120 downstream errors remain, ALL consumers (zero in enum/struct defs). Signatures for Slice 2:
  `cipherbox_sdk::list_folder_owned(fetcher, high_water, ipns_name, folder_read_key:&[u8;32], folder_write_key:&[u8;32])
  -> Result<Vec<ResolvedOwnedChild>, ListingError>`; `ResolvedOwnedChild { child: ResolvedChild, read_key, write_key,
  ipns_private_key }` (move Zeroizing keys straight into child InodeKind).

## SLICE 2 OUTCOME (commit 26cb97b36) — carry-forward for Slices 3-5
- Read path done: populate_folder→list_folder_owned; content_ops→unseal_node. Both ecies::unwrap_key greps EMPTY. 120→78 errs.
- populate_folder NEW sig (Slice 5 fs.rs caller): `async fn populate_folder(&mut self, parent_ino, ipns_name:&str,
  parent_read_key:&[u8;32], parent_write_key:&[u8;32], api:&ApiClient, high_water:&RotationHighWater<JsonSidecarFloorStore>,
  merge_only:bool) -> Result<(),String>`. Also: `resolve_file_pointer(ino, cid, iv, size, encryption_mode)` (dropped
  encrypted_file_key+versions); `mark_remotely_edited_files_unresolved(parent_ino, &[ResolvedOwnedChild])`;
  `fetch_and_decrypt_content_async(api, &PublishedNode, &[u8;32] read_key)`.
- InodeKind::File no longer stores file_key (lives in sealed NodeContent, recovered via unseal_node). "unresolved" = empty cid.
- NodeContent (core/node/types.rs:80): { cid:String, file_iv:String, size, mime_type, encryption_mode, file_key:Vec<u8>
  (base64 wire), versions:Vec<VersionEntry> }. ⇒ **file_iv is HEX** (content_ops does hex::decode) — Slice 3 write MUST
  build NodeContent.file_iv as HEX. file versioning lives in NodeContent.versions (not InodeKind) — verify at E2E.
- FLAG (Slice 5, RESOLVED APPROACH): content_ops takes &PublishedNode but list_folder_owned rejects file nodes. Slice 5
  TASK 0 = add a sanctioned SC#6 public `fetch_node_gated(fetcher,high_water,ipns_name)->PublishedNode` wrapper to sdk
  listing.rs (gate-first resolve_published_node), re-export at cipherbox_sdk::; read_ops uses it to fetch the file's
  PublishedNode → content_ops. Keeps Slice 2's content_ops sig intact. (Tiny additive sdk fn on the branch.)
- Slice 3 SEAM: fs.rs build_folder_metadata CHILD LOOP (181/185/222/244/255/256) = legacy FolderMetadata/FolderEntry/
  FilePointer emission → replace with Node + SealedChildRef/WriteChildRef. Parent read_key+write_key come straight
  from parent InodeKind. File child's write_key/ipns_private_key populated (from ResolvedOwnedChild) → build WriteChildRef/JournalOp.

## SLICE 3 OUTCOME (commit d9a0c9220) — carry-forward for Slices 4-5
- Write path emits Node + reshaped JournalOp. 78→39 errs. Zero in journal_helpers/write_ops. file_iv HEX confirmed.
- D-07 canonical child id = `uuid_from_ino(child_ino)` (now pub(crate)); child node sealed with id=uuid_from_ino;
  parent WriteChildRef.child_id (write) + SealedChildRef (read, by ipnsName) both use it. Readers recover child_id
  from the resolved node's OWN id → NO InodeKind.id field needed. Slice 5 prepopulate root: use id=uuid_from_ino(ROOT_INO).
- Reshaped JournalOp (Slice 4 replay reads): `UploadFile { sidecar_path, sidecar_sha256, legacy_ciphertext_b64,
  child_published_node:String(b64 encode_published_node), parent_child_ref:SealedChildRef, parent_write_child_ref:WriteChildRef,
  file_meta_ipns_name:Option<String>, parent_folder_ipns_name:String, size, created_at_ms }`;
  `MkdirPublish { child_ipns_name, child_published_node:String, parent_child_ref, parent_write_child_ref, parent_folder_ipns_name, created_at_ms }`.
- Slice 4 replay MUST: (1) recover parent ipns_private_key via list_folder_owned(parent_folder_ipns_name) at replay
  (NOT from journal — 69-18 deferred field); (2) UploadFile cid PLACEHOLDER: journal seals file node with NodeContent.cid=""
  → replay re-uploads sidecar ciphertext → real cid → RE-SEAL file node with cid BEFORE publishing (live happy path
  re-seals in publish_file_metadata, Slice 5); (3) re-splice both planes into parent, re-publish parent; (4) fail-closed
  log::warn!+skip on stale/deser failure (mirror queue.rs Err-skip); (5) replay.rs:839 folder-NAME blob = keeper if genuine.
- E2E FLAGS accumulating: (a) file `versions` not reconstructed at upload (InodeKind dropped versions; NodeContent.versions
  exists but write path doesn't populate) — versioning regression to verify at E2E; (b) file_iv hex round-trip; (c) content read
  gated-fetch (Slice 5 TASK 0 fetch_node_gated).

## SLICE 4 OUTCOME (commit 586cfd444) — carry-forward for Slice 5
- replay.rs rewritten onto node/v3. 39→35 errs; replay.rs 4→1 (the 1 = intended fetch_node_gated dep at replay.rs:427).
- Parent keys via list_folder_owned BFS from root (resolve_owned_parent); parent signing seed from parent's OWN sealed
  write-body (recover_signing_seed→unseal_node→decode_write_body), NOT journal. UploadFile: sidecar→real cid→patch
  NodeContent.cid→re-seal→publish. replay.rs:839 name-blob: decrypt_journal_name DELETED (name now in SealedChildRef.name).
- Fail-closed skip in replay_for_vault Err arm (record_failure/retain, no panic).
### SLICE 5 (FINAL → workspace GREEN) — detailed task list (35 fuse errs + desktop + gate):
- **TASK 0 (sdk, additive, keep sdk-green, own commit):** add `pub async fn fetch_node_gated<F,S>(fetcher:&F,
  high_water:&RotationHighWater<S>, ipns_name:&str) -> Result<PublishedNode, ListingError>` to crates/sdk/src/listing.rs
  — gate-first (reuse resolve_published_node, enforce_resolved BEFORE return), NO new raw-resolve public surface beyond
  this sanctioned entrypoint; re-export at cipherbox_sdk::. Add a unit test (round-trip an emitted node). replay.rs:427 + read_ops call it.
- **fuse glue:** read_ops.rs(23), fs.rs(7 read-completion: drain_refresh_completions, populate_folder caller w/ new async sig
  passing api+high_water, resolve_file_pointer, mark_remotely_edited), dir_ops.rs(4), inode.rs(3 residual), poll.rs(2),
  content_ops.rs(2) — repoint onto new InodeKind fields + new signatures (runbook SLICE 2/3 OUTCOME sigs). File content read:
  fetch the file PublishedNode via fetch_node_gated → content_ops fetch_and_decrypt_content_async(api,&PublishedNode,&read_key).
- **desktop:** apps/desktop/src-tauri/src/fuse/mod.rs + prepopulate.rs root population → list_folder_owned + Node populate_folder
  sig; root InodeKind::Root filled from AppState root read_key/write_key/ipns seed (id=uuid_from_ino(ROOT_INO)). Update
  replay_for_vault callers (mod.rs:252 + windows/mod.rs:160) to new sig: (journal, api, journal_dir:PathBuf, root_read_key:&[u8;32],
  root_write_key:&[u8;32], root_ipns_name, coordinator, tee_public_key, tee_key_epoch) — legacy private_key/public_key/root_folder_key gone.
  windows/* behind cfg(winfsp) won't locally compile (69-14 CI) — edit for correctness anyway.
- **SC#6 CI gate:** add grep-gate step to ci.yml Rust lane (cargo-macos ~635 / cargo-linux ~684): fail if crates/fuse/src
  references raw resolve (resolve_published_node|resolve_ipns_verified) outside list_folder|list_shared_folder|list_folder_owned|
  fetch_node_gated. Local dry-run zero hits.
- **GREEN BOUNDARY:** cargo check --workspace green + cargo test -p cipherbox-fuse green + -p cipherbox-sdk green +
  grep ecies::unwrap_key inode.rs/content_ops.rs EMPTY. Write 69-09-SUMMARY.md. Commit incrementally (TASK0 sdk / fuse glue /
  desktop+gate) so partial survives.
- E2E FLAG add: replay doesn't unpin old parent CID after re-publish (orphaned pins GC-able, not correctness-critical).

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
