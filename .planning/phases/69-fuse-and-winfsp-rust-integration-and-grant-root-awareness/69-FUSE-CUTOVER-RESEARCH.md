# Phase 69: FUSE / WinFsp Node-v3 Cutover — Re-Sequencing Design

**Researched:** 2026-07-06
**Domain:** Rust desktop FUSE/WinFsp read+write model cutover from legacy ECIES/`FolderMetadata` to `node/v3`/symmetric/gated-listing
**Confidence:** HIGH (every claim grounded in live `Read`/`grep` of the current tree + the 69-09 executor investigation)
**Supersedes for planning purposes:** the sequencing assumptions of 69-09 / 69-10 / 69-13 / 69-14 (the 4 plans that could not land incrementally)

## Summary

The 69-09 executor was correct and the finding is confirmed by independent grep: the FUSE read-path
ECIES→symmetric swap (SC#1) is **not separable** from the write-path Node-v3 emission or the legacy-type
deletion (SC#4). They are one atomic cutover because they all pin the same in-memory `InodeKind` data model
and the same on-IPNS wire format — read unwraps exactly what write seals, and both reference the legacy
`crates/core` types that D-04 deletes. Splitting them by "read now / write later" either fails
`cargo check --workspace` (callers still pass legacy shapes) or ships a decryption regression (write emits
symmetric, read expects ECIES, or vice-versa) for any vault created across the split.

The good news: the entire pure/stateful foundation is already merged and green — `crates/core/src/node/*`
(types/encode/decode/seal), `crates/sdk/src/{listing,floor_store}.rs`, `crates/sdk/src/rotation/*`
(engine/high_water/scope), and `crates/fuse/src/write_ops/grant_scope.rs`. Nothing in the foundation
needs re-doing. What remains is purely the **consumer cutover** inside `crates/fuse` (Unix) plus the
`crates/sdk::queue::JournalOp` type it is welded to, then the legacy-type deletion in `crates/core`, then
the grant-gate wiring, then the feature-gated Windows platform layer.

**Primary recommendation:** Re-scope the failed 4 plans into a 4-plan cluster whose FIRST plan is a single
**atomic Unix FUSE read+write data-model cutover** (the fix for the exact blocker — expand `files_modified`
from 3 files to the full ~15-file Unix blast radius + `crates/sdk/src/queue.rs`), with the green boundary at
the **plan** level. A **clean flag-day cutover is correct and safe** (greenfield, no prod vaults, D-04 mandates
it); no transitional dual-read is needed and D-04 forbids one. The legacy-type deletion, the grant-gate, and
WinFsp follow as three sequenced, independently-green plans — the Unix default build (`default = ["fuse"]`)
stays green through all three because `platform/windows/*` is `#[cfg(feature = "winfsp")]` and is excluded
from the default `cargo check --workspace`, deferring its (unavoidable) breakage to the Windows-CI-verified
final plan.

## 1. File Inventory + Coupling Map

Legend for "Coupling": **[SHARED-FN]** = defines or is reached through a function whose signature carries a
legacy type, so it moves atomically with every caller; **[INODEKIND]** = reads/writes `InodeKind` fields that
flip from ECIES-hex to symmetric; **[EMIT]** = write side that produces the sealed child-key bytes the read
side consumes; **[TYPE-DEF]** = defines a legacy type or an enum field typed as one.

### 1a. Read side — unwrap legacy child keys today, must become symmetric `unseal_*`

| File | Current model | Must become | Coupling |
|------|---------------|-------------|----------|
| `crates/fuse/src/inode.rs` | `InodeTable::populate_folder(&FolderMetadata,…)`; ECIES unwrap of child folder-key/ipns-key at **434, 452, 658, 716** | `populate_folder` takes Node/`ResolvedChild`; child read-key via `unseal_child_read_key` (role `0x02`) → `unseal_node` | [SHARED-FN] `populate_folder` called from `fs.rs:430` (prod) + ~25 in-file tests; [INODEKIND] defines the struct |
| `crates/fuse/src/replay.rs` | `resolve_folder_key`/`resolve_folder_key_cached` BFS; ECIES unwrap at **365, 708, 740, 749, 988**; folder-NAME ECIES unwrap at **839** | BFS consumes `crates/sdk::listing`; node-to-node hops → `unseal_child_read_key`; **839 is a name blob, assess separately** (may stay ECIES if it is a genuine non-node wrap) | [SHARED-FN] resolve_folder_key is the journal-replay key oracle |
| `crates/fuse/src/content_ops.rs` | `fetch_and_decrypt_content_async`; file content-key ECIES unwrap at **52** | fileKey recovered from the file node's sealed read-body (`unseal_node` → `NodeContent.file_key`), NOT ECIES | [SHARED-FN] `fetch_and_decrypt_content_async` is re-exported and called from 5 files (below) |
| `crates/fuse/src/metadata.rs` | read-path helpers naming legacy types; hosts `spawn_file_meta_reencrypt` (line ~777) | repoint helpers to Node; `spawn_file_meta_reencrypt` deleted in the grant-gate plan (SC#2) | [SHARED-FN] |

### 1b. Read consumers — no ECIES themselves, but call 1a's shared fns / read `InodeKind`

These are the ~9 files the 69-09 scope missed. They break the moment a 1a signature or `InodeKind` changes.

| File | Why it is coupled |
|------|-------------------|
| `crates/fuse/src/fs.rs` | calls `self.inodes.populate_folder(…)` at **430** (the one prod caller) |
| `crates/fuse/src/read_ops.rs` | imports + calls `fetch_and_decrypt_content_async` at **57** |
| `crates/fuse/src/dir_ops.rs` | calls `fetch_and_decrypt_content_async` at **133** |
| `crates/fuse/src/operations.rs` | re-exports `fetch_and_decrypt_content_async`, `publish_file_metadata` (**120**) |
| `crates/fuse/src/cache.rs` | references legacy types (`grep` hit) — folder/file metadata cache entries |
| `crates/fuse/src/events.rs` | references legacy types — event payloads carry metadata shapes |
| `crates/fuse/src/poll.rs` | references legacy types — IPNS poll reconcile path |
| `crates/fuse/src/lib.rs` | re-exports (`spawn_file_meta_reencrypt` at ~63; test-only ECIES wraps) |

### 1c. Write side — EMIT the ECIES-wrapped child keys the read side unwraps

| File | Current emission | Must become | Coupling |
|------|------------------|-------------|----------|
| `crates/fuse/src/journal_helpers.rs` | builds `FolderMetadata` (**421**); ECIES-wraps `file_key` (**165**) + folder names (**314, 459**); constructs `JournalOp::MkdirPublish{ parent_metadata: FolderMetadata }` (**466, 486**) | build `Node`; seal child read-keys symmetric; `parent_metadata` becomes Node-shaped | [EMIT][TYPE-DEF-consumer] welded to `crates/sdk::JournalOp` |
| `crates/fuse/src/write_ops/implementation/mkdir.rs` | builds folder metadata via journal_helpers | emit Node + `SealedChildRef` | [EMIT] |
| `crates/fuse/src/write_ops/implementation/upload.rs` | builds file metadata / `JournalOp::UploadFile` | emit Node file body | [EMIT] |
| `crates/fuse/src/write_ops/implementation/delete.rs` | builds `FilePointer` (**120**), `FolderEntry` (**294**) + ECIES-wrap (**186**) for bin restore; unconditional `revoke_shares_blocking` (**159, 329**) | Node-shaped bin refs; symmetric seal; grant-gate replaces revoke (SC#3 plan) | [EMIT][INODEKIND] |
| `crates/fuse/src/write_ops/implementation/rename.rs` | cross-folder re-encrypt comment (**93**); `spawn_file_meta_reencrypt` caller (**248**) | pure `SealedChildRef` relink; delete spawn caller (SC#2) | [EMIT] |
| `crates/fuse/src/write_ops/mod.rs` | write-op glue | thread `WriteChildRef.childId` (D-07) | [EMIT] |

### 1d. The cross-crate type weld (missed by every original plan)

| File | Coupling |
|------|----------|
| `crates/sdk/src/queue.rs` | **`enum JournalOp` (line 46)** has `MkdirPublish.parent_metadata: cipherbox_core::folder::FolderMetadata`. Deleting `FolderMetadata` from `crates/core` is a **compile break in `crates/sdk`**, which forces the `journal_helpers.rs` constructor and `replay.rs` reader to change in the SAME compile unit. **[TYPE-DEF]** — not in 69-10's `files_modified`; a real gap. |

### 1e. Legacy types being deleted (D-04)

| File | Action |
|------|--------|
| `crates/core/src/folder.rs` | DELETE `FolderMetadata`/`FolderEntry`/`FolderChild` (+ drop `pub mod folder;`) |
| `crates/core/src/file.rs` | DELETE/repoint `FileMetadata`/`FilePointer` |
| `crates/core/src/bin.rs` | repoint `BinEntry` refs to Node-shaped |
| `crates/core/src/decrypt.rs` | repoint decrypt helpers to Node decode/unseal |
| `crates/core/src/vault_blob.rs` | NODE-06 two-key v3 blob (ECIES retained for root wrap only) |

### 1f. Windows platform layer — `#[cfg(feature = "winfsp")]`, excluded from default build

| File | Current model | Must become |
|------|---------------|-------------|
| `platform/windows/operations.rs` | file content-key ECIES unwrap at **239** | symmetric `unseal_node` (mirror content_ops.rs:52) |
| `platform/windows/read_ops.rs` | `spawn_metadata_refresh` + FilePointer poll; legacy refs | consume `crates/sdk::listing` |
| `platform/windows/dir_ops.rs` | calls `fetch_and_decrypt_content_async` (**153**) | Node model |
| `platform/windows/content_fetch.rs` | calls `fetch_and_decrypt_content_async` (**32**) | Node model |
| `platform/windows/write_ops.rs` | ECIES seals at **93, 335, 699, 769**; `spawn_file_meta_reencrypt` caller (**1183**); unconditional revoke (**1269**); builds `FilePointer`/`FolderEntry` | symmetric child-key seal; delete spawn caller (SC#2 whole-tree); grant-gate consuming shared `grant_scope` (Pitfall 1); D-07 dual-keying |
| `platform/windows/operations.rs` (glue) | re-exports content_ops fns | Node model |

**ECIES that stays (do NOT migrate — not node-to-node):**

- `content_ops.rs:134` — wraps `file_ipns_private_key` under the **TEE public key** for republish (CLAUDE.md crypto rule #7). Keep.
- `crates/core/src/vault_blob.rs` — `ECIES(rootReadKey)`/`ECIES(rootWriteKey)` vault-root wrap (NODE-06). Keep.
- `replay.rs:839` — folder-NAME blob. Assess at plan time; likely a genuine name wrap, not a node-to-node key hop.
- All `inode.rs` ECIES `wrap_key` at 1367+ are inside `#[cfg(test)]` fixtures — they move with the tests, not prod.

## 2. The Migration DAG

### 2.1 The core coupling theorem (why the original split was impossible)

```
   crates/core::folder::FolderMetadata / FilePointer / FolderEntry   (legacy types, D-04 deletes)
                     ▲                         ▲
                     │ field type              │ constructed by
        crates/sdk::queue::JournalOp   ◄───────┤
                     ▲                         │
                     │ constructs/reads        │
   ┌─────────────────┴───────────┐   ┌─────────┴──────────────┐
   │  WRITE  (EMIT sealed bytes)  │   │  READ (UNWRAP bytes)   │
   │ journal_helpers, mkdir,      │   │ inode.populate_folder, │
   │ upload, delete, rename,      │──►│ replay.resolve_folder_ │
   │ write_ops/mod                │   │ key, content_ops,      │
   └──────────────┬───────────────┘   │ + fs/read_ops/dir_ops/ │
                  │  both pin the      │   cache/events/poll/   │
                  └────────────────────┤   operations/metadata  │
                     InodeKind model    └────────────────────────┘
```

Read unwraps exactly what write seals. Both name the legacy `crates/core` types and both pin the same
`InodeKind` in-memory fields. In Rust, changing a shared type's shape is a **single compile unit** — every
producer and consumer must change together or `cargo check --workspace` is red. Therefore **SC#1 read swap +
write-path Node-v3 emission + the `JournalOp` field + the InodeKind field flip are one atomic change.** This
is precisely the 69-09 finding, now confirmed to additionally include `crates/sdk/src/queue.rs`.

### 2.2 Must write emit Node-v3 BEFORE the read swap? — No: they are simultaneous, not ordered

- **Write-first-alone** (emit symmetric, read still ECIES): compiles only if `InodeKind` keeps both formats
  (a dual model D-04 forbids); otherwise red. Even if forced green, a folder created after write-first is
  unreadable by the still-ECIES read path → **decryption regression**. Rejected.
- **Read-first-alone** (the original 69-09): "a read-path swap has nothing symmetric to read" — there is no
  symmetric per-folder read-key hierarchy in the live write path to unwrap against. Red or regression. Rejected.
- **Simultaneous** (flip `InodeKind` + write emit + read unwrap in one plan): the only green option. **Chosen.**

### 2.3 Transitional dual-read vs clean flag-day — Clean flag-day

- **No prod vaults exist.** 69-RESEARCH Runtime State Inventory (verified): greenfield project-wide, staging
  wiped per `.planning/REQUIREMENTS.md` Out-of-Scope, no persistent cross-format vault. The only "existing
  vault" risk is a developer's own mid-transition local journal/IPNS state — handled by the fail-closed
  journal replay skip (Pitfall 6) + a documented `~/.cipherbox/journal` clear, not by a dual-read codec.
- **D-04 explicitly mandates a clean cutover** and forbids coexistence/bridge. A transitional dual-read would
  directly violate the locked decision.
- **The atomic plan keeps write+read format-consistent at its own green boundary** — there is never a shipped
  state where the two planes disagree. That is what "never regresses decryption" means here: not
  cross-version compatibility, but write/read self-consistency at every green boundary.

**Conclusion:** clean flag-day, no dual-read, atomic Unix cutover. Evidence: 69-09 SUMMARY grep call-graph;
`crates/sdk/src/queue.rs:46` JournalOp weld; `crates/fuse/Cargo.toml` `default = ["fuse"]` feature gate;
68.2 web precedent (below); D-04.

### 2.4 The 68.2 web precedent (mirror source)

The web side (`git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings`) did NOT do a
read-only swap either. On the web, `packages/core`/`packages/sdk` already owned the Node model and the gated
listing (Phases 62–65), so by 68.2 the web READ consolidation was a thin re-point of `client.ts` onto an
already-Node-shaped write plane. The Rust stack has no such head start — the write plane is still legacy — so
the Rust equivalent must do in ONE phase what the web did across 62→65 (write plane) THEN 68.2 (read
consolidation). This is why the Rust cutover is atomic where the web's final step looked incremental: the web
had already paid the write-plane migration cost in earlier phases. Mirror the END STATE (SDK-owned gated
listing, single read entrypoint), not the incremental SHAPE of 68.2's final plan.

### 2.5 Green-boundary invariant

Interpret "green at every step" as **green at every plan (merge) boundary**, not every intra-plan task commit.
An atomic Rust type flip cannot be per-commit-green without the additive dual model D-04 forbids. The four
plans below are each `cargo check --workspace` green at their boundary; the default `fuse` feature keeps the
Unix plans green while `platform/windows` (winfsp feature) stays broken until the final Windows plan closes it
under `--features winfsp` in Windows CI.

### 2.6 DAG (waves)

```
Foundation (MERGED, green):
  69-01 Node types · 69-04 seal · 69-05 scope · 69-06 listing ·
  69-07 grant_scope · 69-08 rotate engine · high_water/floor_store · 69-09 SC#6 CI gate

Wave A ─ P1  Unix FUSE Node-v3 read+write data-model cutover  (ATOMIC flag-day)
                │  depends: foundation
                ▼
Wave B ─ P2  Delete legacy crates/core types + JournalOp repoint  (D-04)
                │  depends: P1 (fuse no longer references legacy types)
                ▼
Wave C ─ P3  Unix grant-root-gated delete/rename + SC#2 + D-07
                │  depends: P1, P2, 69-07, 69-08
                ▼
Wave D ─ P4  WinFsp/Windows platform cutover + TEST-03 sign-off   (feature-gated, LAST)
                   depends: P1, P2, P3, 69-06, 69-07, 69-08
```

## 3. Proposed Re-Scoped Plan Cluster (replaces 69-09 / 10 / 13 / 14)

> The fix is scoping, not new logic. P1 = the old 69-09 with `files_modified` expanded from 3 files to the
> full Unix blast radius + the write path + `crates/sdk/src/queue.rs`. P2/P3/P4 keep their original objectives
> but are now correctly sequenced after a complete P1.

### P1 — Unix FUSE Node-v3 read+write data-model cutover (ATOMIC)

- **Objective:** Flip the entire Unix `crates/fuse` in-memory `InodeKind` + on-IPNS format from legacy
  ECIES/`FolderMetadata` to `node/v3` symmetric, migrating READ (SC#1) and WRITE (Node emission) together in
  one compile unit. Read routes through `crates/sdk::listing::list_folder` (SC#6). Legacy `crates/core` types
  are **retained-but-unreferenced-by-fuse** (deleted in P2). Journal (`JournalOp`) repointed with fail-closed
  replay skip.
- **files_modified:** `crates/fuse/src/{inode,replay,content_ops,fs,read_ops,dir_ops,operations,cache,events,poll,metadata,lib}.rs`, `crates/fuse/src/write_ops/{mod.rs,implementation/{mkdir,upload,delete,rename}.rs}`, `crates/fuse/src/journal_helpers.rs`, `crates/sdk/src/queue.rs` (JournalOp field type).
- **Explicitly NOT here:** `crates/core/src/folder.rs` deletion (P2); the grant-gate/revoke replacement (P3 — P1 leaves `revoke_shares_blocking` behavior as-is or a minimal Node relink); `spawn_file_meta_reencrypt` deletion (P3); `platform/windows/*` (P4, feature-gated).
- **depends_on:** 69-01, 69-04, 69-06 (+ high_water/floor_store).
- **wave:** A.
- **SC covered:** SC#1 (Unix read symmetric unseal), SC#6 (Unix single gated entrypoint; keep 69-09's CI gate), foundation-in-place for SC#2/#3/#4.
- **Green boundary:** `cargo check --workspace` (default `fuse`) + `cargo test -p cipherbox-fuse` + `-p cipherbox-sdk`.
- **Note:** This is a large plan. It is irreducible under D-04 (see §2.5). Structure as sequenced tasks by
  sub-layer (1: `InodeKind` + write seal + `JournalOp`; 2: read consumers `inode`/`replay`/`content_ops`;
  3: glue `fs`/`read_ops`/`dir_ops`/`cache`/`events`/`poll`/`operations`/`metadata`) but the guaranteed-green
  checkpoint is the plan boundary.

### P2 — Delete legacy crates/core types (D-04 core cutover)

- **Objective:** DELETE `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` from `crates/core`; repoint
  `bin.rs`/`decrypt.rs`/`vault_blob.rs` (NODE-06 two-key v3 blob, ECIES retained root-only); no bridge/adapter.
- **files_modified:** `crates/core/src/{folder,file,bin,decrypt,vault_blob,lib}.rs`.
- **depends_on:** P1 (fuse + sdk queue already off the legacy types).
- **wave:** B.
- **SC covered:** SC#4 (legacy-type deletion half; Node enum + durable floor already delivered in 69-01/05).
- **Green boundary:** `cargo check --workspace` (default) — `platform/windows` still names deleted types but
  is `#[cfg(feature="winfsp")]`, excluded from the default build (breakage deferred to P4, by design).

### P3 — Unix grant-root-gated delete/rename + SC#2 + D-07

- **Objective:** Replace the unconditional `revoke_shares_blocking` (delete.rs 159/329, rename path) with the
  grant-root gate: `has_covering_grant` FALSE → pure relink, ZERO rotation publishes (ROT-02); TRUE →
  `rotate_read_from_node` EXACTLY ONCE at the matched grant-root ancestor. Delete `spawn_file_meta_reencrypt`
  + Unix caller (SC#2). Thread BOTH `WriteChildRef.childId` (UUID) AND `SealedChildRef.ipnsName` (D-07).
  Honor D-08 (write-recipient unlink+bin, no cross-principal revoke).
- **files_modified:** `crates/fuse/src/write_ops/implementation/{delete,rename}.rs`, `crates/fuse/src/metadata.rs`, `crates/fuse/src/lib.rs`, `.github/workflows/ci.yml` (SC#2 grep gate, non-Windows-scoped until P4).
- **depends_on:** P1, P2, 69-07 (grant_scope), 69-08 (rotate engine), 69-05 (scope predicate).
- **wave:** C.
- **SC covered:** SC#3 (grant-root gating), SC#2 (spawn deletion, Unix), D-07, D-08.
- **Security review:** flag `crates/fuse/src/write_ops/` (D-07 conflation) — gsd-security-auditor.
- **Green boundary:** `cargo test -p cipherbox-fuse delete rename` (0-rotate private / 1-rotate shared spies) + `cargo check --workspace`.

### P4 — WinFsp / Windows platform cutover + TEST-03 sign-off (LAST, feature-gated)

- **Objective:** Bring `platform/windows/*` into node/v3 + grant-root conformance so
  `cargo check/test --workspace --no-default-features --features winfsp` is green. SC#1 Windows
  (operations.rs:239), SC#6 Windows (gated listing, no carve-out), SC#3+D-07 Windows write gate **consuming the
  shared `grant_scope` module** (Pitfall 1 — never re-implement), SC#2 whole-tree (delete write_ops.rs:1183
  caller, promote grep gate). Repoint Windows create/mkdir/bin-restore seals off deleted `FilePointer`/
  `FolderEntry`+`ecies::wrap_key` onto symmetric child-key seal.
- **files_modified:** `crates/fuse/src/platform/windows/{operations,read_ops,dir_ops,write_ops,content_fetch}.rs`, `crates/fuse/src/lib.rs`, `.github/workflows/ci.yml`.
- **depends_on:** P1, P2, P3, 69-06, 69-07, 69-08.
- **wave:** D.
- **autonomous:** **false** (D-06 — user iterates on their Windows box; winfsp build is CI-only on macOS).
- **SC covered:** SC#1/#2/#6 (Windows), SC#3+D-07 (Windows), SC#5 / TEST-03.
- **Sign-off (TEST-03):** `Cargo Check & Test (Windows)` job (`cargo-windows`, `--features winfsp`) green +
  dispatched desktop E2E green. NOTE the workflow `name:` is **"Desktop E2E Tests"**, not "CI E2E Tests"
  (69-14 verified live) — `gh workflow list` then `gh workflow run "Desktop E2E Tests" --ref <branch>`.
  Confirm the `cargo-windows` job actually RAN (not path-filter-skipped, Pitfall 7).

### Preserved locked constraints (unchanged by re-scoping)

- **SC#2:** `spawn_file_meta_reencrypt` deleted — Unix caller in P3, Windows caller + whole-tree gate in P4.
- **SC#3:** grant-root gating consumes 69-07 `grant_scope` + 69-08 `rotate_read_from_node` — one shared module for both platforms (Pitfall 1).
- **D-06:** WinFsp isolated as its own plan (P4), `autonomous: false`.
- **D-07:** dual-keying (`childId` UUID vs `ipnsName`) threaded in P3 (Unix) and P4 (Windows); security review both.
- **TEST-03:** on P4 (the Windows plan).

## 4. Landmines

1. **The `crates/sdk::queue::JournalOp` weld (missed by all 4 original plans).** `JournalOp::MkdirPublish.parent_metadata: cipherbox_core::folder::FolderMetadata` lives in `crates/sdk/src/queue.rs:46`, not in fuse. Deleting `FolderMetadata` breaks `crates/sdk` compilation, which cascades to `journal_helpers.rs` (constructor) and `replay.rs` (reader). **`crates/sdk/src/queue.rs` MUST be in P1's `files_modified`.** 69-10 scoped only `metadata.rs`/`journal_helpers.rs` — it would not have compiled.

2. **Deleting legacy `crates/core` types before ALL consumers migrate.** The read/write/journal consumers span ~15 Unix files + `crates/sdk/queue.rs`. Any file left on legacy types when `folder.rs` is deleted = build break. This is exactly why P2 (delete) must follow a COMPLETE P1 (migrate). 69-10's assumption "compiles only because 69-09 already moved the FUSE read path" was false because 69-09 was scoped to 3 files, not the full radius.

3. **The `default = ["fuse"]` feature gate is the linchpin — do not accidentally break it.** `platform/windows/*` is `#[cfg(feature="winfsp")]` and is NOT compiled by `cargo check --workspace` (default). This is what lets P1/P2/P3 be green while Windows lags. But it also means **P1/P2/P3 CANNOT compile-verify any Windows change** — a planner must not put Windows files in P1-P3 expecting the default gate to catch errors. Windows is verified ONLY under `--features winfsp` in the `cargo-windows` CI job (P4). Conversely, do not let P2's core deletion accidentally reference a winfsp-only symbol.

4. **Splitting P1 by read-vs-write reintroduces the blocker.** Any planner temptation to make P1 two plans ("write emits Node-v3" then "read consumes Node-v3") fails: they share `InodeKind` + the on-IPNS format. The only per-plan-green split is migrate-all-fuse (P1) then delete-core-types (P2) — which is the P1/P2 boundary already chosen. Do not split finer.

5. **`spawn_file_meta_reencrypt` deletion ordering (Pitfall 5).** Must be AFTER the Node model lands (P1) — it is dead-by-construction once each node self-seals under its own readKey. Deleting it in P1 (mid-flip) or before leaves cross-folder moves with no re-key path. Unix caller: P3; Windows caller: P4 (feature-gated).

6. **Journal replay must fail-closed, not panic (Pitfall 6).** A developer's pre-cutover on-disk `<journal_dir>/*.json` entry will fail `serde_json::from_str` against the new Node-shaped `JournalOp`. P1's replay loop must `log::warn!` + SKIP (mirror `queue.rs`'s Err-skip), never `unwrap()`/`panic!`, and document the `~/.cipherbox/journal` clear.

7. **Distinguish node-to-node ECIES (migrate) from root/TEE/name ECIES (keep).** KEEP: `content_ops.rs:134` (TEE pubkey wrap, crypto rule #7), `vault_blob.rs` (NODE-06 root wrap), `replay.rs:839` (folder-name blob — assess), all `inode.rs` `#[cfg(test)]` wraps (1367+). MIGRATE: `inode.rs` 434/452/658/716/788/2492, `replay.rs` 365/708/740/749/988, `content_ops.rs:52`, `journal_helpers.rs` 165, `delete.rs` 120/186/271/294, `platform/windows/*`. A blanket `grep -v ecies` gate would wrongly flag the keepers — scope the SC#1 gate to node-to-node call sites only.

8. **The desktop construction sites (`apps/desktop/src-tauri/src/fuse/*`) — CONFIRMED live.** `apps/desktop/src-tauri/src/fuse/mod.rs` and `fuse/windows/mod.rs` construct `CipherBoxFS { … }` by struct-literal, use `cipherbox_fuse::replay_for_vault`, `write_ops::grant_scope::SentSharesCache`, `platform::windows::operations::…WinFspContext`, and the `PendingFilePointer` channel type. If P1 changes any `pub` field/signature the desktop constructs against (or P2 deletes `FilePointer`, on which the desktop's `PendingFilePointer`/`filepointer_tx` channel is modeled), `apps/desktop/src-tauri` breaks the workspace build. Grep `apps/desktop/src-tauri/src/fuse` for `CipherBoxFS`/`PendingFilePointer`/`replay_for_vault`/legacy-type imports at P1/P2 plan time and include broken construction sites in `files_modified` — the workspace build includes the desktop crate. (The Windows desktop glue is itself winfsp-gated, so its breakage tracks P4, but `fuse/mod.rs` is not.)

9. **`revoke_shares_blocking` must be REPLACED, not augmented (anti-pattern).** Today it fires unconditionally on every delete/rmdir. P3 must remove the unconditional call and route through the gate — adding a gated call while leaving the unconditional one is the ROT-02 over-rotation anti-pattern (a private delete would still revoke). Grep the two former sites (delete.rs 159/329) to confirm removal.

10. **`grant_scope` is already `any(fuse, winfsp)`-gated (correct) — do NOT narrow it.** `write_ops/mod.rs:5` declares `pub mod grant_scope` as platform-agnostic `#[cfg(any(feature = "fuse", feature = "winfsp"))]`, reachable from both `write_ops/implementation/*` (Unix, `fuse`) and `platform/windows/write_ops.rs` (`winfsp`). P3/P4 must CONSUME it, and P1 must not accidentally re-gate it to `feature="fuse"`-only, or P4's Windows write gate loses access and would be tempted to re-implement the predicate (Pitfall 1 violation). Its `SentSharesCache` is fed by `cipherbox_api_client::shares::collect_sent_shares` (69-03) — already merged.

## Sources

- `.planning/.../69-09-SUMMARY.md` (via `git show worktree-agent-a8cce22ff1ad4dcdb:`) — the blocker investigation + grep call-graph.
- `.planning/.../69-{09,10,13,14}-PLAN.md` — the 4 plans being re-sequenced (files_modified, depends_on, waves).
- `.planning/.../69-CONTEXT.md` (D-01..D-08), `69-RESEARCH.md` (Pitfalls 1–7, Runtime State Inventory, Architecture Patterns).
- Live grep this session: `crates/fuse/src/**` (ECIES sites, legacy-type refs, shared-fn callers), `crates/sdk/src/queue.rs:46` (JournalOp weld), `crates/fuse/Cargo.toml` (`default = ["fuse"]`, `winfsp` gate), `crates/fuse/src/platform/mod.rs` (`#[cfg(feature="winfsp")]`), foundation module listing (`crates/core/src/node/*`, `crates/sdk/src/{listing,floor_store,rotation}`, `crates/fuse/src/write_ops/grant_scope.rs`).
- 68.2 mirror contract (D-01, via `git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings:`).

## Metadata

**Confidence:** HIGH — the coupling map, the atomic-cutover conclusion, the JournalOp weld, and the feature-gate
linchpin are all grounded in live grep + the independent 69-09 executor finding. The only MEDIUM item is the
exact task-level decomposition of P1 (a planner call), and the `replay.rs:839` name-blob classification (assess
at plan time).

**Research date:** 2026-07-06
**Valid until:** 14 days (in-flight milestone; re-verify grep line numbers if execution is delayed).
