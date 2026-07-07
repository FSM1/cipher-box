---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 09
subsystem: fuse-desktop
tags: [rust, node-v3, fuse, desktop, winfsp, inode-table, replay, sc6, atomic-cutover, cipherbox-fuse, cipherbox-desktop]

# Dependency graph
requires:
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness (plan 16)
    provides: "create_folder_node/create_file_node + build_child_refs (D-07 dual-keying) + ApiNodeFetcher + new_journal_high_water in crates/sdk/src/emit.rs + adapter.rs"
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness (plan 17)
    provides: "list_folder_owned + ResolvedOwnedChild {read_key, write_key, ipns_private_key} owned materialization in crates/sdk/src/listing.rs"
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness (plan 02)
    provides: "RotationHighWater::enforce_resolved + JsonSidecarFloorStore anti-rollback floor gate"
provides:
  - "cipherbox-fuse fully on node/v3: InodeKind carries {read_key, write_key, ipns_private_key}; read path via list_folder_owned/fetch_node_gated, write path emits Node + reshaped JournalOp, replay reinterprets node/v3 journal"
  - "cipherbox-desktop mount (macOS/Linux + winfsp) root population via list_folder_owned + Node populate_folder; replay_for_vault caller on node/v3 root keys"
  - "SC#6 single-gated-read CI grep gate in .github/workflows/ci.yml (cargo-linux lane)"
affects: [69-10, 69-13, 69-14]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "InodeKind is node/v3 owner state: each variant holds Zeroizing {read_key:[u8;32], write_key:[u8;32], ipns_private_key:Vec<u8>} moved straight out of ResolvedOwnedChild (mount = terminal owner, D-09 — moved in, never borrowed-then-zeroed). Legacy node-to-node hex fields (encrypted_folder_key/encrypted_file_key/folder_key) are gone"
    - "populate_folder is now the async fetch (list_folder_owned) + apply_owned_children is the sync apply half of the refresh pipeline; the FUSE callback thread never awaits — a background task fetches Vec<ResolvedOwnedChild> and drain_refresh_completions applies it"
    - "File content descriptors (cid/iv/size/encryption_mode) live in the file node's OWN sealed read-body and are recovered lazily via the gated fetch_node_gated -> resolve_file_descriptors (empty cid == unresolved); no descriptors are stored at populate time"
    - "SC#6 discipline enforced by CI: all crates/fuse/src reads route through the sanctioned gated entrypoints (list_folder / list_shared_folder / list_folder_owned / fetch_node_gated); a raw resolve_ipns_verified/resolve_published_node call requires an inline // sc6-allow marker"

key-files:
  created: []
  modified:
    - apps/desktop/src-tauri/src/fuse/prepopulate.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
    - crates/fuse/src/inode.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/cache.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/journal_helpers.rs
    - crates/fuse/src/publish.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/write_ops/grant_scope.rs
    - crates/fuse/src/write_ops/implementation/delete.rs
    - .github/workflows/ci.yml

key-decisions:
  - "Atomic cutover landed across five sequential slices (1 types+wiring, 2 read, 3 write, 4 replay, 5b lib-green refresh-pipeline redesign) plus 5c (desktop + test module + SC#6 gate) on ONE branch. RED intermediate commits were acceptable per the grind runbook; the FINAL merge is gated on a real local sdk-e2e + desktop-e2e run, NOT cargo-check-green"
  - "DELETE (not laboriously rewrite) legacy-model tests that assert the intentionally-removed pre-node/v3 crypto model — rewriting them risks false-green. Deep node-to-node crypto correctness is covered by the SDK seal/listing vectors and the later E2E gate (explicit user decision)"
  - "Desktop node/v3 root read/write keys are bridged from the legacy root_folder_key with a domain-separated placeholder write_key. The REAL root keys are randomly generated at vault registration (sdk-core registration.ts) and persisted server-side; desktop recovery into KeyState is NOT yet wired (v2.0 client runtime stubbed, phase 63). This is compile/CI-green but E2E-gated — flagged, not overclaimed"
  - "SC#6 gate marker placement is rustfmt-stable: a // sc6-allow marker on the call line lands (via rustfmt) on the line immediately below; the gate checks a ±1-line window so it survives formatting. Negative-tested (an unmarked resolve is flagged)"
  - "No new Cargo dependency added anywhere in the slice"

requirements-completed: []

metrics:
  duration: "~1 session"
  commits: 4
  files-changed: 13
  net-lines: "+577 / -1872"
  completed: 2026-07-06

status: complete
---

# Phase 69 Plan 09: Atomic FUSE node/v3 Cutover Summary

The `cipherbox-fuse` crate and the `cipherbox-desktop` mount are fully migrated to the node/v3 sealed-node model; the entire Rust workspace is green (`cargo check --workspace`, `cargo test -p cipherbox-fuse`, `cargo test -p cipherbox-sdk`), the node-to-node ECIES hops are gone, and a CI grep gate enforces single-gated-read discipline (SC#6).

## The five-slice + 5b/5c grind

69-09 was executed atomically on branch `worktree-agent-aad501548bf8c685c` across bounded per-session slices (RED intermediate commits allowed per the grind runbook). Prior slices (carried in this branch's history):

- **Slice 1** (`4efcc3ef9`) — reshaped `InodeKind` to node/v3 owner state `{read_key, write_key, ipns_private_key}`; added `high_water: RotationHighWater<JsonSidecarFloorStore>` to `CipherBoxFS`. 120 downstream errors, all consumers.
- **Slice 2** (`26cb97b36`) — read path onto `list_folder_owned` + `unseal_node`; both `ecies::unwrap_key` greps empty.
- **Slice 3** (`d9a0c9220`) — write path emits `Node` + reshaped `JournalOp::{UploadFile,MkdirPublish}` (D-07 dual-keying via `build_child_refs`).
- **Slice 4** (`586cfd444`) — `replay.rs` reinterprets the reshaped journal; recovers parent signing seed via `list_folder_owned` BFS from root; fail-closed skip on stale/deser failure.
- **Slice 5 (TASK 0)** (`019a6968b`) — added `fetch_node_gated` (SC#6 single-node read) to the SDK.
- **Slice 5b** (`68c8b5d93`, `28328fb0e`, `9db2016a2`, `da5e158a9`) — drove `crates/fuse` LIB to green: `#[derive(Clone)]` on `RotationHighWater`, read/prefetch glue on `fetch_node_gated`, live per-file `publish_file_node` (first + CAS, leaving `publish_file_metadata`/69-13 untouched), and the refresh-pipeline redesign (`populate_folder` split into async-fetch + `apply_owned_children` sync-apply; `PendingRefresh::Success{children}`; `metadata_cache` as a pure freshness marker).

## Slice 5c — this plan (commits below)

Drove the FULL workspace to green:

| # | Commit | What |
|---|--------|------|
| 1 | `c2910ea5f` | Desktop root population + replay caller onto node/v3 |
| 2 | `445384bf8` | Migrate fuse test module to node/v3 (delete legacy-model tests) |
| 3 | `5bb22969d` | SC#6 single-gated-read CI grep gate |
| 4 | (this doc) | SUMMARY |

### (1) Desktop — `cargo check --workspace` green

- `prepopulate.rs`: the ~330-line legacy block (`resolve_ipns_verified` + `decrypt_metadata_from_ipfs_public` + 5-arg `populate_folder` + 7-arg `resolve_file_pointer` per-child ECIES) was replaced by the gated node/v3 owned listing: `InodeTable::populate_folder` (→ `list_folder_owned`, SC#6) for root + immediate subfolders, then eager file-descriptor resolution via `content_ops::resolve_file_descriptors` (→ `fetch_node_gated`, SC#6). `initial_sequences` is now returned empty (the owned listing surfaces no IPNS sequence numbers; the coordinator records sequences as publishes happen, first publish embeds seq 1).
- `mod.rs` + `windows/mod.rs`: `InodeKind::Root` filled with node/v3 `{ipns_name, read_key, write_key, ipns_private_key}`; `replay_for_vault` caller updated to the new sig `(journal, api, journal_dir: PathBuf, root_read_key: &[u8;32], root_write_key: &[u8;32], root_ipns_name, coordinator, tee_public_key, tee_key_epoch)` — legacy `private_key`/`public_key`/`root_folder_key` replay args gone. `windows/*` is `#[cfg(feature="winfsp")]` (69-14 CI owns its compile) and was edited for correctness.

### (2) Fuse test module — `cargo test -p cipherbox-fuse` green

201 test-compile errors resolved (149 in the initial `--no-run`, more surfaced as earlier crate-units compiled). Per the runbook + user decision: DELETE legacy-model tests, KEEP/PORT non-crypto mechanics, ADD node/v3 smoke tests.

**Deleted (asserted the intentionally-removed model):**

- `inode.rs` — the entire legacy test module tail (~1450 lines): 5-arg `populate_folder(&FolderMetadata)` round-trips (`test_populate_folder_with_file_pointers`, `..._matches_renamed_folder_by_ipns_name`, `..._initial_mount`, `..._resets_resolved_file_on_modified_at_change`), the ECIES-keypair `mark_remotely_edited_*` round-trips, the `d11_*` and `upsert_children_*` suites (all on the removed 5-arg signature + `generate_test_keypair`), and the Option-shaped `ipns_private_key` field-presence checks (`test_inode_kind_folder/root_has_ipns_private_key`).
- `lib.rs` — `decrypt_journal_name_round_trip_and_legacy_compat` (the `crate::replay::decrypt_journal_name` ECIES filename-unwrap helper was deleted in Slice 4; the child name now travels plaintext in `SealedChildRef.name`).

**Kept / ported (non-crypto mechanics):**

- `inode.rs` — table construction, id allocation, insert/find/remove, and NFC name handling (ported `InodeKind` literals to node/v3 fields; no crypto assertions).
- `cache.rs` — the 3 `MetadataCache` tests ported to the node/v3 freshness-marker API (2-arg `set(ipns, cid)`).
- `fs.rs` — the `drain_refresh_completions` refresh-pipeline tests (gated remote-edit mark, local-mutation preservation, unmutated populate, failure guard) ported to `PendingRefresh::Success{children: Vec<ResolvedOwnedChild>}` + node/v3 `InodeKind::File`.
- `lib.rs` — `replay_reuploads_ciphertext` sidecar round-trip (D-01/D-04 durability) ported to the reshaped `JournalOp::UploadFile` (SealedChildRef/WriteChildRef fixtures); `mkdir_happy_path`/`mkdir_conflict_rearms`/replay durability tests were already node/v3.
- `journal_helpers.rs` — the node/v3 `build_mkdir_journal_entry` MkdirPublish test (added a `use base64::Engine;` import for `.decode`).
- `write_ops/grant_scope.rs` + `write_ops/implementation/delete.rs` — test-helper `InodeKind` literals ported to node/v3 fields.

**Added (node/v3 smoke tests):**

- `inode.rs` — `apply_owned_children_populates_and_marks_loaded`, `..._reuses_ino_on_rename_by_ipns_name`, `..._merge_only_preserves_absent_children`, and `resolve_file_pointer_fills_descriptors` — exercising the sync-apply half of the refresh pipeline against `ResolvedOwnedChild` fixtures (stable-ipns-name ino reuse, rename-by-ipns, merge_only preservation, placeholder → resolved).

Result: 92 lib + 1 cross-language-vector tests pass.

### (3) SC#6 CI gate

Added to the `cargo-linux` lane of `ci.yml`. Fails if `crates/fuse/src` contains a raw `resolve_ipns_verified(` / `resolve_published_node(` CALL without a `// sc6-allow:` marker within a ±1-line window (rustfmt-stable). Read path (`inode`/`content_ops`/`read_ops`/`dir_ops`/`fs`/`events`) has **zero** raw resolves.

**Gate command (bash, cargo-linux lane):**

```bash
fail=0
while IFS=: read -r file lineno _; do
  win=$(sed -n "$(( lineno > 1 ? lineno - 1 : 1 )),$(( lineno + 1 ))p" "$file")
  if ! printf '%s\n' "$win" | grep -q 'sc6-allow'; then
    echo "::error file=$file,line=$lineno::SC#6 violation — unsanctioned raw IPNS resolve."
    fail=1
  fi
done < <(grep -rnE 'resolve_ipns_verified\(|resolve_published_node\(' crates/fuse/src)
[ "$fail" -ne 0 ] && exit 1
```

**Allowlisted non-read-path sites (inline `// sc6-allow` markers):**

| File | Site | Reason |
|------|------|--------|
| `publish.rs` (2×) | `resolve_sequence` / `resolve_sequence_strict` | replay-path sequence resolve (`resolve_ipns_for_replay`) |
| `metadata.rs` | `spawn_bin_entry_publish` | legacy recycle-bin publish, not node/v3 |
| `metadata.rs` | `resolve_and_fetch_file_meta` | 69-13 file-meta reencrypt path |

Local dry-run: zero unsanctioned hits. Negative test (injected an unmarked raw resolve into a temp copy): correctly flagged.

## Green boundary evidence (verified in worktree)

| Check | Result |
|-------|--------|
| `cargo check --workspace` (default fuse feature) | 0 errors |
| `cargo test -p cipherbox-fuse` | 92 + 1 passed, 0 failed |
| `cargo test -p cipherbox-sdk` | 132 passed, 0 failed |
| `grep ecies::unwrap_key inode.rs content_ops.rs` | 0 / 0 (empty) |
| SC#6 gate dry-run | CLEAN (3 allowlisted, 0 unsanctioned) |

## Deviations from Plan

Executed exactly per the grind runbook's Slice 5c task list. One bridging deviation, flagged:

- **[Rule 2 / Rule 3] Desktop node/v3 root keys bridged from legacy `root_folder_key`.** The desktop `KeyState` does not yet carry node/v3 root read/write keys (server-persisted, recovered by the stubbed v2.0 client runtime — phase 63). To reach compile-green without expanding scope into the keeper auth flow, `mount_filesystem` derives `root_read_key` from `root_folder_key` and `root_write_key` from a domain-separated placeholder transform, with a prominent in-code E2E-RISK note. The plumbing (params threaded through prepopulate + replay + InodeKind::Root) is correct; the key BYTES are placeholders until server recovery is wired. See E2E-risk list below.

## Known Stubs

- **Desktop root read/write key bridge** (`apps/desktop/src-tauri/src/fuse/mod.rs`, `windows/mod.rs`) — placeholder derivation from `root_folder_key`; real keys are server-persisted and desktop recovery is not yet wired. Compile/CI-green, runtime E2E-gated. Not a per-slice regression — it is the boundary of what the atomic cutover can wire without the (stubbed) v2.0 client root-key recovery.

## Consolidated E2E-risk list (for the orchestrator's merge gate)

The REAL correctness gate is the orchestrator's later local sdk-e2e + desktop-e2e run (docker + TEE). This slice reached compile-green + unit-green honestly; the following node/v3 behaviors are NOT verified at runtime here and must pass E2E before merge:

1. **Desktop root read/write keys** are placeholder-bridged from `root_folder_key` (real keys server-persisted, recovery not wired) — a real node/v3 vault mount will read/write with wrong root keys until recovery lands.
2. **File `versions`** are not reconstructed on write — `InodeKind` dropped the `versions` field (Slice 1); `NodeContent.versions` exists but the write path does not populate it. File-versioning regression to verify.
3. **`file_iv` hex round-trip** — the write path builds `NodeContent.file_iv` as HEX and `content_ops` `hex::decode`s it; verify the round-trip end-to-end.
4. **Gated content read** — file content is fetched via `fetch_node_gated` → `fetch_and_decrypt_content_async(api, &PublishedNode, &read_key)`; verify decrypt correctness against a real sealed node.
5. **Overwrite / CAS path** — `publish_file_node` (first-publish + CAS-update tail) is new; verify the CAS conflict/retry path against a live IPNS.
6. **Orphaned parent-CID pins** — `metadata_cache` no longer surfaces the old metadata CID for unpin after re-publish; stale parent CIDs may accumulate as GC-able orphan pins (not correctness-critical, but verify GC).
7. **`~/.cipherbox/journal` first-mount** — node/v3 sidecar high-water gate lives adjacent to the journal; verify a clean first mount + replay against a fresh journal dir.

## Self-Check: PASSED

- `.planning/phases/69-.../69-09-SUMMARY.md` — written (this file).
- Commits `c2910ea5f`, `445384bf8`, `5bb22969d` — present in `git log` on `worktree-agent-aad501548bf8c685c`.
- Green boundary (workspace check, fuse tests, sdk tests, ecies greps, SC#6 gate) — all pass per evidence table above.
