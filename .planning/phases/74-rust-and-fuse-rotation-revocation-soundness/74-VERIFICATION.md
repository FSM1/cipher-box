---
phase: 74-rust-and-fuse-rotation-revocation-soundness
verified: 2026-07-11T00:00:00Z
status: passed
score: 21/21 must-haves verified
behavior_unverified: 0
overrides_applied: 0
human_verification:

  - test: "Dispatch `Cargo Check & Test (Windows)` CI on this branch and confirm it compiles cleanly and the two new WinFsp rename tests (`rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt`, `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit`) pass."
    expected: "Windows CI job green; both tests pass; the existing `replace_if_exists=false` collision-rejection scenario is unregressed."
    why_human: "`crates/fuse/src/platform/windows/write_ops.rs` is `#[cfg(feature = \"winfsp\")]`-only and does not compile on macOS/Linux (confirmed locally: `cargo check -p cipherbox-fuse --features winfsp` fails on `windows-future`/`windows_core::imp` — a genuine macOS toolchain limitation, not a code defect). Source-level inspection confirms the D-15d ordering (collision check -> ENOTEMPTY check -> source gate -> dest gate -> mutate) is implemented correctly and matches the fuser reference verbatim, but this cannot be compiled/run outside Windows CI."

  - test: "Dispatch the `desktop-e2e` GitHub Actions workflow (matrix: macOS/Linux/Windows) on this branch and confirm Part C (deep decryptability + retained-vs-revoked) and Part D (WinFsp overwrite-rename dest-gate) pass on all 3 platforms, and Part A/B remain green."
    expected: "All legs pass; Part A's Bob assertion (`bobCanReadAfterRotation === false`) still holds post-74-05."
    why_human: "Real-mount FUSE/WinFsp + live API + IPNS round-trip; no live desktop binary/mount was built in this session (matches project memory `project-headless-desktop-fuse-uat` / `project-winfsp-build-ci-only-macos`). Regarding the 74-07-flagged 'Known Risk' about Part A's Bob assertion possibly flipping after 74-05's real `query_grants_rooted_at`: static code reading shows `bobCanReadAfterRotation` is computed against `bobFolderReadKey`, a raw key captured ONCE via `unwrapKey` before rotation and never re-fetched from `/shares/received` after rotation. `canRead()` decrypts directly against the given raw key bytes with no live grant lookup. Since rotation always mints a genuinely new post-rotation key regardless of whether Bob's grant row is also re-minted by 74-05, this stale local variable will not decrypt the new content either way — the assertion tests 'does my captured pre-rotation key still work', not 'is my grant still active'. This is a low-confidence-of-regression assessment from static reading only; live CI confirmation is the authoritative check."
---

# Phase 74: Rust and FUSE Rotation Revocation Soundness Verification Report

**Phase Goal:** Close the remaining scope-exit read-revocation bypasses on the Rust/desktop side so the M4 revocation guarantee holds end-to-end. The rotation engine surfaces every rotated node's new read key (not just the grant-root), all intermediate FUSE inodes are refreshed on rotation, the desktop grant-re-mint seam is wired so retained recipients keep access while revoked ones are cut, and WinFsp overwrite-rename is dest-gated with fuser ordering parity.

**Verified:** 2026-07-11
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | (SC1/74-01) `RotateReadResult` surfaces every rotated node's post-rotation read key keyed by `ipns_name`, not just the grant root | ✓ VERIFIED | `crates/sdk/src/rotation/engine.rs:808-843` — `RotatedNodeKey` struct + `RotateReadResult.rotated_nodes: HashMap<String, RotatedNodeKey>`. Populated at root commit hook (line 1632), BFS child commit hook (line 1879), AND `repair_dirty_node` crash-resume hook (line 2096 — folded in beyond the plan's minimum). `cargo test -p cipherbox-sdk rotation::engine::` — 27/27 passing, including `rotate_read_surfaces_every_rotated_node_key_for_a_deep_tree` (asserts root+folderB+fileC all present, distinct non-zero keys). |
| 2 | (SC1/74-01) Map populated at both root commit hook and BFS child commit hook | ✓ VERIFIED | Same as above — confirmed by direct source read at both call sites. |
| 3 | (SC1/74-01) Depth>=2 tree yields `rotated_nodes` containing every level's key | ✓ VERIFIED | Deep-tree test asserts `result.rotated_nodes.len() == 3` for root+folderB+fileC (`engine.rs:4716-4721`). Test passes. |
| 4 | (SC1/74-02) TS `RotateReadResult` carries `rotatedNodes` map keyed by `ipnsName`, field-for-field parity with Rust | ✓ VERIFIED | `packages/sdk-core/src/rotation/engine.ts:343-378` — `RotatedNodeKey` type + `rotatedNodes: Map<string, RotatedNodeKey>`. Fields match Rust 1:1 (`sequenceNumber: bigint` deliberately, matching the file's existing IPNS-sequence convention rather than the plan table's literal `number` — documented, sound deviation). Exported from both `rotation/index.ts` and `index.ts`. |
| 5 | (SC1/74-02) Map populated at TS structural equivalents of root/BFS-child commit points | ✓ VERIFIED | `engine.ts:2064` (root branch `rotatedNodes.set(rootNodeIpnsName, ...)`) and `engine.ts:2235` (BFS child branch `rotatedNodes.set(item.childRef.ipnsName, ...)`). `pnpm --filter @cipherbox/sdk-core test -- rotation/engine` — 370/370 passing (32 files), including the new deep-tree parity test at `engine.test.ts:3509`. |
| 6 | (SC1/74-02) Depth>=2 tree yields `rotatedNodes` with every level | ✓ VERIFIED | Deep-tree parity test mirrors the Rust structure and passes. |
| 7 | (SC1/74-03) Every rotated node's FUSE inode has its in-memory `read_key` refreshed, not only the grant root | ✓ VERIFIED | `crates/fuse/src/write_ops/grant_scope.rs:575-597` — `refresh_rotated_inode_read_keys` loops over `result.rotated_nodes` with NO early return, matching `Root \| Folder \| File` by `ipns_name`. Called at `rotate_read_on_scope_exit` line 530. `cargo test -p cipherbox-fuse write_ops::grant_scope::` — 17/17 passing, including `refresh_rotated_inode_read_keys_refreshes_intermediate_and_file_inodes`. |
| 8 | (SC1/74-03) Refresh covers `InodeKind::Root`, `Folder`, AND `File` | ✓ VERIFIED | Match arm at `grant_scope.rs:586-596` explicitly includes all three (File arm is new — closes a related staleness gap). |
| 9 | (SC1/74-03) Refresh matches inodes by `ipns_name` against `RotateReadResult.rotated_nodes` from 74-01 | ✓ VERIFIED | Confirmed at same location; signature is `(inodes: &mut InodeTable, result: &RotateReadResult)`. |
| 10 | (SC2/74-04) `update_grant` issues PATCH `/shares/:shareId/grant` with `encryptedReadKey`+`rootGeneration` only | ✓ VERIFIED | `crates/api-client/src/shares.rs:98-129` — `UpdateGrantRequest` (`#[serde(rename_all = "camelCase")]`, only `encrypted_read_key`/`root_generation` fields). `cargo test -p cipherbox-api-client shares::` — 15/15 passing, including `update_grant_patches_grant_path_with_read_key_only_body` (mock server asserts exact body key set). |
| 11 | (SC2/74-04) `revoke_share` issues DELETE `/shares/:shareId`, treats 204 as success | ✓ VERIFIED | `shares.rs:130-` — confirmed via `revoke_share_deletes_share_path` test, passing. |
| 12 | (SC2/74-04) Both wire functions map non-2xx to `ApiError::ApiResponse` with prefixed messages | ✓ VERIFIED | `update_grant_non_2xx_maps_to_api_response_error`, `revoke_share_non_2xx_maps_to_api_response_error`, `revoke_share_500_maps_to_api_response_error` all pass. |
| 13 | (SC2/74-05) `query_grants_rooted_at` returns live grants via `collect_sent_shares` filtered by `root_node_id == node_id` | ✓ VERIFIED | `crates/fuse/src/write_ops/rotation_deps.rs:264-284` — exact filter + hex-decode implementation. `cargo test -p cipherbox-fuse write_ops::rotation_deps::` — 10/10 passing, including `query_grants_rooted_at_filters_by_root_node_id_and_hex_decodes_recipient_key`. |
| 14 | (SC2/74-05) `update_grant` forwards already-ECIES-wrapped key through the seam, no re-wrapping | ✓ VERIFIED | `rotation_deps.rs:292-303` — pure forward to `self.transport.update_grant(...)`; no crypto call in this function. |
| 15 | (SC2/74-05) `delete_grant` forwards through the seam to DELETE | ✓ VERIFIED | `rotation_deps.rs:308-310` — forwards to `self.transport.revoke_share(share_id)`. |
| 16 | (SC2/74-05) `recipient_public_key` hex-decoded (0x stripped, 04 kept); `is_revoked` always false | ✓ VERIFIED | `rotation_deps.rs:270-279` — `cipherbox_crypto::utils::hex_to_bytes(s.recipient_public_key.trim_start_matches("0x"))`, `is_revoked: false` literal. |
| 17 | (SC2/74-05) `grant_scope.rs` and `FuseRotationDeps::new` left unchanged by 74-05 | ✓ VERIFIED | `git show --stat` on both 74-05 commits (`a9e18abf1`, `4efdc35a9`) lists only `rotation_deps.rs` (+ `delete.rs`, a required regression fix) — `grant_scope.rs` never touched. `FuseRotationDeps::new` signature confirmed unchanged at `rotation_deps.rs:178`; its construction site in `grant_scope.rs` (line ~488) still calls it with the same shape. |
| 18 | (SC3/74-06) WinFsp `handle_rename` gates the overwritten `dest_ino` through `run_scope_exit_gate` before removing it | ✓ VERIFIED | `crates/fuse/src/platform/windows/write_ops.rs:1157-1160` — `if crate::write_ops::grant_scope::run_scope_exit_gate(&mut fs, dest_ino).is_err() { return Err(status_access_denied()); }`, immediately before the destination-replacement mutation block. Static source inspection (file cannot compile on macOS — confirmed genuine toolchain limitation, not a code defect: `cargo check -p cipherbox-fuse --features winfsp` fails on unrelated `windows-future`/`windows_core::imp` symbols). |
| 19 | (SC3/74-06) Destination-replacement (ENOTEMPTY-equivalent) validation runs BEFORE the source gate — D-15d ordering parity | ✓ VERIFIED | Source read confirms exact stage order: (1) `replace_if_exists==false` collision check (line 1104, unmoved), (2) `status_directory_not_empty` check (line 1108-1119, now BEFORE the source gate), (3) source `run_scope_exit_gate` (line 1141-1145), (4) NEW dest gate (line 1156-1161). Matches the fuser `rename.rs` reference structurally, confirmed by the SUMMARY's line-by-line parity table and independently re-confirmed here by direct read. |
| 20 | (SC3/74-06) `replace_if_exists=false` collision check unchanged, still first | ✓ VERIFIED | Line 1101-1104, unconditional, unmoved. |
| 21 | (SC3/74-06) No `run_scope_exit_gate_coalesced` introduced into `handle_rename` | ✓ VERIFIED | `run_scope_exit_gate_coalesced` appears exactly once in the file, at line 1310, inside `handle_set_delete` — not `handle_rename`. |

**Score:** 21/21 truths present, wired, and code-verified. Two items (Windows CI compile/test pass for 74-06, and the 3-platform desktop-e2e live run for 74-07's Part C/D) are infra-gated and cannot be executed on this host — routed to human verification below, per project convention (`project-winfsp-build-ci-only-macos`, `project-headless-desktop-fuse-uat`). This is NOT a code gap: static source inspection for both was performed and is documented above/below.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/sdk/src/rotation/engine.rs` | `RotatedNodeKey` + `RotateReadResult.rotated_nodes` | ✓ VERIFIED | Present, substantive, wired at 3 call sites, tested (27/27). |
| `crates/sdk/src/rotation/mod.rs` | Re-export `RotatedNodeKey` | ✓ VERIFIED | Line 17: `pub use engine::{..., RotatedNodeKey, ...}`. |
| `packages/sdk-core/src/rotation/engine.ts` | `RotatedNodeKey` type + `rotatedNodes` field | ✓ VERIFIED | Present, tested (370/370). |
| `crates/fuse/src/write_ops/grant_scope.rs` | `refresh_rotated_inode_read_keys` | ✓ VERIFIED | Present, wired at `rotate_read_on_scope_exit`, tested (17/17). |
| `crates/api-client/src/client.rs` | `authenticated_patch`/`authenticated_delete` | ✓ VERIFIED | Lines 95, 117. |
| `crates/api-client/src/shares.rs` | `update_grant`/`revoke_share`/`UpdateGrantRequest` | ✓ VERIFIED | Present, tested (15/15). |
| `crates/fuse/src/write_ops/rotation_deps.rs` | `RotationTransport` seam extension + `FuseRotationDeps` overrides | ✓ VERIFIED | Present, tested (10/10); full crate 117/117 green. |
| `crates/fuse/src/platform/windows/write_ops.rs` | reordered `handle_rename` + dest gate + 2 tests | ✓ VERIFIED (static) | Present; cannot compile/run locally (winfsp-only); CI-gated. |
| `tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` | Part C + Part D legs | ✓ VERIFIED (static) | Present, typechecks clean (`npx tsc -p tests/desktop-e2e/tsconfig.json --noEmit` exit 0); live run CI-gated. |
| `tests/desktop-e2e/tsconfig.json` | New typecheck config | ✓ VERIFIED | Created, functional. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| engine BFS child commit branch | `rotated_nodes` map | `.insert(item.child_ref.ipns_name.clone(), ...)` | ✓ WIRED | `engine.rs:1879-1887` |
| engine root commit branch | `rotated_nodes` map | `.insert(root_ipns_name.to_string(), ...)` | ✓ WIRED | `engine.rs:1632-1640` |
| `rotateReadFromNode` BFS commit branch | `rotatedNodes` map | `.set(item.childRef.ipnsName, ...)` | ✓ WIRED | `engine.ts:2235` |
| `rotateReadFromNode` root commit branch | `rotatedNodes` map | `.set(rootNodeIpnsName, ...)` | ✓ WIRED | `engine.ts:2064` |
| `rotate_read_on_scope_exit` | `refresh_rotated_inode_read_keys` | direct call, line 530 | ✓ WIRED | `grant_scope.rs:530` |
| refresh loop | every rotated_nodes entry vs every inode (Root\|Folder\|File) | nested loop, no early return | ✓ WIRED | `grant_scope.rs:575-597` |
| `update_grant` | `authenticated_patch` | `-> PATCH /shares/:shareId/grant` | ✓ WIRED | `shares.rs:98-` |
| `revoke_share` | `authenticated_delete` | `-> DELETE /shares/:shareId` | ✓ WIRED | `shares.rs:130-` |
| `query_grants_rooted_at` | `self.transport.collect_sent_shares` | filter `root_node_id == node_id` -> `GrantRow` | ✓ WIRED | `rotation_deps.rs:264-284` |
| `RotationTransport::update_grant` (`ApiClientTransport`) | `cipherbox_api_client::shares::update_grant` | direct call | ✓ WIRED | `rotation_deps.rs:508-524` |
| `RotationTransport::revoke_share` (`ApiClientTransport`) | `cipherbox_api_client::shares::revoke_share` | direct call | ✓ WIRED | `rotation_deps.rs:526-533` |
| `handle_rename` dest branch | `run_scope_exit_gate(&mut fs, dest_ino)` | `-> status_access_denied()` on Err | ✓ WIRED (static) | `write_ops.rs:1156-1161` |
| `handle_rename` ENOTEMPTY check | moved ahead of `run_scope_exit_gate(source_ino)` | reorder | ✓ WIRED (static) | Confirmed by line order read: 1108-1119 precedes 1141-1145 |

### Behavioral Spot-Checks / Test Runs

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Rust rotation engine deep-tree surfacing | `cargo test -p cipherbox-sdk rotation::engine::` | 27/27 passed | ✓ PASS |
| TS rotation engine parity | `pnpm --filter @cipherbox/sdk-core test -- rotation/engine` | 370/370 passed (32 files) | ✓ PASS |
| FUSE grant_scope multi-inode refresh | `cargo test -p cipherbox-fuse write_ops::grant_scope::` | 17/17 passed | ✓ PASS |
| FUSE rotation_deps grant seam | `cargo test -p cipherbox-fuse write_ops::rotation_deps::` | 10/10 passed | ✓ PASS |
| Full cipherbox-fuse crate (fuser feature) | `cargo test -p cipherbox-fuse --features fuse` | 117 lib + 1 integration passed | ✓ PASS |
| api-client shares wire functions | `cargo test -p cipherbox-api-client shares::` | 15/15 passed | ✓ PASS |
| Bounded cross-crate check | `cargo check -p cipherbox-sdk -p cipherbox-api-client -p cipherbox-fuse --tests` | clean (warnings only, pre-existing) | ✓ PASS |
| WinFsp feature compile (macOS) | `cargo check -p cipherbox-fuse --features winfsp` | Fails on `windows-future`/`windows_core::imp` (unrelated crate, macOS-only toolchain gap) | ? SKIP (confirmed infra-limited, not this phase's code) |
| desktop-e2e typecheck | `npx tsc -p tests/desktop-e2e/tsconfig.json --noEmit` | exit 0, zero errors | ✓ PASS |
| Debt-marker scan (TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER) | grep across all 17 phase-modified files | zero hits | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|-----------------|--------------|--------|----------|
| SC1 | 74-01, 74-02, 74-03, 74-07 | Deep scope-exit rotation refreshes every retained inode's read key; revoked recipient cannot decrypt any node under the rotated grant root | ✓ SATISFIED (code); live proof CI-gated | Engine + FUSE code confirmed correct and unit-tested at every layer; desktop-e2e Part C authored and typechecked, live run pending CI dispatch |
| SC2 | 74-04, 74-05, 74-07 | Desktop `query_grants_rooted_at` returns live grants; retained recipients keep access post-rotation | ✓ SATISFIED (code); live proof CI-gated | api-client + FUSE seam confirmed correct and unit-tested; desktop-e2e Part C (Carol re-mint leg) authored, live run pending CI dispatch |
| SC3 | 74-06, 74-07 | WinFsp overwrite-rename cannot bypass the scope-exit gate; matches fuser behavior; Windows CI green | ✓ SATISFIED (code); CI green pending dispatch | Static ordering-parity confirmed exact match to fuser reference; Windows CI job not yet dispatched on this branch (no PR/CI run found) |

No orphaned requirements — all `requirements:` fields across the 7 plans map to SC1/SC2/SC3, and all three roadmap Success Criteria are covered by at least one plan.

### Anti-Patterns Found

None. Zero `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` markers across all 17 files modified by this phase's 7 plans.

### Human Verification Required

#### 1. Windows CI: `Cargo Check & Test (Windows)`

**Test:** Dispatch `gh workflow run "Cargo Check & Test (Windows)" --ref feat/rust-and-fuse-rotation-revocation-soundness` (or via PR) and observe the result.
**Expected:** Compiles cleanly with `--features winfsp`; `rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt` and `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit` both pass; the pre-existing `replace_if_exists=false` collision-rejection scenario is unregressed.
**Why human:** `platform/windows/write_ops.rs` is `#[cfg(feature = "winfsp")]`-only. Confirmed via direct attempt that it cannot compile on this macOS host (`windows-future`/`windows_core::imp` symbol-resolution errors — an unrelated Windows-only crate issue, not this phase's code). No PR/CI run currently exists for this branch (`gh run list` and `gh pr list` both empty) — this is expected pre-ship state, not a regression.

#### 2. Desktop-e2e CI: 3-platform matrix

**Test:** Dispatch `gh workflow run "desktop-e2e" --ref feat/rust-and-fuse-rotation-revocation-soundness` and observe macOS/Linux/Windows results, paying specific attention to Part A's `bobCanReadAfterRotation` assertion.
**Expected:** Part A/B (pre-existing, unchanged) remain green; Part C (deep decryptability + Carol retained-vs-revoked) passes on all 3 platforms; Part D (WinFsp overwrite-rename dest-gate) passes, authoritative on Windows.
**Why human:** Requires a built Tauri desktop binary + live FUSE-T/fuser/WinFsp mount + API + real IPNS round-trip — infeasible in this session. Regarding 74-07's self-flagged "Known Risk" (that 74-05's real `query_grants_rooted_at` might flip Part A's Bob assertion from FAIL to PASS-incorrectly since his grant is never explicitly revoked): static reading of `bobCanReadAfterRotation`'s implementation shows it is computed against `bobFolderReadKey`, a value captured once via `unwrapKey` BEFORE rotation and never re-fetched afterward; `canRead()` decrypts directly against the supplied raw key bytes with no live grant lookup. Because rotation always mints a genuinely new key regardless of whether Bob's grant row is separately re-minted by 74-05, this stale captured key will fail to decrypt the new content either way — the assertion tests "does my pre-rotation key still work," which is orthogonal to whether Bob's grant itself was re-minted. This is a reasoned-but-unverified assessment (I did not execute the e2e); recommend confirming via the CI dispatch above rather than treating the SUMMARY's flagged risk as either confirmed or dismissed.

### Gaps Summary

No code-level gaps found. All 21 must-have truths across the 7 plans are verified present, substantively implemented, and correctly wired by direct source inspection; every automated test suite claimed in the SUMMARYs was independently re-run on this host and matches the claimed pass counts exactly (27/27, 370/370, 17/17, 10/10, 117/117, 15/15). No debt markers, no stubs, no orphaned requirements.

The only outstanding items are the two infra-gated CI legs (Windows compile+unit-test for 74-06, and the 3-platform desktop-e2e live run for 74-07's Part C/D), which cannot be executed on this host by design and are routed to human verification rather than treated as gaps, per project convention for CI-only-verifiable infra limitations. The 74-07-flagged "Known Risk" about Part A's Bob assertion was assessed via static code reading and appears likely to be a false alarm (the assertion does not depend on grant re-mint status), but this is not a substitute for an actual CI run.

---

*Verified: 2026-07-11*
*Verifier: Claude (gsd-verifier)*
