---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 23
subsystem: desktop-vault
tags: [root-key-recovery, node-v3, vault-blob-v3, ecies, hkdf, zero-knowledge]
requires: ["69-21", "69-22"]
provides:
  - desktop-vault-init-node-v3
  - desktop-vault-recovery-node-v3
affects:
  - apps/desktop/src-tauri/src/commands/vault.rs
tech-stack:
  added: []
  patterns:
    - two-independent-random-root-keys
    - ecies-wrap-both-under-user-pubkey
    - vault-blob-v3-serialize-deserialize
    - hkdf-derived-root-ipns-keypair
key-files:
  created: []
  modified:
    - apps/desktop/src-tauri/src/commands/vault.rs
decisions:
  - "Desktop vault init now mints two INDEPENDENT random 32-byte root keys (generate_file_key x2), never derived from each other — matching the web oracle so a v3 vault is cross-openable"
  - "The `^0xA5` bridge helper derive_root_node_keys is deleted; build_empty_root_published_node is retained and fed the real random keys"
  - "root_folder_key stays populated (= copy of root_read_key) transitionally so the still-bridged mount + post_auth_finalize stay green until 69-24"
  - "No auth.rs change was required (workspace green without it); mount-signature lockstep deferred to 69-24 per plan"
metrics:
  duration: ~10m
  completed: 2026-07-07
status: complete
---

# Phase 69 Plan 23: Desktop vault INIT + RECOVERY on node/v3 Summary

Migrated desktop `initialize_vault` and `fetch_and_decrypt_vault` (apps/desktop/src-tauri/src/commands/vault.rs) from 69-20's `^0xA5` bridge + v2-blob placeholder to the real node/v3 model: two independent random root keys ECIES-wrapped into a vault-blob-v3, with recovery unwrapping both back into KeyState.

## What was built

### Task 1 — init mints two random keys + v3 blob + real-key root seal (commit cdb03d796)
- Deleted the `derive_root_node_keys` helper (the `^0xA5` bridge) entirely.
- `initialize_vault` now mints `root_read_key` and `root_write_key` as **two independent** `Zeroizing<[u8;32]>` via `generate_file_key()` (two separate calls — never derived from one another).
- ECIES-wraps **both** keys under the user's secp256k1 public key (`wrap_key`, read then write, mirroring the web oracle `packages/core/src/vault/init.ts` + `packages/sdk-core/src/vault/index.ts::publishVaultKeyBlob`).
- Packs them into a **vault-blob-v3** via `serialize_vault_blob_v3(&enc_read, &enc_write)` (69-21), uploads to IPFS, and publishes to the vault-key IPNS name via the **existing** seq-1 tail (`create_ipns_record(seq=1)` + `marshal_ipns_record` + `IpnsPublishRequest{expected_sequence_number:None}` + `publish_ipns`, Conflict aborts).
- The empty root Node is sealed under **those same two real keys** via the retained `build_empty_root_published_node` helper (HKDF-derived root Ed25519 IPNS seed fed as the write-body signing key), published at seq 1 via the unchanged root-node tail.
- `/vault/init` POST body unchanged: `{ owner_public_key, root_ipns_name }` (server stays zero-knowledge).

### Task 2 — recovery unwraps both keys from v3 blob + round-trip test (commit 514c899ab)
- `fetch_and_decrypt_vault` now routes through the retained `resolve_ipns_verified` (D-09 chokepoint), fetches the blob, and calls `deserialize_vault_blob_v3(&blob_bytes)` → `(enc_read, enc_write)`.
- ECIES-unwraps each under the user private key (`unwrap_key`, returns `Zeroizing<Vec<u8>>`) → lands into `state.sdk.root_read_key` / `state.sdk.root_write_key` (69-22).
- `state.sdk.root_folder_key` is also set to a copy of `root_read_key` (transitional — mount still bridges from it until 69-24; commented as such).
- Root Ed25519 IPNS keypair stays HKDF-derived (`derive_vault_ipns_keypair`, not from the blob).
- Removed the `detect_blob_version != 2` gate + `deserialize_vault_blob_v2` + "not v2 format" error string; a v2/malformed blob is now rejected fail-closed by `deserialize_vault_blob_v3`'s Err.
- Added `init_recover_v3_round_trips` unit test (pure, no live IO): wrap two known distinct keys under a fixed secp256k1 keypair (privkey=1, pubkey=generator point G, via `hex::decode` — no new dependency) → serialize v3 → deserialize → unwrap both, asserting byte-identical recovery and mutual distinctness; then seal the empty root under the recovered keys and assert the read-body opens under `root_read_key` while the write-body does **not** (AAD/key separation). Also updated the pre-existing `build_empty_root_published_node_round_trips` test to use two explicit distinct keys instead of the deleted bridge helper.

## Green-boundary checks (verified in this worktree)

| Check | Evidence |
|-------|----------|
| `cargo check --workspace` (default fuse feature) | GREEN — `Finished dev profile` |
| `cargo test -p cipherbox-desktop --features fuse vault` | GREEN — 2 passed (both round-trip tests incl. init→recover two-key byte-identical recovery) |
| `grep '0xA5\|derive_root_node_keys' vault.rs` | EMPTY (bridge gone from creation) |
| `grep 'serialize_vault_blob_v2\|deserialize_vault_blob_v2\|is not v2 format' vault.rs` | EMPTY (v2 path gone) |
| `grep 'serialize_vault_blob_v3\|deserialize_vault_blob_v3' vault.rs` | PRESENT (5 hits) |
| `git diff base -- apps/desktop/src-tauri/Cargo.toml` | EMPTY (no new dependency) |
| Files changed since base | `apps/desktop/src-tauri/src/commands/vault.rs` only |

## How the crypto flows

- **INIT — generate + wrap + publish two random keys:** `generate_file_key()` × 2 → `Zeroizing<[u8;32]>` each → `wrap_key(&*root_read_key, public_key)` and `wrap_key(&*root_write_key, public_key)` → `serialize_vault_blob_v3(enc_read, enc_write)` → IPFS upload → publish to vault-key IPNS (seq 1). Same two keys → `build_empty_root_published_node(&root_read_key, &root_write_key, root_ipns_private_key)` → root-node publish (seq 1). Zeroizing ownership held until after both the ECIES wrap and the root seal complete.
- **RECOVERY — unwrap + derive IPNS key:** `resolve_ipns_verified` → `fetch_content` → `deserialize_vault_blob_v3` → `unwrap_key` × 2 under the user private key → `root_read_key`/`root_write_key` into KeyState (+ transitional `root_folder_key` copy). Root Ed25519 IPNS keypair re-derived via `derive_vault_ipns_keypair` (HKDF, byte-identical per `crates/crypto/tests/cross_language.rs`), stored in `root_ipns_private_key`.

## Confirmations
- Bridge + v2-init **deleted from creation**: `derive_root_node_keys` removed; `serialize_vault_blob_v2` no longer called from init.
- `build_empty_root_published_node` **retained and reused** with the real random keys (not `build_folder_emission`, which would mint its own IPNS keypair and break the HKDF root IPNS agreement).
- **No auth.rs change needed** — workspace is green with only vault.rs modified; the mount-signature lockstep is deferred to 69-24 as the plan states.

## Deviations from Plan

**1. [Task-ordering] Updated the pre-existing `build_empty_root_published_node_round_trips` test in Task 1 (not Task 2)**
- **Found during:** Task 1
- **Issue:** The existing test referenced `derive_root_node_keys` and `0xA5`; deleting the bridge helper in Task 1 would break the build and fail the `0xA5`/`derive_root_node_keys` grep on the Task 1 commit.
- **Fix:** Rewrote that test in the Task 1 commit to use two explicit distinct keys (`0x42`/`0x7E`) with the bridge assertions removed. The new `init_recover_v3_round_trips` test landed in Task 2 as planned.
- **Files modified:** apps/desktop/src-tauri/src/commands/vault.rs
- **Commit:** cdb03d796

**2. [TDD note] Task 2 RED/GREEN gate is degenerate**
- The plan marks Task 2 `tdd="true"`, but `fetch_and_decrypt_vault` is IO-bound (live API/IPFS) and cannot be unit-tested purely. The round-trip test exercises the pure codec + seal path (all lower layers from 69-21 already exist), so it passes without a separate RED phase. Committed test + impl together as a single `feat` commit. Real recovery correctness rides the desktop-e2e run (see residual risks).

## Residual E2E risks (not covered by these unit tests)
- Full new-user create → mount → recover correctness is validated only by the orchestrator's **desktop-e2e run after 69-25**. The unit/round-trip tests are necessary but NOT sufficient.
- The mount (`fuse/mod.rs`) still bridges from `root_folder_key`; real two-key mount correctness lands in **69-24** (auth.rs mount-signature lockstep). Until then, a v3 vault's write-plane at mount is still the transitional `root_folder_key` mirror, not `root_write_key`.
- Live IPNS publish/resolve, IPFS upload/fetch, and the `/vault/init` server round-trip are unexercised here (no live IO in unit tests).

## Self-Check: PASSED
- FOUND: apps/desktop/src-tauri/src/commands/vault.rs
- FOUND commit cdb03d796 (feat(69-23): vault init mints node/v3 two-key root + v3 blob)
- FOUND commit 514c899ab (feat(69-23): vault recovery unwraps node/v3 two-key root from v3 blob)
