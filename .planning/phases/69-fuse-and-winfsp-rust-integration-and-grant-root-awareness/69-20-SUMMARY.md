---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 20
subsystem: desktop-vault
tags: [node-v3, vault-creation, legacy-retirement, SC-04]
requires: [69-15, 69-16, 69-19]
provides: [empty-node-v3-root-emit, vault-folder-model-retired]
affects: [69-10]
tech-stack:
  added: []
  patterns: [core-seal-path-direct, deterministic-keys-not-minted, mount-bridge-key-derivation]
key-files:
  created: []
  modified:
    - apps/desktop/src-tauri/src/commands/vault.rs
decisions:
  - "Compose crates/core::node seal path directly (deterministic HKDF + bridge keys) instead of cipherbox_sdk::build_folder_emission (which mints random keys) so create/mount key identity agree"
  - "Bridge root read/write keys from root_folder_key (read = [..32]; write = read ^ 0xA5), byte-matching the mount bridge at fuse/mod.rs:192-205 — temporary phase-63 placeholder"
  - "Reuse the existing seq-1 create_ipns_record/marshal/publish tail verbatim; only the uploaded payload changed"
metrics:
  duration: ~10m
  completed: 2026-07-06
status: complete
---

# Phase 69 Plan 20: Vault-creation empty node/v3 root emit (P4b) Summary

Migrated `initialize_vault` (`apps/desktop/src-tauri/src/commands/vault.rs`) off the legacy
`FolderMetadata` model onto node/v3: new users now get an empty `Node::Root` (generation 0,
empty children, both bodies sealed) published at IPNS sequence 1, using root read/write keys
that byte-match the desktop mount bridge — retiring the second and last consumer that blocked
the 69-10 legacy-folder-type delete.

## What was built

- **`derive_root_node_keys(root_folder_key) -> (Zeroizing<[u8;32]>, Zeroizing<[u8;32]>)`** — a
  pure helper reproducing the mount bridge (`fuse/mod.rs:192-205`) EXACTLY: `read_key` = first
  32 bytes of `root_folder_key` (via the same `.min(32)` copy); `write_key` = `read_key` with
  every byte XOR `0xA5`. Both derivations documented as a temporary phase-63 placeholder.
- **`build_empty_root_published_node(read_key, write_key, ipns_seed) -> Vec<u8>`** — a pure,
  no-IO helper that builds `Node::Root { generation: 0, children: [] }` +
  `NodeWriteBody { ipns_private_key: <root ipns seed>, write_children: [] }`, seals via
  `cipherbox_core::node::seal::seal_published_node(.., Some(&write_body))`, then
  `encode_published_node` → envelope bytes. Mirrors `build_folder_emission`'s seal path but
  with DETERMINISTIC keys, not minted ones.
- **`initialize_vault` wiring** — replaced the `FolderMetadata{version:"v2",children:[]}` build,
  `encrypt_folder_metadata` seal, and `{iv,data}` JSON envelope with `derive_root_node_keys` +
  `build_empty_root_published_node`. Uploads the `encode_published_node` bytes and reuses the
  EXISTING seq-1 publish tail (`create_ipns_record(.., 1, ..)` → `marshal_ipns_record` →
  `IpnsPublishRequest{ expected_sequence_number: None }` → `publish_ipns` with Success/Conflict).
- **KAT-consistent unit test** (`root_emit_tests::build_empty_root_published_node_round_trips`) —
  asserts the bridge byte-match, decodes the envelope (schema `node/v3`, kind `root`, generation
  0, `write_sealed` present), unseals the read-body under `root_read_key` → empty-children Root,
  unseals the write-body under `root_write_key` → empty `write_children` + the exact ipns seed,
  and asserts the read key CANNOT open the write-body seal (AAD/key separation).

## Keys used (mount-consistent bridge — confirmed)

| Key | Source | Notes |
|-----|--------|-------|
| root IPNS keypair | `derive_vault_ipns_keypair` (HKDF) | UNCHANGED — identical at create and mount |
| `root_read_key` | `root_folder_key[..32]` | byte-matches `fuse/mod.rs:192-198` |
| `root_write_key` | `root_read_key ^ 0xA5` | byte-matches `fuse/mod.rs:199-205` |

The v2 vault-KEY-blob publish (`serialize_vault_blob_v2` + `ecies::wrap_key`) and the
`/vault/init` registration tail are UNCHANGED — ECIES retained for the vault-root wrap only
(NODE-06 / CLAUDE.md #4).

## Green boundary (verified in this worktree)

- `cargo check --workspace` — GREEN (only pre-existing third-party `fuser` dead-struct warnings).
- `cargo test -p cipherbox-desktop --features fuse root_emit` — 1 passed (the KAT round-trip).
- `cargo test -p cipherbox-core` — 87+ passed, 0 failed.
- `cargo test -p cipherbox-fuse` — 97+ passed, 0 failed.
- `grep 'FolderMetadata\|encrypt_folder_metadata\|cipherbox_core::folder' vault.rs` — EMPTY.
- `grep 'build_folder_emission\|create_folder_node' vault.rs` — only in doc comments (no calls).
- No new dependency in `apps/desktop/src-tauri/Cargo.toml`.

## Residual FolderMetadata use in vault.rs

None. The only remaining `folder`-adjacent tokens are the retained v2 vault-key-blob functions
(`serialize_vault_blob_v2`/`deserialize_vault_blob_v2`, ECIES) and `build_folder_emission`
mentioned in doc comments — none reference `cipherbox_core::folder::FolderMetadata`.

## Deviations from Plan

None — plan executed as written. rustfmt (`--edition 2021`, changed file only) reflowed a few
pre-existing lines in `load_vault_settings`; that reformat is in-scope per the plan's fmt rule.

## Known Stubs / Residual E2E Risk (not overclaimed)

- **Placeholder bridge-key coupling (phase-63).** The root read/write keys are bridged from
  `root_folder_key` because the real node/v3 root keys (minted server-side at registration,
  recovered at login) are not yet wired into the desktop runtime (v2.0 client stubbed). A real
  node/v3 vault's persisted keys will NOT match these placeholder keys. Create and mount agree
  ONLY because both use the same bridge — this is compile/unit/CI-correct but not runtime-final.
- **Unverified live create→mount round-trip.** Full new-user vault creation needs the desktop
  stack + real key recovery (phase-63, D-06 desktop-e2e deferred/accepted). The reachable gate
  here is the pure seal/round-trip KAT + workspace-green, which pass.

## Threat mitigations applied

- T-69-20-01 (create/mount key divergence): `derive_root_node_keys` byte-matches the mount
  bridge; the unit test seals+unseals under those keys.
- T-69-20-02 (first publish seq != 1): reused seq-1 tail (`create_ipns_record(.., 1, ..)`).
- T-69-20-03 (ECIES weakening): v2 key-blob path left untouched; grep confirms intact.
- T-69-20-04 (minted keys): core seal path used directly; no `build_folder_emission`/`create_folder_node` calls.

## Commits

- `1f2329f50` — feat(69-20): pure empty-root node/v3 emit helper + KAT unit test
- `dbb5d6f0f` — feat(69-20): vault-creation emits empty node/v3 root node

## Self-Check: PASSED

- `apps/desktop/src-tauri/src/commands/vault.rs` — FOUND (modified)
- Commit `1f2329f50` — FOUND
- Commit `dbb5d6f0f` — FOUND
