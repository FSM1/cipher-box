---
phase: 76-fuse-durability-and-tee-write-path-hardening
plan: 01
subsystem: desktop-vault-init
tags: [rust, desktop, vault, ipns, recovery, fail-closed, tdd]
requires:
  - cipherbox_api_client::ipns::resolve_ipns
  - cipherbox_api_client::ipns::resolve_ipns_verified
  - cipherbox_core::vault_blob::deserialize_vault_blob_v3
  - cipherbox_crypto::ecies::unwrap_key
  - cipherbox_core::node::seal::unseal_node
provides:
  - preflight_ipns_absent (fail-closed IPNS existence check)
  - route_vault_init (vault-init decision seam)
  - decrypt-and-resume recovery branch in initialize_vault
affects:
  - apps/desktop/src-tauri/src/commands/vault.rs
tech-stack:
  added: []
  patterns:
    - Fail-closed preflight-before-any-write
    - Decrypt-and-resume recovery (never re-mint keys)
    - Pure decision seam for unit testability
key-files:
  created: []
  modified:
    - apps/desktop/src-tauri/src/commands/vault.rs
decisions:
  - "Recovery uses resolve_ipns_verified (D-09 chokepoint) for the key blob, mirroring fetch_and_decrypt_vault; the existence-only preflight uses the raw resolve_ipns"
  - "route_vault_init consumes the raw preflight Results so a transient Err aborts (via ?) before any route is chosen — abort-before-publish is enforced structurally"
  - "Coherency gate fetches the just-published root back and unseals its read body under the recovered read key before POST /vault/init"
metrics:
  duration: 20min
  completed: 2026-07-11
status: complete
---

# Phase 76 Plan 01: Vault Init Fail-Closed Preflight and Decrypt-and-Resume Recovery Summary

Hardened desktop `initialize_vault` with a fail-closed preflight of both IPNS names and a decrypt-and-resume recovery branch that ECIES-unwraps the already-published key blob to recover the ORIGINAL root keys instead of re-minting, closing the partial-publish permanent-stuck vault bug (SC1, todo:2026-06-26-vault-init-publish-ordering-preflight).

## What Was Built

All changes are in `apps/desktop/src-tauri/src/commands/vault.rs`.

- **Task 1 — Preflight helper + seam** (`5fb06cba0`): `classify_preflight_outcome` (pure decision seam mapping a resolve `Result` to absent/present/abort) and `preflight_ipns_absent` (resolve + classify). Fails closed: any non-404 `ApiError` returns `Err`, never `Ok(true)`. Four unit tests cover not-found, present, transient 5xx, and auth-error mapping.
- **Task 2 — Wire preflight + recovery** (`9c3696bc5`): `initialize_vault` now derives both IPNS names first, preflights BOTH before any write, and routes via `route_vault_init` (decision seam) to one of `FreshInit`, `RecoverResume`, or a fail-closed abort. `RecoverResume` recovers root keys via `recover_root_keys_from_key_blob` (ECIES-unwrap of the existing blob, NO `generate_file_key`), republishes the missing root under recovered keys, and runs `coherency_check_root_unseal` before `/vault/init`. Extracted `publish_vault_key_blob`, `publish_root_folder`, and `register_vault` helpers shared by both branches. Six route tests including transient-abort-before-publish.
- **Task 3 — Recovery + abort tests** (`a188175d9`): a decrypt-and-resume round-trip asserting recovered root read/write keys equal the first attempt's minted keys byte-for-byte and that the coherency unseal succeeds; an end-to-end classify→route abort test for a transient resolve; an unrecoverable-state abort test.

## Behavior Coverage

- Both absent (fresh user) → mint keys, publish blob, publish root, register (unchanged happy path).
- Transient (non-404) resolve on either name → abort before any publish (fail closed).
- Key-blob present + root absent → decrypt-and-resume: recover original keys, republish root, coherency-unseal, register — no re-mint.
- Publish failure after clean preflight → distinguishable `Err`; key-blob-first order means the next attempt's preflight routes to `RecoverResume`.
- Both present → abort with guidance to route through the load path.
- Root present + key-blob absent → abort as unrecoverable/unexpected.

## Threat Mitigations

- T-76-01 (fail-closed preflight): a resolve that cannot confirm absence never publishes — enforced by `classify_preflight_outcome`'s `Err` arm and `route_vault_init`'s `?` propagation before any write.
- T-76-02 (root key coherency on retry): recovery ECIES-unwraps the ORIGINAL keys; re-mint prohibited (no `generate_file_key` in the recovery branch — verified by grep); `unseal_node` coherency gate binds recovered keys to the published root.
- T-76-03 (key material disclosure): recovered keys stay in `Zeroizing` buffers; no key material in error strings or logs.

## Deviations from Plan

None — plan executed as written. The three plan tasks map 1:1 to the three commits. The plan's "test seam (closure/trait)" was realized as pure decision functions (`classify_preflight_outcome`, `route_vault_init`) that `initialize_vault` actually calls in production — cleaner than a test-only mirror while satisfying the same unit-testability goal.

## Verification

- `cargo test -p cipherbox-desktop vault` → 15 passed, 0 failed (includes preflight, route, recovery round-trip, and existing round-trip tests).
- `cargo build -p cipherbox-desktop` clean (only pre-existing vendored-fuser warnings).
- Backstop (not run here, per plan): a genuinely fresh-user desktop vault init end-to-end via `desktop-e2e.yml` — `initialize_vault` is only invoked for a new/unregistered user; a fully-registered vault routes to `fetch_and_decrypt_vault`.

## Known Stubs

None.

## Self-Check: PASSED

- FOUND: apps/desktop/src-tauri/src/commands/vault.rs
- FOUND commit 5fb06cba0 (Task 1)
- FOUND commit 9c3696bc5 (Task 2)
- FOUND commit a188175d9 (Task 3)
- Verified: no `generate_file_key` call in the RecoverResume branch (both occurrences are in FreshInit).
