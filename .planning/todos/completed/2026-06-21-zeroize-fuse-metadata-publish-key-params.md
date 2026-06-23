---
created: 2026-06-21
title: Zeroize key params in fuse metadata/bin publish spawn helpers
area: security
files:
  - crates/fuse/src/metadata.rs
  - crates/fuse/src/events.rs
---

> **Resolved by PR #543** (merged 2026-06-22). Verified already-fixed in the 2026-06-23 pending-todo audit (independent adversarial re-check confirmed). Archived from pending.

## Context

CodeRabbit flagged `spawn_metadata_publish` (and siblings) in `crates/fuse/src/metadata.rs:85-86` taking `folder_key: Vec<u8>` and `ipns_private_key: Vec<u8>` as plain `Vec<u8>` rather than `zeroize::Zeroizing<Vec<u8>>`, so the key material is not cleared on drop. `events.rs` already wraps `folder_key` in `Zeroizing`, so the pattern is inconsistent.

Deferred from Phase 55 (HARD-06, pure refactor) because the function signatures are **byte-identical to `main`** — the refactor only moved them verbatim from `lib.rs`. Changing the param types is a public-signature + behavior change (touches call sites), out of scope for a no-behavior-change refactor.

## Why deferred, not done

Phase 55's contract is "split/dedup without public-API or behavior changes." Adding `Zeroizing` changes the parameter types and ripples to call sites — a legitimate hardening, but a behavioral change that belongs in a security-hardening pass, not the refactor.

## Caution for the implementer

Heed the existing zeroization rule in this codebase: a callee that receives a **caller-owned or reused buffer must NOT zero it** — only the terminal owner zeroes (see the prior `createAndPublishIpnsRecord` regression that broke 48/89 SDK E2E by zeroing a reused publicKey buffer). Wrapping a param in `Zeroizing<Vec<u8>>` transfers ownership to the callee, which then zeroes on drop — only safe if the caller actually transfers ownership and does not reuse the buffer afterward. Audit each call site before changing the type.

## Scope

- **Verified 2026-06-21 — scope is now ONE helper:** only `spawn_metadata_publish`
  (`crates/fuse/src/metadata.rs:85-86`) still takes plain `Vec<u8>` key params. `spawn_bin_entry_publish`
  and `spawn_file_meta_reencrypt` ALREADY take `Zeroizing<Vec<u8>>`, and `events.rs` `spawn_metadata_refresh`
  already wraps `folder_key` in `Zeroizing`. So the real remaining change is just `spawn_metadata_publish`.
- Reconcile with the `Zeroizing` usage already in `events.rs`.
