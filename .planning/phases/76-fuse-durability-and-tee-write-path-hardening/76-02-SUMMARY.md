---
phase: 76-fuse-durability-and-tee-write-path-hardening
plan: 02
subsystem: desktop-fuse
tags: [fuse, ipns, publish-retry, concurrency, zeroization, hardening]
status: complete
requires:
  - node/v3 write emission (Phase 69-09) — spawn_metadata_publish / build_folder_metadata / journal_helpers
provides:
  - single attempt-budgeted publish_with_cas_retry helper (max_attempts param)
  - cross-cycle global FP-resolve concurrency cap
  - defense-in-depth zeroization of locally-owned transient key copies
affects:
  - crates/fuse
  - apps/desktop/src-tauri/src/fuse
tech-stack:
  added: []
  patterns:
    - attempt-budget-parameterized CAS retry helper (one source of publish-retry truth)
    - global concurrency budget derived from the in-flight accounting set
    - Zeroizing/clear_bytes only on locally-owned copies (never caller-owned buffers)
key-files:
  created: []
  modified:
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/content_ops.rs
    - crates/fuse/src/journal_helpers.rs
    - crates/fuse/src/write_ops/implementation/mkdir.rs
    - crates/fuse/src/platform/windows/write_ops.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
decisions:
  - "publish_with_cas_retry gains max_attempts: u32; callers pass 2 (bin/per-file) or 5 (metadata)"
  - "helper never unpins the just-published CID (same-CID re-publish would otherwise unpin live content) — latent over-unpin fixed"
  - "FP-resolve cycle budget = MAX_CONCURRENT_FP_RESOLVES.saturating_sub(resolving_file_pointers.len())"
  - "build_folder_metadata + MkdirJournalResult.parent_ipns_private_key now Zeroizing<Vec<u8>>"
  - "prepopulate.rs verified-clean — no un-zeroed transient bare-key buffer (source todo lines 117,455 stale)"
metrics:
  duration: 35min
  completed: 2026-07-11
  tasks: 3
  files: 7
---

# Phase 76 Plan 02: FUSE Publish / Concurrency / Zeroization Hardening Summary

One-liner: consolidated the two divergent CAS-publish retry loops into one `max_attempts`-parameterized helper (no 5→2 metadata regression), made the FilePointer-resolve concurrency cap truly global across refresh cycles, and scrubbed locally-owned transient plaintext key copies — all with the `cipherbox-fuse` suite green (120/120 + cross-language vectors).

## What Was Built

### Task 1 — `publish_with_cas_retry(max_attempts: u32)` (metadata.rs)

- Added `max_attempts: u32` to `publish_with_cas_retry` and rewrote the single-retry body into an attempt-budget loop (`resolve → make_record(new_seq) → publish → on-Conflict jitter + re-resolve`, up to `max_attempts`).
- `spawn_metadata_publish` deleted its inline 5-attempt loop and now delegates to the shared helper with `max_attempts: 5` (its `make_record` was adapted to the helper's `(record_b64, cid)` closure shape; the sealed envelope is still uploaded once and re-signed at fresh sequences).
- The two existing 2-attempt callers pass `2`: `spawn_bin_entry_publish`'s update path (metadata.rs) and `publish_file_node`'s per-file update path (content_ops.rs).
- Generalized the `run_publish_retry_seam` unit seam to model the attempt budget and added two locking tests: Conflict×4-then-Success **succeeds** under `max_attempts: 5` and **exhausts (Err)** under `max_attempts: 2`.

### Task 2 — Cross-cycle global FP-resolve cap (fs.rs)

- Replaced the per-call `let mut spawned = 0` seed with a derived cycle budget: `MAX_CONCURRENT_FP_RESOLVES.saturating_sub(self.resolving_file_pointers.len())`, feeding BOTH the pending-drain loop and the fresh-unresolved loop.
- The `resolving_file_pointers.contains(&fp_ino)` dedup guards are untouched; no struct field added (`resolving_file_pointers` already IS the global accounting set).
- Added a 2-consecutive-cycle test that pre-fills the cap in cycle 1 and asserts cycle 2 spawns zero more, so the global in-flight count never overshoots `MAX_CONCURRENT_FP_RESOLVES`.

### Task 3 — Defense-in-depth zeroization

- `journal_helpers.rs`: `parent_node_keys` now returns a 3-tuple — the dead `ipns_private_key.to_vec()` clone (bound to `_parent_ipns_key` by both callers) is gone. `MkdirJournalResult.parent_ipns_private_key` is `Zeroizing<Vec<u8>>`.
- `fs.rs`: `build_folder_metadata` returns the parent signing seed as `Zeroizing<Vec<u8>>`; the two `spawn_metadata_publish` call sites drop their now-redundant `Zeroizing::new(...)` re-wrap.
- `mkdir.rs` (mac) + `platform/windows/write_ops.rs`: the narrowed child/parent `[u8;32]` signing seeds are `Zeroizing<[u8;32]>` via `try_from(as_slice())` (no transient plaintext Vec).
- `content_ops.rs`: the unseal-recovered `NodeContent.file_key` is scrubbed with `clear_bytes` right after the working key is derived (length-error path included); the locally-owned `file_key`/`ipns_private_key` `.to_vec()` copies in `publish_file_node` are scrubbed after `seal_published_node` returns, covering success AND all subsequent error paths.
- `apps/desktop/.../fuse/mod.rs`: root read/write key narrowing switched from zero-padding `copy_from_slice(&src[..min(32)])` to strict `try_from` (fail-closed — root keys are always 32 bytes).

## Per-target local-ownership confirmation (zeroization)

| Target | File | Ownership | Action |
|--------|------|-----------|--------|
| parent ipns seed clone | journal_helpers.rs `parent_node_keys` | dead local clone (unused) | removed (3-tuple) |
| parent signing seed return | fs.rs `build_folder_metadata` | locally-owned `.to_vec()` copy | `Zeroizing<Vec<u8>>` |
| MkdirJournalResult.parent_ipns_private_key | journal_helpers.rs | locally-owned (from above) | `Zeroizing<Vec<u8>>` |
| child/parent `[u8;32]` narrow | mkdir.rs, windows/write_ops.rs | locally-owned copy | `Zeroizing<[u8;32]>` |
| unsealed `content.file_key` | content_ops.rs `fetch_and_decrypt_content_async` | locally-owned (unseal output) | `clear_bytes` incl. error path |
| `node_content.file_key` / `write_body.ipns_private_key` | content_ops.rs `publish_file_node` | locally-owned `.to_vec()` copies | `clear_bytes` after seal (all paths) |
| root read/write key | desktop fuse/mod.rs | locally-owned narrow | strict `try_from` |
| bare `[u8;32]` folder key copies | prepopulate.rs | copy-out-of-inode (accepted pattern) | verified-clean, NO change |

`read_key`/`write_key` borrows into `seal_published_node`/`build_child_refs` are caller-owned and were deliberately left untouched (D-09 terminal-owner discipline) — the established "broke 48/89 E2E" trap does not apply.

## prepopulate.rs verify-only outcome

Re-grepped the current 156-line file. Its only `[u8;32]` key handling is direct copy-out-of-inode (`**read_key`/`**write_key` into a snapshot Vec/local for an immediate resolve call) — the same accepted pattern used in `fs.rs` (FP-resolve loop, `build_folder_metadata` child loop) which this plan does not zeroize. The source todo's cited lines (117, 455) do not exist / do not correspond to any un-zeroed transient bare-key buffer. **Marked done-as-verified-clean; no change made** (per the plan prohibition and RESEARCH Assumption A1).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Windows platform consumer of the changed `MkdirJournalResult` type**

- **Found during:** Task 3 (promoting `MkdirJournalResult.parent_ipns_private_key` to `Zeroizing<Vec<u8>>`)
- **Issue:** `crates/fuse/src/platform/windows/write_ops.rs:237` consumed the field via `parent_ipns_private_key.try_into()` — a `Zeroizing<Vec<u8>>` has no such `TryInto<[u8;32]>`, so the shared struct change would break the Windows build (`Cargo Check & Test (Windows)`).
- **Fix:** Mirrored the mac narrow — `Zeroizing::new(<[u8;32]>::try_from(parent_ipns_private_key.as_slice())?)`. This is a compile-necessity for the shared struct only; the Windows D-07 `node_id` keying fix remains out of scope (plan 76-05). Cannot self-verify on macOS (Windows module is CI-gated) — flagged for the Windows CI leg.
- **Files modified:** crates/fuse/src/platform/windows/write_ops.rs
- **Commit:** e3840cd81

**2. [Rule 1 - Bug] Helper no longer unpins the just-published CID**

- **Found during:** Task 1 (unifying the retry cleanup semantics)
- **Issue:** Both real callers re-publish the SAME uploaded content blob at a fresh sequence, so the old helper's "unpin the superseded initial CID on retry-success" path would have unpinned the very CID the successful record points at — a latent over-unpin, and a hard regression if the metadata (5-attempt) path delegated to it.
- **Fix:** The helper now skips any intermediate CID equal to the finally-published CID when unpinning on success. Observable seam-test behavior (Ok/Err, attempt count, record_publish) is byte-for-byte preserved; only best-effort fire-and-forget unpins changed. `spawn_metadata_publish`'s own post-failure `unpin(cid)` cleanup is retained.
- **Files modified:** crates/fuse/src/metadata.rs
- **Commit:** b48bcbd27

## Threat Model Mitigations Applied

- **T-76-04 (DoS, publish retry budget):** `max_attempts` preserves the 5-attempt metadata budget; the attempt-5-succeeds test guards against the silent 5→2 regression.
- **T-76-05 (DoS, FP-resolve concurrency):** cross-cycle global cap prevents unbounded in-flight resolve overshoot; 2-cycle property test locks it in.
- **T-76-06 (Info disclosure, transient key plaintext):** `clear_bytes`/`Zeroizing` on locally-owned copies incl. error paths; caller-owned buffers explicitly excluded.

## Verification

- `cargo test -p cipherbox-fuse` — 120 passed, 0 failed (+ `ipns_verify_cross_language` vector test green).
- `cargo test -p cipherbox-fuse publish_with_cas_retry` — 6 passed (incl. the new 5th-attempt and budget-2 cases).
- `cargo test -p cipherbox-fuse fp_resolve` / `drain_refresh_completions_tests` — global-cap + all existing drain tests green.
- `cargo check -p cipherbox-desktop --bins` — clean (desktop fuse/mod.rs strict-narrow change compiles).
- No new external dependency added.

## Commits

- b48bcbd27: refactor(fuse): parameterize publish_with_cas_retry with max_attempts
- a0033490a: fix(fuse): make FP-resolve concurrency cap global across refresh cycles
- e3840cd81: refactor(fuse): defense-in-depth zeroization of transient key copies

## Follow-ups / Notes

- Windows D-07 `node_id` write-plane keying (SC2 item 3) remains plan 76-05 (`autonomous:false`, CI-gated). The Windows consumer edit here is compile-only, not that fix.
- The Windows narrow change cannot be locally verified on macOS — confirm the `Cargo Check & Test (Windows)` CI leg is green before merge.

## Self-Check: PASSED

- SUMMARY file present on disk.
- All four commits (b48bcbd27, a0033490a, e3840cd81, 7aeda063f) present in git history.
