---
created: 2026-07-07T00:00:00.000Z
title: Deferred FUSE publish/concurrency hardening from Phase 69 ship review
area: desktop-fuse
severity: low
source: Phase 69 ship review (CodeRabbit + adversarial verification); verified against live code 2026-07-07
files:
  - crates/fuse/src/metadata.rs
  - crates/fuse/src/fs.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/journal_helpers.rs
  - crates/fuse/src/content_ops.rs
---

## Deferred items (verified genuine, but risky/large or CI-gated — not fixed in the ship PR)

1. **`spawn_metadata_publish` duplicates `publish_with_cas_retry` (metadata.rs).** Genuine
   duplication, but the retry budgets differ and are NOT equivalent: the shared helper does a
   single retry (~2 attempts), while `spawn_metadata_publish` runs a 5-attempt loop. Delegating
   naively regresses resilience 5→2. Fix = generalize the helper to accept an attempt count, then
   delegate — a behavioral change to a publish path that is only sdk-e2e/desktop-e2e gated, so it
   needs E2E coverage. Deferred to a deliberate consolidation PR.

2. **FilePointer resolve global concurrency cap (fs.rs ~457-511).** `MAX_CONCURRENT_FP_RESOLVES`
   is applied per refresh cycle, not globally, so total in-flight can overshoot the cap when
   `resolving_file_pointers` already holds work from prior cycles; a transient duplicate can also
   be enqueued across `pending_fp_resolves` and the fresh `unresolved` pass. Verified NOT a
   correctness defect — the `resolving_file_pointers` + `scheduled_this_cycle` guards prevent any
   double-spawn/double-resolve and stale dups are popped-and-dropped next cycle. A correct global
   cap touches cross-cycle concurrency accounting; deferred rather than patched.

3. **Windows write-plane keying (platform/windows/write_ops.rs ~657).** The Windows write path
   derives the D-07 write child id from `uuid_from_ino(ino)`, correct only for newly-minted local
   nodes; materialized/replayed nodes must use the persisted `InodeData.node_id` (the exact fix
   already applied to the Unix path in commit c4d30e598 for D-07). `crates/fuse/src/platform/windows/*`
   does not compile under local mac cargo (macFUSE-only linking), so this belongs to plan **69-14**
   (WinFsp platform layer, `autonomous:false`, CI-gated). Fix + verify via the `cargo-windows` +
   Desktop E2E CI gates.

4. **Lower-value defense-in-depth zeroization (journal_helpers.rs, content_ops.rs, fs.rs, mkdir.rs,
   prepopulate.rs).** A coherent crypto-hygiene pass, deferred as a unit to keep the ship PR's diff
   focused on the verified correctness/security fixes. All verified safe (locally-owned copies, no
   caller-borrowed-buffer zeroization — the 48/89 trap does not apply):
   - `journal_helpers.rs parent_node_keys` returns a dead `ipns_private_key.to_vec()` clone that both
     callers bind to `_parent_ipns_key` and discard — drop it (3-tuple return).
   - Promote the parent IPNS signing seed to `Zeroizing<Vec<u8>>` for parity with the child/file
     seeds: `MkdirJournalResult.parent_ipns_private_key` (journal_helpers.rs) and the 2nd return of
     `build_folder_metadata` (fs.rs), rippling to `fs.rs` publish sites and `mkdir.rs` (the
     `parent_ipns_private_key.try_into()` becomes a `to_key32`-style copy). Also wrap the un-zeroed
     `[u8;32]` arrays at `mkdir.rs:168,212` and `prepopulate.rs:117,455` bare-key copies.
   - Scrub transient plaintext copies of `NodeContent.file_key` / `NodeWriteBody.ipns_private_key`
     (and the unseal-then-reseal path in content_ops.rs) with `cipherbox_crypto::utils::clear_bytes`
     after use, incl. error paths. Low value — the same secrets are already retained as `Zeroizing`
     on the persisted/returned path; these are duplicate transient copies.
   - `apps/desktop/.../fuse/mod.rs:120-133` narrows state keys into `[u8;32]` via
     `copy_from_slice(&src[..min(32)])`, silently zero-padding a short key; use `try_into()` with an
     error for strictness (harmless today — ECIES-unwrapped root keys are always 32 bytes).

   (The higher-value zeroization/leak fixes — the `InodeKind` redacting `Debug`, the replay child-key
   `Zeroizing` intermediates, and the `operations.rs` dropped read-key copy — WERE applied in the ship PR.)

## Acceptance

Metadata publish retry logic lives in one helper with an explicit attempt budget (no 5→2
regression); FP-resolve concurrency respects a true global cap with no cross-cycle duplicate
enqueue; the Windows write plane keys D-07 refs by stored `node_id` (verified green in
`cargo-windows` + Desktop E2E); transient plaintext key copies are scrubbed after use.
