---
created: 2026-06-26T00:00:00.000Z
title: Desktop FUSE deletes bypass share revocation (and likely CID-capture)
area: fuse
severity: high
source: Follow-up to PR #563 (web/SDK share-revocation-on-delete); user-flagged 2026-06-26 — desktop deletes leave shares active
files:
  - crates/fuse/src/write_ops/implementation/delete.rs
  - crates/fuse/src/metadata.rs
  - packages/sdk/src/bin/index.ts
  - packages/sdk/src/share/index.ts
  - apps/api/src/shares/shares.controller.ts
---

## Status: SUPERSEDED — folded into the read key-chaining design (to be resolved on implementation)

This per-path revocation gap is structurally eliminated by the read key-chaining design rather than
patched as a standalone bug:

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §3.5 / §4 / §3.8 — FUSE gains a
  grant-root concept and every scope-exit mutation (a desktop FUSE delete included) calls
  `rotateReadFromNode`, which rotates the departing subtree's `readKey`/`generation` AND revokes its
  grant rows uniformly; "one rule, four call sites" (§3.8) removes the Rust-only delete path that
  bypassed the SDK revocation wiring.
- `.planning/design/2026-06-26-sharing-read-keychaining-AMENDMENTS.md` — decision 2 (delete/move
  rotate on scope exit), the §3.5/§4 FUSE grant-root amendment, and the Bin amendment (shared delete
  rotates + revokes, composing PR #563).

The narrow CID-capture concern noted below is also covered (content self-seal + fresh `fileKey` on
rotation — ADR 0002 / CRIT-1). Retired from the backlog: it will be closed by the design's
implementation cycle, tracked there, not as a standalone bug.

## Problem

PR #563 added fail-closed share revocation when an item is soft-deleted to the
recycle bin — but ONLY in the SDK/web path: `CipherBoxClient.addToBin`
(`packages/sdk/src/client.ts`) injects `revokeSharesForItemsFn` into
`binOps.addToBin` (`packages/sdk/src/bin/index.ts`), which walks the deleted
subtree and calls `POST /shares/revoke-for-items` before the destructive folder
mutation.

Desktop (Tauri + FUSE) deletes go through a **parallel Rust-only path that never
touches that wiring**:

- `crates/fuse/src/write_ops/implementation/delete.rs:58` `handle_unlink` (file)
- `crates/fuse/src/write_ops/implementation/delete.rs:208` `handle_rmdir` (folder)
- both call `publish_bin_entry_on_delete` → `spawn_bin_entry_publish`
  (`crates/fuse/src/metadata.rs:424`)

That path publishes a `BinEntry` to the bin IPNS record but makes **zero API
calls beyond IPFS/IPNS** — no auth, no `POST /shares/revoke-for-items`. The FUSE
crate has no reference to `revokeSharesForItems` / `shares/revoke`.

**Result:** any file/folder deleted from the desktop mount leaves its `Share` +
`ShareInvite` rows active. Sharees retain valid read access to deleted content —
the exact data-exposure bug #563 closes for the web, still open on desktop.

### Related sub-concern to verify (pin leak parity)

The #14 / #563 pin-leak fix (`unpinEntryCids`) only unpins CIDs that the
`BinEntry` actually carries (`contentCid` / `versionCids` / `descendantCids`).
Confirm whether the FUSE-built `BinEntry` in `spawn_bin_entry_publish` populates
those fields. If it does NOT, then content soft-deleted from desktop still leaks
pins on empty-bin/permanent-delete even after #563 — a second desktop parity gap
to fix in the same pass.

## Solution

Hook revocation into the Rust FUSE delete path, fail-closed, mirroring the SDK.

1. **No subtree walk needed (simpler than SDK).** FUSE deletes bottom-up —
   `rmdir` rejects non-empty dirs (`delete.rs:237`), so the OS unlinks each child
   first. Each operation revokes exactly ONE node's `ipnsName`:
   - `handle_unlink` → revoke the file's `fileMetaIpnsName`.
   - `handle_rmdir` → revoke the (now-empty) folder's own `ipnsName`.
2. **Infra already exists.** `CipherBoxFS.api` is an authenticated `ApiClient`
   (already used by `spawn_bin_entry_publish`). Add a `POST /shares/revoke-for-items`
   call with the node's `ipnsName`. `folderKey` + `userPrivateKey` are in
   `CipherBoxFS` scope if any enumeration is needed.
3. **Failure policy — design decision to lock.** The SDK aborts the delete if
   revoke fails (it can, since it owns the publish). FUSE `unlink`/`rmdir` is a
   filesystem op that is awkward to abort cleanly. Decide between: (a) block the
   FUSE op until revoke succeeds (true fail-closed, but stalls the single-threaded
   FUSE loop — must be careful), or (b) best-effort revoke with retries spawned
   like `spawn_bin_entry_publish`, accepting a small window. Prefer fail-closed if
   feasible without stalling; otherwise retried-best-effort with a logged alert.
4. **Verify + fix CID capture** in the FUSE `BinEntry` (see sub-concern) so
   empty-bin unpin works for desktop-deleted content too.
5. **Test:** add a desktop E2E (or Rust integration assertion) that a shared file
   deleted via the FUSE mount revokes its `Share` (and a folder rmdir revokes the
   folder's own share). The desktop E2E is dispatch-gated — budget a CI round-trip.

Size: ~80-120 LOC Rust + tests. Natural fit alongside the FUSE/desktop hardening
cluster, or as a standalone `fix(fuse):` once #563 merges (its `/shares/revoke-for-items`
endpoint is the dependency).
