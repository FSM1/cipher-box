---
created: 2026-06-26T00:00:00.000Z
title: Revoke shares on rename/replace-over-existing-destination (web + desktop)
area: fuse
severity: high
source: PR #568 adversarial review (revocation-completeness lens) — 2026-06-26
files:
  - crates/fuse/src/write_ops/implementation/rename.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - packages/sdk/src/bin/index.ts
  - packages/sdk/src/client.ts
  - apps/api/src/shares/shares.controller.ts
---

## Status: SUPERSEDED — folded into the read key-chaining design (to be resolved on implementation)

This per-path revocation gap is structurally eliminated by the read key-chaining design rather than
patched as a standalone bug:

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §3.6 / §3.8 — rename/replace over
  an existing destination collapses to a scope-exit rotation of the displaced destination subtree
  (`rotateReadFromNode`), which revokes its grant rows the same way delete does, unified across the
  web and both FUSE (unix + Windows) call sites.
- `.planning/design/2026-06-26-sharing-read-keychaining-AMENDMENTS.md` — decision 2 (scope-exit
  rotation) + the §3.6/§3.8 delete-rule rewrite, composing the shipped PR #563 revoke-for-items and
  preserving its ordering invariant.

Retired from the backlog: it will be closed by the design's implementation cycle, tracked there, not
as a standalone bug.

## Problem

PRs #563 (web/SDK) and #568 (desktop FUSE) added fail-closed share revocation on
**delete** — but only on the delete-to-bin path. When a file/folder is **renamed
or moved OVER an existing destination** (replace/overwrite), the destination node
is destroyed WITHOUT revoking its shares. This is the same data-exposure class as
the delete bug those PRs closed: the destination's `Share` / `ShareInvite` rows
stay active against content that has been replaced (and, on the unix file branch,
its CID is even unpinned), so sharees retain read access to vanished content.

Confirmed by the #568 completeness review as **pre-existing on every surface**:

- **Unix FUSE:** `crates/fuse/src/write_ops/implementation/rename.rs` (~163-186) —
  the File branch destroys the dest node and even spawns `unpin_content` on the
  dest CID, with no share revocation.
- **Windows FUSE:** `crates/fuse/src/platform/windows/write_ops.rs` (~1097-1124) —
  same replace-over-dest path, no revocation.
- **Web / SDK:** the #563 revocation (`revokeSharesForItemsFn`) is wired ONLY into
  `addToBin` (`packages/sdk/src/bin/index.ts:483`, `client.ts:221`), NOT into any
  overwrite/replace/move path.

So there is NO web-vs-desktop parity regression — it's an equal gap on both, and
#568 correctly scoped rename out (delete-only).

## Solution

When a rename/move overwrites an existing destination, revoke the **destination
node's** shares before/as the destination is destroyed, mirroring the delete-path
fail-closed contract (`POST /shares/revoke-for-items`, revoke-before-destructive-
mutation, abort on failure where the call site allows it):

1. **Web/SDK:** wire revocation into the replace/overwrite path (whatever the SDK
   uses when a move/upload clobbers an existing destination), reusing the existing
   `revokeSharesForItems` helper + chunking + 4xx short-circuit.
2. **Unix FUSE** (`rename.rs`): revoke the dest node's `ipnsName`
   (`file_meta_ipns_name` for a file dest) before destroying it; reuse
   `metadata::revoke_shares_blocking` (added in #568). Fail-closed via `EIO` if the
   handler return path allows it.
3. **Windows FUSE** (`write_ops.rs`): same, at the corresponding replace point.

Clarify dest-can-be-a-folder semantics: POSIX `rename` over a non-empty dir fails,
but check the app's move/replace semantics — if a folder dest is reachable, decide
whether a subtree walk is needed (delete used the bottom-up invariant; replace may
not have it).

Tests: web-e2e + desktop-e2e that a shared file replaced via move/overwrite revokes
its share, plus unit coverage. Depends on the live `/shares/revoke-for-items`
endpoint (already shipped in #563).
