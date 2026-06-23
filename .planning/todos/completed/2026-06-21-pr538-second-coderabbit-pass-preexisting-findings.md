---
created: 2026-06-21
title: Pre-existing correctness/security findings from PR 538 second CodeRabbit pass
area: fuse, web, sdk-core
files:
  - crates/fuse/src/write_ops/implementation/file_data.rs
  - crates/fuse/src/write_ops/implementation/mkdir.rs
  - apps/web/src/components/file-browser/details/DetailsPrimitives.tsx
  - apps/web/src/components/file-browser/details/VersionHistory.tsx
  - packages/sdk-core/src/folder/registration.ts
---

> **Resolved by PR #543** (merged 2026-06-22). Verified already-fixed in the 2026-06-23 pending-todo audit (independent adversarial re-check confirmed). Archived from pending.

## Context

A second CodeRabbit review of PR `#538` (phase 55 refactor) surfaced 6 more findings (3 Major,
2 Minor, 1 Major-security). Each was verified **byte-identical to `origin/main`** — phase 55 only
MOVED this code into new modules (write_ops split, DetailsDialog split, folder/index.ts split); it
did not introduce these. Deferred because phase 55's contract (HARD-06) forbids behavior changes.
Companion to `2026-06-21-fuse-ipns-robustness-findings-from-pr538-review.md` and
`2026-06-21-zeroize-fuse-metadata-publish-key-params.md` — batch into a hardening pass.

## Findings (all pre-existing; new-file line numbers as of the refactor)

### Major — FUSE write path

1. `write_ops/implementation/file_data.rs:123` (`handle_write`) — `let new_end = offset as u64 + data.len() as u64;`
   is computed with no offset validation. A negative `offset` wraps into a huge `u64`; a large offset can
   overflow. Reject `offset < 0` (EINVAL) and use `checked_add` (EFBIG on overflow) **before** `write_at`.
   Base: `origin/main:crates/fuse/src/write_ops.rs:122`.
2. `write_ops/implementation/file_data.rs:164` (`handle_create`/mknod path) — allocates a new inode and inserts
   under `parent` without checking whether `name_str` already exists, allowing duplicate dirents / name-resolution
   corruption. Add `if fs.inodes.find_child(parent, name_str).is_some() { reply.error(libc::EEXIST); return; }`
   after the `parent_exists` check. Base: `origin/main:crates/fuse/src/write_ops.rs:140-171`.
3. `write_ops/implementation/mkdir.rs:58` (`handle_mkdir`) — same missing duplicate-name guard; should return
   `EEXIST` for an existing child name before mutating the inode table. Base: `origin/main:write_ops.rs:452-477`.

### Major — sdk-core crypto (security)

4. `packages/sdk-core/src/folder/registration.ts:65` — `ipnsPrivateKeyEncrypted`/`folderKeyEncrypted` are
   computed via `wrapKey` **before** the `try` whose `catch` zeroes key material. If either `wrapKey` throws,
   `catch` never runs and the sensitive buffers are not zeroed. Move both `wrapKey` calls inside the `try`.
   Heed the codebase rule that a callee must not zero a caller-owned/reused buffer — confirm these buffers are
   owned here. Base: `origin/main:packages/sdk-core/src/folder/index.ts:123-131`.

### Minor — web (apps/web file-browser details)

5. `apps/web/src/components/file-browser/details/DetailsPrimitives.tsx:33` — `setCopied(true)` runs even when
   both clipboard paths fail (false success state). Gate it on an actual-copy flag (`navigator.clipboard.writeText`
   resolving, or `document.execCommand('copy')` returning true). Base: `origin/main:.../DetailsDialog.tsx:56`.
6. `apps/web/src/components/file-browser/details/VersionHistory.tsx:37` — version download early-returns silently
   when `vaultKeypair?.privateKey` is undefined; surface a user-visible error instead. Base:
   `origin/main:.../DetailsDialog.tsx:129`.
