---
created: 2026-06-14T12:37:25.820Z
title: Reuse publish_file_metadata and a cas-publish helper in replay
area: desktop-fuse
files:
  - crates/fuse/src/lib.rs
  - crates/fuse/src/operations.rs
  - crates/fuse/src/write_ops.rs
  - crates/fuse/src/platform/windows/write_ops.rs
---

## Problem

The replay path in `crates/fuse/src/lib.rs` re-implements logic that already exists:

- `replay_upload_entry` re-inlines ~70 lines that duplicate `operations::publish_file_metadata`
  (encrypt FileMetadata, upload, `[u8;32]` key cast, create+marshal IPNS record, the
  TEE-enrollment match, `IpnsPublishRequest`, Success/Conflict + `record_publish`).
- `fetch_merge_publish_parent` re-inlines a ~40-line CAS-parent-publish tail that is a
  third copy of the sequence already inline in the live mkdir paths
  (`write_ops.rs` and `platform/windows/write_ops.rs`).

Two+ copies of TEE-enrollment and CAS-publish must be kept in lockstep (TTL, seq
handling, wrap). Surfaced by the phase-43 `/simplify` reuse reviewer; deferred from
commit a1ec69f1b.

## Solution

1. Have `replay_upload_entry` delegate the encrypt+publish+TEE tail to
   `operations::publish_file_metadata`. Keep the first-publish probe OUTSIDE the helper:
   `publish_file_metadata` calls `resolve_sequence` internally, which returns NotFound
   for a brand-new record, so the caller must still compute `is_first_publish` and pass
   it in. (Pairs with the typed-NotFound todo.)
2. Extract `pub(crate) async fn cas_publish_parent(api, parent_ipns_name, parent_key_raw,
   json_bytes, old_cid, coordinator) -> Result<PublishResult, String>` in
   `operations.rs` and call it from `fetch_merge_publish_parent` plus both live mkdir
   paths. Note the live sites also do the child first-publish before the parent and
   signal `MkdirConflict` rather than returning Err — extract only the shared parent
   tail. Verify replay tests + winfsp CI still pass.
