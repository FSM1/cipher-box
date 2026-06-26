---
created: 2026-06-24
title: Unpin the orphaned uploaded CID when verified merge fails closed
area: fuse
files:
  - crates/fuse/src/metadata.rs
---

## Problem

In `spawn_metadata_publish` (`crates/fuse/src/metadata.rs`), the new metadata blob (`new_cid`) is uploaded and server-pinned (~line 245) before the verified-resolve/merge step. Every normal exit of the Conflict arm unpins `new_cid` (Success ~line 391, persistent-Conflict ~line 403), but the `VerifyError::Invalid` fail-closed branch (~line 327-330) returns early **without** unpinning, leaving an orphaned pinned blob on every retry of a verification failure.

Surfaced by CodeRabbit during the Phase 60 ship review (finding F11). Verified real but classified out-of-scope (it is a storage-cleanup leak, not a verification-correctness gap — the fail-closed behavior itself is correct) and not low-risk (touches the delicate merge flow).

## Solution

In the `VerifyError::Invalid` arm of the verified merge, call `cipherbox_api_client::ipfs::unpin_content(&api, &new_cid)` (best-effort, same as the other exits) before returning the error, so a failed IPNS verify does not strand the pre-uploaded blob.
