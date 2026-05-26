---
status: resolved
trigger: 'After editing a text file in the CipherBox web UI and saving, the FUSE-mounted desktop folder still shows the original file content.'
created: 2026-04-13T00:00:00Z
updated: 2026-04-13T00:00:00Z
---

## Current Focus

hypothesis: CONFIRMED and FIXED - populate_folder now detects modified_at changes and marks files for re-resolution
test: unit test passes; awaiting human verification with real desktop + web workflow
expecting: user confirms FUSE mount picks up web UI file edits within ~30s
next_action: user verifies end-to-end with real FUSE mount

## Symptoms

expected: After saving a file edit in the web UI, opening the same file from the FUSE-mounted folder should show the updated content.
actual: The FUSE mount still shows the original (pre-edit) version of the file. The web UI does show the updated version.
errors: No error messages reported.
reproduction: 1. Upload a text file via the desktop mounted folder. 2. Open the web UI, edit the text file, save. 3. Close editor, reopen to confirm changes persisted to IPFS. 4. Open the file from the mounted folder — original content still displayed.
started: Current behavior being tested.

## Eliminated

## Evidence

- timestamp: 2026-04-13T00:10:00Z
  checked: SyncDaemon::poll() in crates/sdk/src/sync.rs
  found: SyncDaemon detects IPNS sequence changes but only logs them. Does NOT actively invalidate caches or trigger re-population. Comments say "Cache will refresh on next access."
  implication: The sync daemon is passive - it relies on metadata cache TTL expiry for refresh.

- timestamp: 2026-04-13T00:15:00Z
  checked: MetadataCache TTL in crates/fuse/src/cache.rs
  found: Metadata cache has 30s TTL. When stale, readdir fires background refresh via drain_refresh_completions.
  implication: Folder metadata does get refreshed after 30s, but folder metadata only contains FilePointers (name, fileMetaIpnsName), not the actual file CID.

- timestamp: 2026-04-13T00:20:00Z
  checked: populate_folder() in crates/fuse/src/inode.rs line 428-444
  found: When processing FilePointer entries, if an existing inode has file_meta_resolved=true, the code at line 443 keeps the existing InodeKind unchanged. This preserves the old CID, encrypted_file_key, iv, size, etc.
  implication: ROOT CAUSE - Once a file's per-file IPNS metadata is resolved, it is NEVER re-resolved even when the folder metadata refreshes. The old CID persists indefinitely.

- timestamp: 2026-04-13T00:22:00Z
  checked: drain_refresh_completions() in crates/fuse/src/lib.rs line 642-727
  found: After populate_folder, it spawns async resolution ONLY for unresolved file pointers (file_meta_resolved=false). Already-resolved files are skipped.
  implication: Confirms the gap - the refresh path only resolves NEW files, never re-resolves existing files that may have updated content.

- timestamp: 2026-04-13T00:25:00Z
  checked: Content cache in crates/fuse/src/cache.rs
  found: ContentCache is keyed by CID (content-addressed). Even if it expired, the read path would re-fetch the SAME old CID because the inode still points to it.
  implication: Content cache is not the issue. The issue is upstream - the inode's CID reference is stale.

## Resolution

root_cause: In populate_folder() (inode.rs:443), when a folder metadata refresh occurs, files that were already resolved (file_meta_resolved=true) have their InodeKind preserved as-is. This means the CID, encrypted_file_key, iv, and size from the initial resolution are never updated. When a file is edited via the web UI (which publishes a new file metadata IPNS record with a new CID), the FUSE mount's folder refresh detects the folder change but populate_folder skips re-resolving the file's individual IPNS metadata because it's already marked as resolved. The old CID continues to be served on read.
fix: In populate_folder() (inode.rs), when processing a FilePointer for an already-resolved file, compare the incoming modified_at timestamp with the existing inode's mtime. If modified_at is newer, mark the file as unresolved (file_meta_resolved=false) with cleared CID, preserving IPNS keys. This causes drain_refresh_completions to spawn a new async IPNS resolution for the file, picking up the new CID. Added a dedicated test (test_populate_folder_resets_resolved_file_on_modified_at_change) verifying the three-phase behavior: initial populate -> resolve -> re-populate with newer modified_at resets to unresolved.
verification: Unit tests pass (37/37). Awaiting human verification with real FUSE mount.
files_changed: [crates/fuse/src/inode.rs]
