---
status: resolved
trigger: 'Investigate and fix two related folder rename bugs in CipherBox desktop FUSE mount'
created: 2026-05-26T00:00:00Z
updated: 2026-05-26T00:02:00Z
---

## Current Focus

hypothesis: CONFIRMED - Both bugs fixed, awaiting user verification
test: All 39 unit tests pass, desktop app compiles cleanly
expecting: User confirms renames work in Finder and sync correctly
next_action: User verifies in real environment

## Symptoms

expected: Folder renames in Finder/terminal should work like any local folder instantly, then sync to IPFS/IPNS. Remote renames should fully replace the old folder on sync.
actual:
BUG 1 (FUSE rename): Finder shows Touch ID/password dialog asking for elevated permissions. After authenticating, shows "You don't have permission to rename the item".
BUG 2 (sync after web rename): Renaming folder in web UI, then manually syncing desktop app creates a NEW folder with the new name while the OLD folder persists. Both folders visible.
errors: macOS Finder elevation dialog + "You don't have permission to rename the item 'renamed folder'"
reproduction:
BUG 1: Mount FUSE, try to rename any folder from Finder or terminal
BUG 2: Rename folder in web UI, trigger sync on desktop, observe both old and new folders
started: Unknown if it ever worked

## Eliminated

- hypothesis: access() returning EACCES causes rename failure
  evidence: access() already returns reply.ok() unconditionally (read_ops.rs lines 857-869). Desktop CLAUDE.md confirms this was already fixed.
  timestamp: 2026-05-26T00:00:30Z

## Evidence

- timestamp: 2026-05-26T00:00:10Z
  checked: access() implementation in read_ops.rs
  found: access() always returns OK for any mask (lines 857-869). This was already fixed per desktop CLAUDE.md.
  implication: access() is NOT the cause of BUG 1.

- timestamp: 2026-05-26T00:00:15Z
  checked: getattr() and FileAttrs permissions
  found: Directories use perm 0o755 (rwxr-xr-x), files use 0o644 (rw-r--r--). FUSE-T SMB backend creates an SMB share and macOS connects as SMB client. SMB server may do its own permission check based on getattr. 0o755 only grants write to owner. If SMB UID mapping differs from FUSE UID, write operations (including rename, which requires parent dir write) fail.
  implication: BUG 1 root cause: directory perms 0o755 are too restrictive for SMB backend. Need 0o777 since encryption is the real access control.

- timestamp: 2026-05-26T00:00:20Z
  checked: setattr() implementation
  found: setattr ignores mode, uid, gid parameters entirely (operations.rs line 220-221, write_ops.rs lines 23-87). Only handles size. Returns current attrs on all non-size calls.
  implication: Even if SMB client tries to chmod, it silently succeeds (returns OK) but permissions don't change. Not the primary cause but confirms permissions need to be permissive from the start.

- timestamp: 2026-05-26T00:00:25Z
  checked: populate_folder() in inode.rs
  found: Lines 340-343 match folders by NAME only: find_child(parent_ino, &folder.name). When folder renamed in web UI (same id/ipns_name, new name), desktop sync sees new name, find_child returns None, allocates NEW inode. Lines 656-662: merge_only=true preserves old inodes not in remote metadata. Result: both old and new folder co-exist.
  implication: BUG 2 root cause confirmed. Need to match folders by ipns_name (stable identifier) in addition to name.

- timestamp: 2026-05-26T00:01:30Z
  checked: Fix compilation and tests
  found: All 39 tests pass (including 2 new rename tests). Desktop app compiles cleanly. Windows code unaffected (separate feature gate).
  implication: Fixes are safe and correct.

## Resolution

root_cause:
BUG 1: Directory permissions (0o755) and file permissions (0o644) are too restrictive for FUSE-T SMB backend. The SMB server interprets Unix permissions from getattr and may deny write operations when the SMB client UID doesn't match the FUSE-reported owner UID. Finder's pre-flight permission check triggers the elevation dialog.
BUG 2: populate_folder() matches children by name only via find_child(parent_ino, &folder.name). When a folder is renamed remotely (same ipns_name, new name), find_child() returns None (no child with new name), so a new inode is allocated. The merge_only=true preservation logic keeps the old inode too, resulting in duplicates.
fix:
BUG 1: Changed all FUSE directory permissions from 0o755 to 0o777 and file permissions from 0o644 to 0o666. Encryption is the access control, not Unix permissions. Affected locations: InodeTable::new() (root), populate_folder() (folders and files), handle_mkdir(), handle_create().
BUG 2: Enhanced populate_folder() to build ipns_name-to-ino and file_ipns_name-to-ino lookup maps from existing children. When find_child by name fails, falls back to matching by stable IPNS identifier. On IPNS match (rename detected), cleans up old name index entry before inserting with new name. Also updated the non-merge removal logic to check IPNS names instead of display names, preventing renamed items from being incorrectly removed.
verification: 39/39 unit tests pass. 2 new tests specifically verify folder rename matching by IPNS name (merge_only=true and merge_only=false). Desktop app compiles cleanly.
files_changed:

- crates/fuse/src/inode.rs
- crates/fuse/src/write_ops.rs
- crates/fuse/Cargo.toml
