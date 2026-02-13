# macOS System Integration Gotchas

**Date:** 2026-02-08

## Original Prompt

> Phase 9 UAT: Desktop client with FUSE mount, tray icon, keychain persistence.

## What I Learned

### Keychain (keyring crate)

- `keyring::set_password()` fails with "already exists" error if the item already exists in macOS Keychain. The crate doesn't upsert.
- **Workaround:** Always `delete_credential()` before `set_password()`. But this still fails intermittently — possibly a timing issue with Keychain's internal locking or access group conflicts.
- The intermittent nature suggests a race condition in Keychain Services itself, or possibly Keychain Access app holding a read lock.

### Force Unmount

- `umount(path)` fails with "Resource busy" when Finder has open handles on the mount point (common — Finder reads `.DS_Store` and metadata eagerly).
- `diskutil unmount path` also fails in this case.
- `diskutil unmount force path` works reliably. This is the equivalent of `umount -f` but goes through DiskArbitration framework.
- **Always** use force unmount as the fallback, not just `diskutil unmount`.

### Stale Mount Point

- After a crash or ungraceful exit, `~/CipherBox` may contain `.DS_Store`, `.metadata_never_index`, and potentially cached Finder metadata.
- FUSE-T mount on a non-empty directory works but can behave unexpectedly.
- **Solution:** On startup, if the mount directory exists, remove all its contents before mounting.

### Spotlight Indexing

- Without mitigation, Spotlight will try to index the FUSE mount, generating constant read traffic.
- Creating `.metadata_never_index` in the mount root prevents this.
- Must be created AFTER cleaning stale files but BEFORE mounting FUSE.

## Key Files

- `apps/desktop/src-tauri/src/fuse/mod.rs` — Mount point cleanup, Spotlight suppression, force unmount
- `apps/desktop/src-tauri/src/api/auth.rs` — Keychain token storage with delete-before-set
