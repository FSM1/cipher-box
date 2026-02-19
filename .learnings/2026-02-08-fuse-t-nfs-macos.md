# FUSE-T NFS on macOS — Hard-Won Lessons

**Date:** 2026-02-08

## Original Prompt

> Phase 9: Build a Tauri desktop client with FUSE mount for transparent file access to CipherBox vault.

We chose FUSE-T (userspace NFS) over macFUSE (kernel extension) because Apple deprecated kexts. This introduced a whole class of NFS-specific issues that don't exist with kernel FUSE.

## What I Learned

### The Single-Thread Rule

- **ALL FUSE-T NFS callbacks run on a single thread.** Any blocking call — even 500ms — stalls the entire filesystem and causes macOS NFS client to report "server connection interrupted."
- `read()` is the most dangerous callback. IPFS fetches take 1-3s. A naive `block_on(fetch)` inside `read()` will kill the mount within seconds.
- **Solution:** Channel-based prefetch architecture. `open()` fires a background IPFS fetch via `content_tx`. `read()` drains `content_rx` into cache non-blocking. On cache miss, return `EIO` — NFS retries automatically.
- This pattern applies to ANY async I/O in FUSE callbacks: never block, always defer to background tasks and drain results opportunistically.

### Inode Stability is Sacred

- NFS clients cache inode numbers aggressively. If `populate_folder()` allocates new ino numbers for children that already exist (same name, same content), NFS returns "stale file handle" errors and Finder disconnects.
- **Solution:** `populate_folder()` must check `find_child(parent_ino, &name)` and reuse the existing ino. Only allocate new inos for genuinely new children.
- Also preserve the `children` list and `children_loaded` state of existing folder inodes — don't reset them on refresh.

### READDIR Cache is Permanent (Practically)

- macOS NFS client caches READDIR results and does NOT re-fetch even when the directory's mtime changes via GETATTR. There is no server-side mechanism to invalidate this cache.
- `acdirmin`/`acdirmax` mount options could help, but FUSE-T doesn't expose them from the server side.
- **Consequence:** The FIRST READDIR response for any directory must be correct. There are no second chances.
- **Solution:** Pre-populate all immediate subfolders during mount (before the FUSE event loop starts), so the first READDIR returns real children, not empty results.
- Files created via CLI (`echo > ~/CipherBox/folder/file.txt`) will appear in `ls` but NOT in Finder until a new Finder window is opened. This is a known limitation of NFS on macOS — no FSEvents on NFS mounts.

### READDIR Deduplication

- NFS calls `readdir` twice per directory listing: once at offset=0 and once at offset=N (continuation). Both calls trigger the same background refresh logic.
- **Solution:** Only fire background refresh on `offset == 0`. The offset=N call will use whatever data is already cached.

### Directory mtime Matters

- NFS uses directory mtime to decide if READDIR cache is valid (even though it doesn't always re-fetch).
- `populate_folder()` must detect when children actually changed and bump parent `mtime`+`ctime` to `SystemTime::now()`.
- Similarly, mutation callbacks (create, mkdir, unlink, rmdir, rename) must bump parent mtime.
- Use `DIR_TTL=0` for directories (always re-validate via GETATTR) and `FILE_TTL=60s` for files.

### Lookup Consistency

- NFS client does LOOKUP for every entry returned by READDIR, including "." and "..". Returning ENOENT for ".." causes an immediate NFS disconnect.
- **Solution:** Handle "." and ".." explicitly in `lookup()`, returning the current and parent inode respectively.

### FUSE-T Rename Truncation

- FUSE-T truncates the filename in rename callbacks by exactly 8 bytes. A file named `document.txt` might arrive as `docu` in the rename callback's `newname` parameter.
- **Solution:** Suffix-match fallback — if exact match fails, find the child whose name ends with the (truncated) new name.

### Platform Special Files

- macOS generates `.DS_Store`, `.Spotlight-V100`, `.Trashes`, `.fseventsd`, `._*` resource forks, `.localized`, `Icon\r` on every directory access.
- These MUST be filtered: ENOENT in lookup, filtered from readdir, EACCES on create/mkdir, excluded from rename.
- Centralize in an `is_platform_special()` helper — the list is long and you'll need it everywhere.

### Mutation Cooldown

- Background metadata refreshes (IPNS resolve) can overwrite local mutations before they propagate through IPNS (which is eventually consistent, ~30s).
- **Solution:** Track `mutated_folders` with timestamps. Skip background refreshes for 30 seconds after any local mutation to that folder.

## What Would Have Helped

- A document explaining FUSE-T's NFS translation layer behavior — none exists. We learned everything through trial and error.
- Understanding upfront that FUSE-T != kernel FUSE. Every assumption about FUSE behavior needs re-verification under NFS semantics.
- A test harness that could exercise FUSE callbacks without requiring a full mount (unit-test the filesystem struct directly).
- Knowing that macOS NFS READDIR caching is essentially permanent would have led us to eager pre-population from the start.

## Key Files

- `apps/desktop/src-tauri/src/fuse/mod.rs` — CipherBoxFS struct, mount/unmount, drain helpers, pre-population
- `apps/desktop/src-tauri/src/fuse/operations.rs` — All FUSE callbacks (lookup, getattr, readdir, read, write, create, mkdir, rename, unlink, rmdir)
- `apps/desktop/src-tauri/src/fuse/inode.rs` — Inode table, populate_folder with ino reuse
- `apps/desktop/src-tauri/src/fuse/cache.rs` — Metadata and content caches with TTL
- `apps/desktop/src-tauri/.cargo/config.toml` — FUSE-T pkg-config override
- `apps/desktop/src-tauri/pkg-config/fuse.pc` — Custom fuse.pc pointing to FUSE-T headers

## Implications for Linux/Windows

- **Linux:** Can use kernel FUSE (libfuse) directly. Most NFS-specific issues disappear. Inode stability still matters. No READDIR caching issue. No rename truncation. No single-thread constraint (FUSE supports multithreaded mode). The channel-based prefetch architecture is still beneficial for performance.
- **Windows:** WinFSP or Dokan. Different callback model entirely. The async/non-blocking architecture translates well. Platform special files will be different (desktop.ini, Thumbs.db, etc.). Inode concept replaced by file IDs — same stability requirement.
- **Shared code:** The `InodeTable`, `MetadataCache`, `ContentCache`, and the channel-based prefetch pattern are platform-agnostic. The FUSE callback implementations will need per-platform variants, but the data structures and async patterns can be reused.
