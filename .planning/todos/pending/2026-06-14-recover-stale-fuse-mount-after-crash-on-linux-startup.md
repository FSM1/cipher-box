---
created: 2026-06-14T02:27:23.144Z
title: Recover stale FUSE mount after crash on Linux startup
area: desktop-fuse
files:
  - apps/desktop/src-tauri/src/fuse/mod.rs:65-86
---

## Problem

After a SIGKILL/crash, the Linux desktop cannot remount its vault on the next
launch. The mount fails with `Filesystem mount failed: Failed to create mount
point: File exists (os error 17)` and fires a user-facing "mount failed" OS
notification, with **no automatic recovery** — the user must manually run
`fusermount3 -u ~/CipherBox` before the app can mount again.

Root cause is in `mount_filesystem` (`apps/desktop/src-tauri/src/fuse/mod.rs:65-86`):

```rust
if mount_path.is_symlink() { return Err(...) }
if !mount_path.exists() {
    std::fs::create_dir_all(&mount_path)            // line 69-71
        .map_err(|e| format!("Failed to create mount point: {}", e))?;
} else {
    // read_dir + remove each entry, then:
    log::info!("Cleaned stale mount point: ...");   // line 77-85
}
```

When `~/CipherBox` is left as a **disconnected** FUSE mount (ENOTCONN — `ls`
reports "Transport endpoint is not connected"), `stat()` on the path returns
ENOTCONN, so `mount_path.exists()` returns **false**. The code therefore takes
the `create_dir_all` branch, but the directory entry still exists → EEXIST →
"File exists (os error 17)". The stale-cleanup `else` branch that would have
handled it is skipped precisely because `exists()` returned false.

Normal relaunches (where the previous mount was cleanly released) hit the `else`
branch, log "Cleaned stale mount point", and mount fine — so this only bites the
post-crash ENOTCONN state.

## Evidence

Observed during the Phase 43 Linux/FUSE UAT (Linux 6.17, libfuse3, default
`fuse` feature, 2026-06-14). Most relaunches logged "Cleaned stale mount point"
and mounted; the one relaunch that hit the disconnected state logged
`Filesystem mount failed: Failed to create mount point: File exists (os error 17)`
and rendered the "mount failed" notification (user-visible). Relates to phase 43
fuse-write-durability (crash/restart recovery) and the existing
[[2026-06-11-fuse-mkdir-parent-publish-orphan]] /
[[2026-06-11-fuse-release-data-loss-before-remote-commit]] desktop-fuse items.

## Solution

Make startup mount detect and recover a stale/disconnected mount before
`create_dir_all`:

- Treat an ENOTCONN `stat()` on the mount point as "stale mount present, needs
  unmount" (don't rely on `exists()` alone — it lies for disconnected FUSE
  mounts). Could check `/proc/self/mountinfo` for the mount point as the
  authoritative signal on Linux.
- Run `fusermount3 -u <mount_path>` (lazy `-z` as fallback) to clear it, then
  proceed to mount.
- Alternatively/additionally: when `create_dir_all` returns `EEXIST`, fall
  through to the unmount + stale-cleanup path instead of erroring out.
- Secondary: replace the bare "mount failed" notification copy with something
  less alarming and actionable (e.g. "Reconnecting your vault…" with an auto
  self-heal), since the condition is recoverable.

Platform scope: Linux only. macOS uses a different mount path (FUSE-T) and
already "cleans stale contents before mount"; Windows/WinFsp is unaffected.
Severity: medium — manually recoverable, but a crashed session looks broken with
no in-app recovery.
