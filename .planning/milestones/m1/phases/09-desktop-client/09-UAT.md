---
status: testing
phase: 09-desktop-client
source: 09-01-SUMMARY.md, 09-02-SUMMARY.md, 09-03-SUMMARY.md, 09-04-SUMMARY.md, 09-05-SUMMARY.md, 09-06-SUMMARY.md, 09-07-PLAN.md
started: 2026-02-08T12:00:00Z
updated: 2026-02-08T20:30:00Z
---

## Current Test

number: 15
name: Quit unmounts cleanly
expected: |
Click "Quit CipherBox" in tray. FUSE unmounts. App process exits completely.
awaiting: user response

## Tests

### 1. Desktop app launches as menu bar utility

result: pass

### 2. Web3Auth login via webview

result: issue
severity: major
note: Tray status not updated on first login attempt (greyed out options, login still visible). Works on retry. Also intermittent keychain "already exists" error despite delete-before-set fix.

### 3. FUSE mount appears after login

result: pass (after fix: FUSE-T userspace via custom pkg-config)

### 4. Read files through FUSE mount

result: pass

### 5. Create file through FUSE mount

result: pass (after fix: non-blocking release + background upload)

### 6. Create folder through FUSE mount

result: pass (after fix: non-blocking mkdir)

### 7. Delete file through FUSE mount

result: pass

### 8. Delete folder through FUSE mount

result: pass

### 9. Rename file through FUSE mount

result: pass (after fix: suffix-match for FUSE-T rename truncation)

### 10. Tray "Open CipherBox" action

result: pass (after fix: NFS "."/".." lookup, platform file filtering, mutation cooldown)

### 11. Tray "Sync Now" action

result: pass
note: UX issue — no visible sync feedback (context menu closes on click). Low priority.

### 12. Background sync detects remote changes

result: pass
note: ~30s latency (metadata cache TTL). Reactive sync (triggered by readdir), not proactive polling. Acceptable for v1.

### 13. Keychain token persistence

result: pass
note: Requires clicking "Connect" in webview (Web3Auth private key can't be persisted). Auth is automatic after that.

### 14. Logout clears state

result: pass (after fix: force unmount, webview reload, OAuth popup cleanup)
note: Multiple fixes required — see fixes 10-13 below.

### 15. Quit unmounts cleanly

result: pass
note: UX suggestion — no visual feedback during quit/unmount process (takes a few seconds). Low priority.

## Summary

total: 15
passed: 14
issues: 1
pending: 0
skipped: 0

## Gaps

- truth: 'Tray status updates reliably after Web3Auth login'
  status: open
  severity: major
  test: 2
  note: 'Intermittent — works on retry. Also keychain "already exists" error persists intermittently despite delete-before-set fix.'

## Fixes Applied During UAT

### Build Fixes

- Cargo.toml: `default = ["fuse"]`, added `features = ["libfuse"]` to fuser
- Switched macFUSE (kext) to FUSE-T (userspace NFS): custom `pkg-config/fuse.pc` + `.cargo/config.toml`

### FUSE-T NFS Fixes (9 total, from previous session)

1. **Rename truncation workaround** — FUSE-T truncates filenames by 8 bytes in rename callback. Suffix-match fallback in rename(). `src/fuse/operations.rs`

2. **Platform special file filtering** — Centralized `is_platform_special()` helper. Used in lookup (ENOENT), readdir (filter), create/mkdir (EACCES), rename (exclude). `src/fuse/operations.rs`

3. **NFS "." and ".." lookup** — NFS clients LOOKUP ".." after readdir; returning ENOENT caused disconnect. Added "."/".." handling in lookup(). `src/fuse/operations.rs`

4. **Mutation cooldown** — Background refreshes overwrote local mutations before IPNS propagation. Added `mutated_folders` map, skip refreshes for 30s after local change. `src/fuse/mod.rs`

5. **Keychain delete-before-set** — `set_password()` fails if item exists on macOS. Delete first in `store_refresh_token()` and `store_user_id()`. `src/api/auth.rs`

6. **ipns.service.ts non-null assertion** — TypeScript can't narrow module-level `let` variables. Added `!` assertion. `apps/api/src/ipns/ipns.service.ts:407`

7. **Split DIR_TTL=0 / FILE_TTL=60s** — NFS client cached dir attrs for 60s, missing mtime changes. Dirs always re-validated, files cached. `src/fuse/operations.rs`

8. **Parent mtime bump on mutations** — NFS uses dir mtime for readdir cache validity. Bump mtime+ctime after rename/unlink/rmdir/create/mkdir. `src/fuse/operations.rs`

9. **Non-blocking read with content prefetch** — read() blocked NFS thread for up to 3s on IPFS cache miss, causing Finder disconnects. Replaced with channel-based prefetch: open() fires background IPFS fetch via `content_tx`, read() drains `content_rx` into cache non-blocking, returns EIO on miss (NFS retries). `src/fuse/operations.rs`, `src/fuse/mod.rs`

### Fixes from this session (10-16)

10. **Force unmount fallback** — `umount` fails when Finder has open handles ("Resource busy"). Changed fallback from `diskutil unmount` to `diskutil unmount force`. `src/fuse/mod.rs`

11. **Webview reload on re-login** — After tray logout, re-showing the login window showed stale DOM (disabled button, success message). Now calls `location.reload()` to reset all state. `src/tray/mod.rs`

12. **OAuth popup cleanup** — Google OAuth popup window stayed open after auth completed. Now `handle_auth_complete` destroys all `oauth-popup-*` windows and hides main webview on success. `src/commands.rs`

13. **Web3Auth clearCache fix** — `logout({ cleanup: true })` tore down Web3Auth connectors, causing "Wallet connector not ready" error on re-login. Changed to `clearCache()` in initWeb3Auth (preserves connectors) and plain `logout()` (no cleanup flag) in login(). `apps/desktop/src/auth.ts`

14. **Deduplicate readdir refresh fires** — NFS calls readdir twice (offset=0 and offset=N), both fired background refreshes for the same IPNS name. Now only fires on offset=0. `src/fuse/operations.rs`

15. **Inode reuse in populate_folder** — Background refreshes allocated new inode numbers for existing children, causing NFS "stale file handle" disconnects. Now reuses existing ino for children matching by name. Also preserves children_loaded state and existing grandchildren. `src/fuse/inode.rs`

16. **Eager subfolder pre-population** — NFS clients cache READDIR aggressively and don't re-fetch even when mtime changes. First READDIR for subfolders returned empty (before async refresh). Now pre-populates all immediate subfolders during mount so first READDIR is correct. `src/fuse/mod.rs`

### Known Issues to Fix Before Merge

- **Finder NFS cache staleness**: Finder does not re-issue READDIR when mtime changes via GETATTR. Files created via CLI may not appear in Finder until a new Finder window is opened. Deeper NFS cache control (acdirmin/acdirmax) not available from FUSE-T server side.
- **Keychain "already exists" intermittent**: Delete-before-set fix applied but error still appears sometimes. May need to investigate keychain access group or timing.
- **Stale mount point cleanup**: After crash, `~/CipherBox` may contain `.DS_Store` etc. App should clean mount point on startup.
- **Diagnostic logging**: Remove all `eprintln!(">>>` lines before final commit.
