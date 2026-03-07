# Phase 9: Desktop Client - Context

**Gathered:** 2026-02-07
**Status:** Ready for planning

## Phase Boundary

Tauri-based macOS desktop app with FUSE mount at ~/CipherVault. Users log in via Web3Auth running inside the Tauri webview, the app mounts the encrypted vault as a native filesystem, and runs as a menu bar utility with background sync. macOS only for v1. Linux/Windows are out of scope (v1.1).

## Implementation Decisions

### FUSE write model

- Temp-file commit approach: buffer writes to local temp file, encrypt+upload complete file on close/flush
- Simplest approach given 100MB file limit and IPFS immutable blob model
- Structure code so write model can be upgraded to streaming in future versions
- Last-write-wins for concurrent edits across devices (no merge/conflict logic)
- Read-write mount from day one — full FUSE operations (open, read, write, create, unlink, mkdir, rmdir, rename)

### Offline behavior

- Queue writes when offline, sync when connectivity returns
- User doesn't notice the delay — writes succeed locally, upload queued
- Background sync retries queued uploads when online

### Login and auth window

- **REVISED DECISION:** Web3Auth runs inside the Tauri webview (NOT system browser redirect). This avoids passing the private key through URL parameters or deep links, which would be a security risk. The webview handles the full Web3Auth SDK flow internally (modal popup within the webview). After authentication, the webview passes the idToken and derived private key to the Rust side via Tauri IPC commands -- a secure in-process communication channel.
- The original plan was system browser redirect with deep link (cipherbox://) returning token to app, but this was revised because the private key would need to transit through URL parameters, which is insecure.
- Remember last auth method: try silent refresh from Keychain first, only show Web3Auth modal if refresh fails
- After login: webview window hides, FUSE mounts, app lives in menu bar only
- Tray icon shows mount status during mount process (mounting -> synced)
- Auto-start on macOS login: opt-in checkbox in Preferences (uses macOS Login Items), off by default

### System tray and status

- Menu bar icon only — no Dock icon (pure background utility like Dropbox)
- Notifications: minimal — only on errors (failed sync, auth expired, mount failed). No routine sync notifications.

### Caching and performance

- Memory-only file content cache for v1 (no disk cache). Architecture should support adding encrypted disk cache later.
- Folder metadata cached with 30s TTL (matches sync polling interval)
- Fetch file content on open only — no pre-fetching when browsing folders
- File attributes (size, dates) returned from decrypted folder metadata — no IPFS fetch needed for Finder listings

### Claude's Discretion

- Tray menu items (balance spec completeness vs v1 simplicity)
- Tray icon visual states (synced/syncing/error/offline variants)
- FUSE cache eviction strategy for memory cache
- Preferences window scope for v1
- Temp file location and cleanup strategy
- Offline write queue persistence (memory vs disk)

## Specific Ideas

- "Go for the simplest solution" — given 100MB file limit and 500MB total quota, optimize for simplicity over performance
- Structure code so write model can be upgraded later — don't paint into a corner
- Memory-only cache for v1, but keep disk cache option in mind for future versions
- App should feel like a background utility (Dropbox-style) — menu bar only, no persistent windows

## Deferred Ideas

- Linux/Windows desktop support — v1.1
- Encrypted-at-rest disk cache for file content — future version
- Pre-fetching small files when browsing folders — future optimization
- Conflict detection and warning for concurrent edits — future version
- Auto-update mechanism — noted in spec open questions, defer to post-v1

---

_Phase: 09-desktop-client_
_Context gathered: 2026-02-07_
