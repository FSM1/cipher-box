# Phase 9: Desktop Client - Research

**Researched:** 2026-02-07
**Domain:** Tauri v2 desktop app, FUSE filesystem, macOS integration
**Confidence:** MEDIUM (some areas HIGH, FUSE-T/fuser integration is LOW)

## Summary

Phase 9 builds a macOS menu bar utility using Tauri v2 that mounts an encrypted FUSE filesystem at `~/CipherVault`. The app authenticates via Web3Auth (system browser redirect with deep link callback), stores refresh tokens in macOS Keychain, and runs a background sync daemon polling IPNS every 30 seconds.

The architecture splits into three main components: (1) a Tauri v2 shell providing the menu bar icon, window management, deep link handling, and Keychain access; (2) a Rust FUSE filesystem using the `fuser` crate with FUSE-T on macOS; and (3) the existing `@cipherbox/crypto` TypeScript module running in the Tauri webview for all encryption operations.

**Primary recommendation:** Use Tauri v2 as the app shell with a Rust FUSE layer (`fuser` crate + FUSE-T), run `@cipherbox/crypto` in the webview context (Web Crypto API is available in WKWebView), and bridge FUSE operations to the webview via Tauri IPC commands. The Rust side handles FUSE syscalls and HTTP calls to the API; the webview handles crypto operations. Store the refresh token in macOS Keychain via the `keyring` Rust crate.

## Standard Stack

### Core

| Library            | Version | Purpose               | Why Standard                                                           |
| ------------------ | ------- | --------------------- | ---------------------------------------------------------------------- |
| Tauri              | 2.10.x  | Desktop app framework | Rust-backed, small binary, native webview, mature v2 release           |
| fuser              | 0.16.0  | Rust FUSE bindings    | Only maintained Rust FUSE crate, pure Rust (not just C bindings)       |
| FUSE-T             | 1.0.35+ | macOS FUSE backend    | Kext-less, NFS-based, no kernel extension needed, Apple Silicon native |
| keyring            | 3.6.x   | macOS Keychain access | Cross-platform credential storage, `apple-native` feature for Keychain |
| reqwest            | 0.12.x  | HTTP client (Rust)    | Standard Rust HTTP client for API calls from FUSE layer                |
| tokio              | 1.x     | Async runtime (Rust)  | Required by fuser and reqwest, standard async runtime                  |
| serde / serde_json | 1.x     | Serialization (Rust)  | Required for Tauri IPC and API responses                               |

### Tauri Plugins

| Plugin                    | Version | Purpose                          | When to Use                              |
| ------------------------- | ------- | -------------------------------- | ---------------------------------------- |
| tauri-plugin-deep-link    | 2.x     | Custom URL scheme (cipherbox://) | Auth callback from system browser        |
| tauri-plugin-autostart    | 2.x     | macOS Login Items                | Opt-in auto-start on login               |
| tauri-plugin-shell        | 2.x     | Open system browser              | Launch Web3Auth login in default browser |
| tauri-plugin-notification | 2.x     | Error notifications              | Failed sync, auth expired, mount errors  |

### Frontend (Webview)

| Library                      | Version | Purpose              | When to Use                                     |
| ---------------------------- | ------- | -------------------- | ----------------------------------------------- |
| @cipherbox/crypto            | 0.0.1   | Shared crypto module | All encryption/decryption operations in webview |
| @tauri-apps/api              | 2.x     | Tauri JS bindings    | IPC invoke, event listening                     |
| @tauri-apps/plugin-deep-link | 2.x     | Deep link JS API     | Listen for auth callbacks                       |

### Alternatives Considered

| Instead of    | Could Use            | Tradeoff                                                                                                                    |
| ------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| FUSE-T        | macFUSE (kext)       | Requires kernel extension, recovery mode on Apple Silicon. macFUSE 5+ has FSKit backend but limited to /Volumes mount point |
| FUSE-T        | macFUSE FSKit        | macOS 15.4+ only, mount point restricted to /Volumes (not ~/CipherVault), I/O performance lower                             |
| fuser         | fuse3 crate          | Less maintained, fewer downloads; fuser is the community standard                                                           |
| keyring crate | Tauri Stronghold     | Stronghold is Tauri-specific encrypted DB, not OS keychain; keyring uses native Keychain                                    |
| keyring crate | tauri-plugin-keyring | Community plugin wrapping keyring crate; use keyring directly from Rust instead                                             |
| Tauri v2      | Electron             | 10x larger binary, no native Rust FUSE integration, higher memory use                                                       |

**Installation (Rust - Cargo.toml):**

```toml
[dependencies]
tauri = { version = "2.10", features = ["tray-icon"] }
tauri-plugin-deep-link = "2"
tauri-plugin-autostart = "2"
tauri-plugin-shell = "2"
tauri-plugin-notification = "2"
fuser = { version = "0.16", default-features = false }
keyring = { version = "3.6", features = ["apple-native"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

**Installation (JS - package.json):**

```bash
pnpm add @tauri-apps/api @tauri-apps/plugin-deep-link @tauri-apps/plugin-shell @cipherbox/crypto
```

## Architecture Patterns

### Recommended Project Structure

```text
apps/desktop/
  src/                    # Frontend (webview) TypeScript
    main.ts               # Webview entry point
    crypto-bridge.ts      # Crypto operations called via IPC
    auth.ts               # Web3Auth + deep link handling
  src-tauri/
    src/
      main.rs             # Tauri entry point
      fuse/
        mod.rs            # FUSE filesystem implementation
        inode.rs          # Inode table and metadata cache
        file_handle.rs    # Open file handles (temp-file write buffer)
        operations.rs     # FUSE operation implementations
      api/
        mod.rs            # API client (reqwest)
        auth.rs           # Token management + Keychain
        ipfs.rs           # IPFS upload/download
        ipns.rs           # IPNS resolve/publish
      sync/
        mod.rs            # Background sync daemon
        queue.rs          # Offline write queue
      tray/
        mod.rs            # Menu bar icon + menu
        status.rs         # Status state machine
      state.rs            # App state (keys, mount status)
      commands.rs         # Tauri IPC commands (crypto bridge)
    Cargo.toml
    tauri.conf.json
    capabilities/
      default.json        # Permission grants
    icons/
```

### Pattern 1: Dual-Layer Architecture (Rust FUSE + Webview Crypto)

**What:** The FUSE filesystem runs in Rust (native thread via fuser), while all cryptographic operations are performed in the Tauri webview where `@cipherbox/crypto` runs natively with Web Crypto API.

**When to use:** Always -- this is the core architecture.

**Why:** The `@cipherbox/crypto` module uses Web Crypto API (`crypto.subtle`) for AES-256-GCM and the `eciesjs` library for ECIES. Both work in WKWebView (macOS Safari engine). Rewriting crypto in Rust would require reimplementing and re-auditing the entire crypto module. Using the existing TypeScript module ensures cryptographic correctness.

**Data flow for file read:**

```text
Finder (open file)
  -> FUSE read() [Rust, fuser]
    -> Check memory cache
    -> If miss: HTTP GET /ipfs/{cid} [Rust, reqwest]
    -> Send encrypted bytes to webview via Tauri event
    -> Webview decrypts with @cipherbox/crypto
    -> Return plaintext to Rust via IPC callback
  -> Return data to kernel
```

**Critical consideration:** FUSE operations are synchronous from the kernel's perspective. The `fuser` crate provides `reply` objects that can be answered asynchronously. The Rust FUSE handler must:

1. Receive FUSE call (e.g., `read`)
2. Spawn async task on tokio runtime
3. Fetch encrypted data via reqwest
4. Call Tauri IPC to webview for decryption
5. Reply to FUSE with decrypted data

### Pattern 2: Alternative -- Rust-Native Crypto (Recommended)

**What:** Instead of bridging to the webview for crypto, implement equivalent crypto operations directly in Rust using well-audited crates.

**When to use:** This is actually the BETTER approach for FUSE operations, despite the initial overhead.

**Why this is likely better:** FUSE operations need to be fast and synchronous-ish. Round-tripping through the webview IPC for every file read/write adds latency and complexity. The Rust ecosystem has equivalent crates:

| TypeScript (@cipherbox/crypto) | Rust Equivalent               | Notes                                       |
| ------------------------------ | ----------------------------- | ------------------------------------------- |
| `crypto.subtle` AES-256-GCM    | `aes-gcm` crate (RustCrypto)  | Same algorithm, well-audited                |
| `eciesjs` (secp256k1 ECIES)    | `ecies` crate                 | Compatible output format needs verification |
| `@noble/ed25519`               | `ed25519-dalek`               | Standard Ed25519                            |
| `@libp2p/crypto` + `ipns`      | Custom or `libp2p` Rust crate | IPNS record creation                        |
| `crypto.getRandomValues`       | `rand` crate with `OsRng`     | OS-provided entropy                         |

**Tradeoff:** Requires verifying that Rust crypto produces byte-identical output to the TypeScript module (same ECIES scheme, same key format, same IV handling). Create cross-language test vectors from the existing `@cipherbox/crypto` tests.

**Recommendation:** Use Rust-native crypto for the FUSE layer. The webview is only needed for the initial Web3Auth login flow (which returns the user's keypair). After login, all keys are passed to the Rust side and crypto operations happen natively. This eliminates the IPC bottleneck entirely.

### Pattern 3: Temp-File Commit Write Model

**What:** Writes are buffered to a local temp file. On `flush()` or `release()` (close), the complete file is encrypted and uploaded to IPFS, then folder metadata is updated.

**When to use:** All write operations through FUSE.

**Example (pseudocode):**

```rust
// On create/open for writing:
fn open(&mut self, ino: u64, flags: i32, reply: ReplyOpen) {
    let fh = self.next_file_handle();
    let temp_path = self.temp_dir.join(format!("cb-{}", fh));
    self.open_files.insert(fh, OpenFile {
        ino,
        temp_path,
        dirty: false,
        original_data: None, // loaded on first read if existing file
    });
    reply.opened(fh, 0);
}

// On write:
fn write(&mut self, ino: u64, fh: u64, offset: i64, data: &[u8], ..., reply: ReplyWrite) {
    let file = self.open_files.get_mut(&fh).unwrap();
    // Write to temp file at offset
    let mut f = OpenOptions::new().write(true).create(true).open(&file.temp_path)?;
    f.seek(SeekFrom::Start(offset as u64))?;
    f.write_all(data)?;
    file.dirty = true;
    reply.written(data.len() as u32);
}

// On flush/release:
fn release(&mut self, ino: u64, fh: u64, ..., reply: ReplyEmpty) {
    let file = self.open_files.remove(&fh).unwrap();
    if file.dirty {
        // Read complete temp file
        let plaintext = std::fs::read(&file.temp_path)?;
        // Encrypt (AES-256-GCM with new random key+IV)
        // Upload to IPFS
        // Update folder metadata + publish IPNS
        // Queue if offline
        self.upload_queue.push(UploadTask { ino, plaintext, ... });
    }
    std::fs::remove_file(&file.temp_path).ok();
    reply.ok();
}
```

### Pattern 4: Menu Bar Only App (No Dock Icon)

**What:** App runs as a pure background utility with menu bar icon only.

**How:**

```rust
// In Tauri setup:
tauri::Builder::default()
    .setup(|app| {
        #[cfg(target_os = "macos")]
        app.set_activation_policy(tauri::ActivationPolicy::Accessory);

        // Build tray icon
        let tray = TrayIconBuilder::new()
            .icon(app.default_window_icon().unwrap().clone())
            .menu(&build_tray_menu(app)?)
            .menu_on_left_click(true)
            .on_menu_event(handle_tray_menu_event)
            .build(app)?;

        Ok(())
    })
```

**tauri.conf.json -- no default window:**

```json
{
  "app": {
    "windows": []
  }
}
```

### Pattern 5: Deep Link Auth Flow

**What:** Web3Auth login via system browser with `cipherbox://` callback.

**Flow:**

1. User clicks "Login" in tray menu or on first launch
2. App opens system browser: `https://auth.web3auth.io/...?redirect_uri=cipherbox://auth/callback`
3. User authenticates in browser
4. Browser redirects to `cipherbox://auth/callback?token=...`
5. macOS routes deep link to Tauri app
6. App extracts token, calls backend `/auth/login`, receives `accessToken`
7. Backend sets refresh token in response body (not cookie -- see Auth section)
8. App stores refresh token in Keychain
9. App fetches vault keys, decrypts, mounts FUSE

**tauri.conf.json:**

```json
{
  "plugins": {
    "deep-link": {
      "desktop": {
        "schemes": ["cipherbox"]
      }
    }
  }
}
```

### Anti-Patterns to Avoid

- **Running crypto in Rust AND TypeScript:** Pick one. Either use Rust-native crypto for all FUSE operations, or bridge everything to webview. Don't split crypto across both -- it doubles the attack surface and testing burden.
- **Synchronous FUSE + synchronous HTTP:** Never block the FUSE thread waiting for HTTP. Use tokio async runtime and reply asynchronously via fuser's reply mechanism.
- **Storing keys on disk:** Keys (privateKey, rootFolderKey, folderKeys) must remain in memory only. Only the refresh token goes to Keychain. Clear keys from memory on logout/quit.
- **Using HTTP-only cookies for desktop auth:** Tauri apps run on `tauri://localhost` which doesn't support secure cookies. The API needs a new endpoint or parameter to return the refresh token in the response body for desktop clients.

## Don't Hand-Roll

| Problem               | Don't Build                   | Use Instead                                 | Why                                           |
| --------------------- | ----------------------------- | ------------------------------------------- | --------------------------------------------- |
| macOS Keychain access | Custom Security.framework FFI | `keyring` crate with `apple-native` feature | Handles ACL, item classes, error codes        |
| FUSE mount/unmount    | Custom NFS or devfs           | `fuser` crate + FUSE-T                      | Kernel/userspace protocol is complex          |
| Deep link URL scheme  | Custom mach port listener     | `tauri-plugin-deep-link`                    | OS integration varies by version              |
| Auto-start on login   | Custom LaunchAgent plist      | `tauri-plugin-autostart`                    | Handles LaunchAgent creation/removal          |
| Tray icon management  | Custom NSStatusBar FFI        | Tauri `TrayIconBuilder`                     | Built into Tauri, handles menu lifecycle      |
| HTTP client in Rust   | Raw socket/hyper              | `reqwest`                                   | Connection pooling, TLS, redirects, multipart |
| AES-256-GCM in Rust   | Custom implementation         | `aes-gcm` crate (RustCrypto)                | Audited, constant-time, hardware-accelerated  |
| ECIES in Rust         | Custom ECDH+HKDF+AES          | `ecies` crate                               | Must verify format compatibility with eciesjs |
| App code signing      | Manual codesign               | Tauri's built-in signing                    | Handles entitlements, notarization            |

**Key insight:** The FUSE layer is the highest-risk custom code in this phase. Everything else should use established libraries. Budget most development time for the FUSE filesystem implementation and its interaction with the CipherBox API.

## Common Pitfalls

### Pitfall 1: FUSE-T READDIR Must Return All Results in First Pass

**What goes wrong:** FUSE-T's NFS backend does not support paginated readdir. If the filesystem returns partial results expecting subsequent calls with increasing offset, FUSE-T may not call back for remaining entries.
**Why it happens:** NFS protocol differences from native FUSE kernel module.
**How to avoid:** Always return ALL directory entries in a single `readdir` response. Pre-load folder metadata so readdir can respond synchronously from cache.
**Warning signs:** Directories appear empty or missing files in Finder.

### Pitfall 2: HTTP-Only Cookie Refresh Won't Work in Tauri

**What goes wrong:** The current backend sets refresh tokens via HTTP-only cookies scoped to `/auth`. Tauri apps run on `tauri://localhost`, and cookies don't work reliably on custom protocol origins.
**Why it happens:** Browser security model assumes HTTP/HTTPS origins. Tauri's custom protocol doesn't participate in cookie jar.
**How to avoid:** Add a new API endpoint or header flag for desktop clients: `POST /auth/refresh` should accept the refresh token in the request body (e.g., `Authorization: Bearer <refresh_token>` or a `{ refreshToken }` body field) when a `X-Client-Type: desktop` header is present. Alternatively, add a `POST /auth/refresh-desktop` endpoint that accepts the token in the body and returns the new refresh token in the response body. The desktop app stores this token in macOS Keychain.
**Warning signs:** Silent refresh always fails, user must re-login every session.

### Pitfall 3: FUSE Thread Blocking on Async Operations

**What goes wrong:** FUSE callbacks are invoked on fuser's worker threads. If you block these threads waiting for HTTP or crypto, FUSE operations stall and Finder shows spinning beachball.
**Why it happens:** fuser dispatches FUSE operations to a thread pool. Blocking all threads deadlocks the filesystem.
**How to avoid:** Use fuser's asynchronous reply pattern: store the `reply` object, spawn an async task on a shared tokio runtime, and call `reply.data()` / `reply.ok()` when the async work completes. Do NOT call `.await` on the FUSE thread directly.
**Warning signs:** Finder hangs when opening folders or files.

### Pitfall 4: FUSE-T Timestamp Limitations

**What goes wrong:** FUSE-T via NFS cannot set access time and modification time independently. `touch -m` and `touch -a` both modify both timestamps.
**Why it happens:** NFS protocol limitation in FUSE-T's implementation.
**How to avoid:** Accept this limitation for v1. Store authoritative timestamps in folder metadata (which CipherBox already does). Report metadata timestamps for `getattr`, don't try to honor `setattr` time modifications.
**Warning signs:** File modification times appear wrong after touch operations.

### Pitfall 5: File Locking Not Supported by FUSE-T

**What goes wrong:** `flock`, `lockf`, and `fcntl` locking calls bypass FUSE entirely when using FUSE-T.
**Why it happens:** FUSE-T explicitly does not implement file locking.
**How to avoid:** Accept this for v1 (last-write-wins is the decision from CONTEXT.md). Don't implement `getlk`/`setlk` in the Filesystem trait. If apps that require locking (e.g., SQLite databases) are placed in the vault, they may behave incorrectly -- document this limitation.
**Warning signs:** Database corruption if users store SQLite files in the vault.

### Pitfall 6: Deep Links Only Work in Bundled App

**What goes wrong:** Custom URL schemes (`cipherbox://`) don't work during development (`cargo tauri dev`). They only work when the app is bundled and installed in `/Applications`.
**Why it happens:** macOS registers URL schemes from the app bundle's Info.plist at install time. During dev, there's no installed bundle.
**How to avoid:** For development, implement a fallback localhost callback server (e.g., `http://localhost:19287/auth/callback`) that Web3Auth redirects to. The Tauri app starts a temporary HTTP server during dev mode. Switch to deep links only in production bundles.
**Warning signs:** Auth flow hangs during development because deep link never arrives.

### Pitfall 7: FUSE-T Requires "Network Volumes" System Setting

**What goes wrong:** FUSE-T mounts appear as NFS network volumes. macOS may require users to enable "Network Volumes" in System Settings > Privacy & Security.
**Why it happens:** FUSE-T uses NFS under the hood; macOS treats the mount as a network drive.
**How to avoid:** Document this in installation instructions. Detect mount failure and show a user-friendly notification with instructions to enable the setting. Check for FUSE-T installation at app startup and prompt if missing.
**Warning signs:** Mount fails silently or with cryptic NFS error.

### Pitfall 8: Inode Number Management

**What goes wrong:** FUSE requires stable inode numbers. If you assign inodes dynamically per session, Finder may cache stale attributes or show wrong files.
**Why it happens:** macOS aggressively caches file metadata keyed by inode number.
**How to avoid:** Use a deterministic inode assignment: hash the file/folder ID to a 64-bit inode number. Maintain an inode table that maps inode -> (folder_id, child_id). Ensure inodes are stable across sync updates.
**Warning signs:** Files show wrong names, sizes, or Finder shows ghost files.

## Code Examples

### Tauri App Entry Point

```rust
// src-tauri/src/main.rs
use tauri::tray::TrayIconBuilder;
use tauri::{menu::{Menu, MenuItem}, Manager};
use tauri_plugin_deep_link::DeepLinkExt;

#[tauri::command]
async fn decrypt_file(
    encrypted: Vec<u8>,
    file_key: Vec<u8>,
    iv: Vec<u8>,
) -> Result<Vec<u8>, String> {
    // Called from Rust FUSE layer -> invokes JS -> returns plaintext
    // Or better: use Rust-native aes-gcm crate directly
    todo!()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // Hide dock icon (menu bar only)
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Register deep link handler
            app.deep_link().on_open_url(|event| {
                dbg!(event.urls());
                // Parse cipherbox://auth/callback?token=...
                // Store token, trigger login flow
            });

            // Build tray
            let quit = MenuItem::with_id(app, "quit", "Quit CipherBox", true, None::<&str>)?;
            let open_vault = MenuItem::with_id(app, "open", "Open CipherVault", true, None::<&str>)?;
            let sync_now = MenuItem::with_id(app, "sync", "Sync Now", true, None::<&str>)?;
            let status = MenuItem::with_id(app, "status", "Status: Not Connected", false, None::<&str>)?;
            let logout = MenuItem::with_id(app, "logout", "Logout", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&status, &open_vault, &sync_now, &logout, &quit])?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .menu_on_left_click(true)
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "quit" => app.exit(0),
                        "open" => {
                            // Open ~/CipherVault in Finder
                            let _ = std::process::Command::new("open")
                                .arg(dirs::home_dir().unwrap().join("CipherVault"))
                                .spawn();
                        }
                        "sync" => { /* trigger manual sync */ }
                        "logout" => { /* unmount FUSE, clear keys, clear Keychain */ }
                        _ => {}
                    }
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![decrypt_file])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

### Keychain Storage (Rust)

```rust
// src-tauri/src/api/auth.rs
use keyring::Entry;

const SERVICE_NAME: &str = "com.cipherbox.desktop";

pub fn store_refresh_token(user_id: &str, token: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, user_id)
        .map_err(|e| format!("Keychain error: {}", e))?;
    entry.set_password(token)
        .map_err(|e| format!("Failed to store token: {}", e))?;
    Ok(())
}

pub fn get_refresh_token(user_id: &str) -> Result<Option<String>, String> {
    let entry = Entry::new(SERVICE_NAME, user_id)
        .map_err(|e| format!("Keychain error: {}", e))?;
    match entry.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to read token: {}", e)),
    }
}

pub fn delete_refresh_token(user_id: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, user_id)
        .map_err(|e| format!("Keychain error: {}", e))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // Already gone
        Err(e) => Err(format!("Failed to delete token: {}", e)),
    }
}
```

### FUSE Filesystem Skeleton (Rust)

```rust
// src-tauri/src/fuse/mod.rs
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEntry, ReplyOpen, ReplyWrite, ReplyEmpty,
    Request,
};
use std::ffi::OsStr;
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(1);

pub struct CipherVaultFS {
    // Inode table: inode -> metadata
    inodes: HashMap<u64, InodeData>,
    // Open file handles
    open_files: HashMap<u64, OpenFileHandle>,
    // API client for IPFS/IPNS
    api: ApiClient,
    // Tokio runtime for async operations
    rt: tokio::runtime::Handle,
    // Next file handle counter
    next_fh: AtomicU64,
}

impl Filesystem for CipherVaultFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // Look up child by name in parent's cached metadata
        let name_str = name.to_str().unwrap_or("");
        if let Some(child_ino) = self.find_child(parent, name_str) {
            if let Some(inode) = self.inodes.get(&child_ino) {
                reply.entry(&TTL, &inode.attr, 0);
                return;
            }
        }
        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if let Some(inode) = self.inodes.get(&ino) {
            reply.attr(&TTL, &inode.attr);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        // IMPORTANT: Return ALL entries in single pass (FUSE-T requirement)
        if let Some(inode) = self.inodes.get(&ino) {
            let entries = vec![
                (ino, FileType::Directory, "."),
                (inode.parent_ino, FileType::Directory, ".."),
            ];
            // Add children from cached metadata
            for (i, entry) in entries.iter().enumerate().skip(offset as usize) {
                if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                    break; // Buffer full
                }
            }
            // Add actual children...
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        // If writing, create temp file
        // If reading, fetch from IPFS on first read
        self.open_files.insert(fh, OpenFileHandle::new(ino, flags));
        reply.opened(fh, 0);
    }

    fn read(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock: Option<u64>, reply: ReplyData) {
        // Async: fetch from IPFS, decrypt, cache, return slice
        let rt = self.rt.clone();
        let api = self.api.clone();
        // Use reply asynchronously...
    }

    fn write(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock: Option<u64>, reply: ReplyWrite) {
        // Write to temp file, mark dirty
        if let Some(handle) = self.open_files.get_mut(&fh) {
            handle.write_at(offset, data);
            handle.dirty = true;
            reply.written(data.len() as u32);
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn release(&mut self, _req: &Request, ino: u64, fh: u64, _flags: i32, _lock: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        if let Some(handle) = self.open_files.remove(&fh) {
            if handle.dirty {
                // Encrypt and upload in background
                // Queue upload task
            }
        }
        reply.ok();
    }
}
```

### Background Sync (Rust)

```rust
// src-tauri/src/sync/mod.rs
use tokio::time::{interval, Duration};

pub struct SyncDaemon {
    api: ApiClient,
    root_ipns_name: String,
    cached_root_cid: Option<String>,
    poll_interval: Duration,
}

impl SyncDaemon {
    pub fn new(api: ApiClient, root_ipns_name: String) -> Self {
        Self {
            api,
            root_ipns_name,
            cached_root_cid: None,
            poll_interval: Duration::from_secs(30),
        }
    }

    pub async fn run(&mut self) {
        let mut ticker = interval(self.poll_interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.poll().await {
                eprintln!("Sync error: {}", e);
                // Exponential backoff on repeated failures
            }
        }
    }

    async fn poll(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let resolved = self.api.resolve_ipns(&self.root_ipns_name).await?;
        if Some(&resolved.cid) != self.cached_root_cid.as_ref() {
            self.cached_root_cid = Some(resolved.cid.clone());
            self.refresh_metadata_tree(&resolved.cid).await?;
        }
        Ok(())
    }
}
```

## State of the Art

| Old Approach                       | Current Approach                                  | When Changed                | Impact                                                      |
| ---------------------------------- | ------------------------------------------------- | --------------------------- | ----------------------------------------------------------- |
| macFUSE (kernel extension)         | FUSE-T (kext-less, NFS) or macFUSE FSKit          | 2023 (FUSE-T), 2025 (FSKit) | No kernel extension needed, easier install on Apple Silicon |
| Tauri v1 (single-process)          | Tauri v2 (plugin architecture, IPC redesign)      | Oct 2024 (v2.0 stable)      | Better plugin system, tray-icon feature, deep link plugin   |
| macOS kernel extensions encouraged | Apple discourages kexts, promotes DriverKit/FSKit | macOS 11+ (2020)            | FUSE-T is the practical alternative                         |
| keytar (Node.js native)            | keyring crate (Rust native)                       | 2024+                       | No Node.js dependency, direct Rust integration              |

**Deprecated/outdated:**

- **Tauri v1:** Use v2 exclusively. Plugin APIs changed significantly.
- **macFUSE kext on Apple Silicon:** Requires recovery mode to enable third-party kernel extensions. Avoid for user-facing apps.
- **fuse crate (zargony/fuse-rs):** Unmaintained predecessor to `fuser`. Use `fuser` instead.

## Open Questions

### 1. FUSE-T + fuser Crate Compatibility

- **What we know:** FUSE-T is a "drop-in replacement" for macFUSE at the libfuse API level. `fuser` is a pure Rust reimplementation that optionally uses libfuse for mount/unmount only.
- **What's unclear:** Whether `fuser` compiled against FUSE-T headers (instead of macFUSE) works correctly. The `fuser` README says macOS support is "untested." FUSE-T provides its own `libfuse-t.dylib` that is API-compatible.
- **Recommendation:** This is the highest-risk integration point. Create a minimal proof-of-concept FUSE filesystem in Rust using `fuser` + FUSE-T on macOS before planning detailed tasks. If it doesn't work, alternatives include: (a) using fuser with macFUSE, (b) using the `fuse3` crate, (c) using C libfuse directly with Rust FFI, or (d) implementing a WebDAV local server instead of FUSE.

### 2. eciesjs to ecies Crate Format Compatibility

- **What we know:** `@cipherbox/crypto` uses `eciesjs` (npm) for ECIES wrapping with secp256k1. The Rust `ecies` crate does the same thing.
- **What's unclear:** Whether the output format is byte-identical (ephemeral pubkey || nonce || ciphertext || tag). Different ECIES implementations may use different KDF parameters, padding, or serialization.
- **Recommendation:** Write cross-language test vectors: encrypt with `eciesjs` in TypeScript, decrypt with `ecies` in Rust, and vice versa. If formats differ, either (a) add a compatibility layer or (b) keep crypto in the webview and bridge via IPC.

### 3. API Modification for Desktop Refresh Tokens

- **What we know:** The current API returns refresh tokens only in HTTP-only cookies (`Set-Cookie` header). Desktop apps can't reliably use cookies.
- **What's unclear:** Whether to add a new endpoint (`/auth/refresh-desktop`) or modify the existing endpoint to accept/return tokens in the body when a desktop client header is present.
- **Recommendation:** Add a `X-Client-Type: desktop` header. When present, `/auth/login` returns `{ accessToken, refreshToken }` in the response body (instead of cookie), and `/auth/refresh` accepts `{ refreshToken }` in the body. This is a small API change in Phase 9.

### 4. Web3Auth Desktop SDK Availability

- **What we know:** Web3Auth has web and mobile SDKs. The web SDK runs in a browser context.
- **What's unclear:** Whether Web3Auth has a native desktop SDK or if we must use the system browser redirect approach.
- **Recommendation:** Use system browser redirect (as decided in CONTEXT.md). Open the Web3Auth login page in the user's default browser, receive the callback via deep link. The Web3Auth `idToken` is passed in the deep link URL parameters.

### 5. Mount Point Location with FUSE-T

- **What we know:** FUSE-T uses NFS backend. macFUSE FSKit is limited to `/Volumes` mount points.
- **What's unclear:** Whether FUSE-T's NFS backend allows mounting at `~/CipherVault` (user home directory) or if NFS mounts are also restricted.
- **Recommendation:** Test this in the proof-of-concept. If `~/CipherVault` is not possible, fall back to `/Volumes/CipherVault` and create a symlink at `~/CipherVault`.

## Sources

### Primary (HIGH confidence)

- [Tauri v2 System Tray](https://v2.tauri.app/learn/system-tray/) - Tray icon setup, menu building, event handling
- [Tauri v2 Deep Linking](https://v2.tauri.app/plugin/deep-linking/) - Custom URL scheme registration, macOS-specific behavior
- [Tauri v2 Autostart](https://v2.tauri.app/plugin/autostart/) - LaunchAgent setup for macOS
- [Tauri v2 Calling Rust](https://v2.tauri.app/develop/calling-rust/) - IPC command pattern
- [Tauri v2 macOS Code Signing](https://v2.tauri.app/distribute/sign/macos/) - Distribution requirements
- [fuser crate on crates.io](https://crates.io/crates/fuser) - v0.16.0, Rust FUSE implementation
- [fuser Filesystem trait](https://docs.rs/fuser/latest/fuser/trait.Filesystem.html) - 41 FUSE operations
- [keyring crate](https://crates.io/crates/keyring) - v3.6.x, macOS Keychain via apple-native feature

### Secondary (MEDIUM confidence)

- [FUSE-T Website](https://www.fuse-t.org/) - Kext-less FUSE, NFS backend, drop-in replacement
- [FUSE-T GitHub Wiki](https://github.com/macos-fuse-t/fuse-t/wiki) - Unsupported operations, limitations, NFS quirks
- [FUSE-T GitHub](https://github.com/macos-fuse-t/fuse-t) - Latest releases, compatibility info
- [Tauri macOS dock icon discussions](https://github.com/tauri-apps/tauri/discussions/10774) - ActivationPolicy::Accessory pattern
- [macFUSE FSKit backend](https://macfuse.github.io/) - FSKit on macOS 26, /Volumes restriction

### Tertiary (LOW confidence)

- fuser + FUSE-T integration compatibility (no verified source; needs PoC testing)
- eciesjs to ecies Rust crate format compatibility (no verified cross-language test vectors found)
- Web3Auth desktop SDK existence/approach (could not find desktop-specific SDK documentation)

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - Tauri v2 is stable (2.10.x), well-documented. fuser and keyring are established crates.
- Architecture: MEDIUM - Dual-layer (Rust FUSE + webview crypto) is sound in theory, but Rust-native crypto is recommended instead. The key question is fuser+FUSE-T compatibility on macOS.
- Pitfalls: HIGH - FUSE-T limitations are well-documented in their wiki. Cookie issues are confirmed by Tauri community. Deep link dev limitations are documented.
- FUSE integration: LOW - fuser README says macOS is "untested." FUSE-T compatibility with fuser is unverified. This requires a proof-of-concept before detailed planning.

**Research date:** 2026-02-07
**Valid until:** 2026-03-07 (Tauri and fuser are actively developed; check for breaking changes)
