# Phase 11: Windows Desktop - Research

**Researched:** 2026-02-22
**Domain:** Windows desktop filesystem integration (WinFsp, Tauri NSIS, Windows system integration)
**Confidence:** MEDIUM-HIGH

## Summary

This phase ports the existing macOS CipherBox desktop app to Windows. The core challenge is replacing the macOS FUSE layer (fuser + FUSE-T) with WinFsp while reusing as much platform-agnostic code as possible. The existing codebase already has a clean separation between platform-dependent FUSE callbacks (`operations.rs`) and platform-agnostic data structures (`inode.rs`, `cache.rs`, `file_handle.rs`).

The `winfsp` Rust crate (v0.12.4) provides safe bindings to WinFsp with a `FileSystemContext` trait that maps well to the existing `fuser::Filesystem` trait, though with significant API differences. The biggest architectural difference is that WinFsp's `FileContext` is accessed via shared immutable references (requiring interior mutability), while fuser's `Filesystem` trait uses `&mut self`. The existing codebase's channel-based async architecture (refresh_tx/rx, content_tx/rx, upload_tx/rx) translates well to WinFsp since the same principle applies: never block the filesystem thread on network I/O.

**Primary recommendation:** Create a platform abstraction layer with `#[cfg(target_os = "macos")]` and `#[cfg(target_os = "windows")]` modules sharing the same `CipherBoxFS` core struct, inode table, caches, and publish coordinator. The WinFsp implementation wraps the shared state in `Arc<Mutex<CipherBoxFS>>` to satisfy the `&self` + interior mutability requirement.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `winfsp` | 0.12.4 | WinFsp Rust bindings for Windows filesystem | Only mature Rust WinFsp crate; SnowflakePowered actively maintained; passes ntptfs test suite |
| `winfsp-sys` | (dep of winfsp) | Raw FFI bindings to WinFsp | Transitive dependency of `winfsp` |
| `tauri` | 2.x | Application framework (already in use) | Already the app framework |
| `tauri-plugin-autostart` | 2.x | Auto-start on login (already in use) | Uses Windows Registry `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| `keyring` | 3.x | Credential storage (already in use) | Windows Credential Manager backend via `windows-native` feature |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| WinFsp driver | 2.1.25156 (MSI) | Kernel-mode filesystem driver | Bundled in NSIS installer, silently installed |
| `tauri-plugin-notification` | 2.x | System notifications (already in use) | Windows toast notifications |
| `tauri-plugin-shell` | 2.x | Open file manager (already in use) | Opens `explorer.exe` instead of Finder |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| WinFsp | ProjFS (Windows Projected FS) | Built-in to Windows 10+, but Rust crate has 5 GitHub stars, no releases, minimal docs. Not production-ready. |
| WinFsp | Dokan | More FUSE-like API, but winfsp crate is more mature and has better Rust support |
| Folder mount | Drive letter mount | Drive letters are simpler but harder to test (allocation/deallocation), inconsistent with macOS `~/CipherBox` pattern |

### Installation (build dependencies)
```toml
# Cargo.toml additions for Windows
[target.'cfg(windows)'.dependencies]
winfsp = { version = "0.12", features = [] }

[target.'cfg(windows)'.build-dependencies]
winfsp = "0.12"  # for winfsp::build::winfsp_link_delayload()
```

### License Consideration
WinFsp and winfsp-rs are GPLv3 licensed. WinFsp has a FLOSS exception allowing linking from Free/Open Source software. CipherBox is a technology demonstrator, not a commercial product, so this is acceptable. If commercial licensing is ever needed, WinFsp offers a commercial license option.

**Confidence: HIGH** - Verified via crates.io, docs.rs, and GitHub repository.

## Architecture Patterns

### Recommended Project Structure
```
apps/desktop/src-tauri/src/
├── api/             # API client (unchanged, platform-agnostic)
├── commands.rs      # Tauri IPC commands (minor platform branching)
├── crypto/          # Encryption (unchanged, platform-agnostic)
├── fs/              # NEW: Platform abstraction layer
│   ├── mod.rs       # Re-exports, mount_filesystem(), unmount_filesystem()
│   ├── common.rs    # CipherBoxFS struct, shared logic (moved from fuse/mod.rs)
│   ├── inode.rs     # InodeTable (moved from fuse/inode.rs, remove fuser dep)
│   ├── cache.rs     # MetadataCache, ContentCache (moved from fuse/cache.rs)
│   ├── file_handle.rs  # OpenFileHandle (moved from fuse/file_handle.rs)
│   ├── macos/       # macOS FUSE-T implementation
│   │   ├── mod.rs   # mount/unmount using fuser
│   │   └── operations.rs  # fuser::Filesystem impl
│   └── windows/     # WinFsp implementation
│       ├── mod.rs   # mount/unmount using winfsp service
│       └── operations.rs  # FileSystemContext impl
├── main.rs          # Entry point (platform branching for activation policy, etc.)
├── registry/        # Device registry (unchanged)
├── state.rs         # AppState (unchanged)
├── sync/            # Sync daemon (unchanged)
└── tray/            # System tray (minor platform branching)
    ├── mod.rs       # Platform-branched "Open" handler (explorer vs Finder)
    └── status.rs    # TrayStatus (unchanged)
```

### Pattern 1: Platform Abstraction via cfg Modules

**What:** Use `#[cfg(target_os)]` to switch between macOS and Windows filesystem implementations while sharing the core `CipherBoxFS` struct, inode table, caches, and publish coordinator.

**When to use:** All filesystem code that interacts with the OS filesystem driver API.

**Example:**
```rust
// fs/mod.rs
mod common;
mod inode;
mod cache;
mod file_handle;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub use common::CipherBoxFS;
pub use inode::{InodeTable, InodeData, InodeKind, ROOT_INO};
pub use cache::{MetadataCache, ContentCache};
pub use file_handle::OpenFileHandle;

// Platform-agnostic mount/unmount API
pub fn mount_point() -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    { dirs::home_dir().unwrap().join("CipherBox") }
    #[cfg(target_os = "windows")]
    { dirs::home_dir().unwrap().join("CipherBox") }
}

#[cfg(target_os = "macos")]
pub use macos::{mount_filesystem, unmount_filesystem};
#[cfg(target_os = "windows")]
pub use windows::{mount_filesystem, unmount_filesystem};
```

### Pattern 2: WinFsp FileSystemContext with Interior Mutability

**What:** WinFsp's `FileSystemContext` trait receives `&self` (not `&mut self`) for all callbacks because the driver can invoke callbacks on any thread. Use `Arc<Mutex<CipherBoxFS>>` for the shared state.

**When to use:** The Windows filesystem implementation.

**Example:**
```rust
// fs/windows/operations.rs
use std::sync::{Arc, Mutex};
use winfsp::filesystem::FileSystemContext;

pub struct WinFspContext {
    inner: Arc<Mutex<CipherBoxFS>>,
    rt: tokio::runtime::Handle,
}

// FileContext for open files - must use interior mutability
pub struct WinFspFileContext {
    fh: u64,  // file handle ID into CipherBoxFS.open_files
    ino: u64,
}

impl FileSystemContext for WinFspContext {
    type FileContext = WinFspFileContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let fs = self.inner.lock().unwrap();
        // Convert Windows path to inode lookup
        let path = file_name.to_string_lossy();
        // ... lookup inode, return attributes
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let mut fs = self.inner.lock().unwrap();
        // Convert path to inode, create file handle
        // ... similar to fuser open() but with Windows path semantics
    }

    fn close(&self, context: Self::FileContext) {
        let mut fs = self.inner.lock().unwrap();
        // Release file handle, trigger upload if dirty
    }

    // ... other callbacks
}
```

### Pattern 3: WinFsp Service Architecture for Lifecycle Management

**What:** WinFsp recommends using its service architecture to manage the filesystem host lifecycle. The service handles start/stop/cleanup automatically.

**When to use:** Mounting and unmounting the filesystem.

**Example:**
```rust
use winfsp::host::{FileSystemHost, FileSystemParams, VolumeParams};
use winfsp::service::FileSystemServiceBuilder;

pub fn mount_filesystem(/* ... */) -> Result<JoinHandle<()>, String> {
    // Initialize WinFsp
    let _init = winfsp::winfsp_init_or_die();

    let mut volume_params = VolumeParams::new();
    volume_params
        .prefix("")  // local filesystem, not network
        .filesystem_name("CipherBox")
        .file_info_timeout(1000);  // 1s attribute cache

    let context = WinFspContext::new(/* ... */);

    let host = FileSystemHost::new(
        FileSystemParams::new(volume_params),
        context,
    ).map_err(|e| format!("Failed to create filesystem host: {:?}", e))?;

    // Mount at C:\Users\<user>\CipherBox
    let mount_path = mount_point();
    host.mount(&mount_path)
        .map_err(|e| format!("Failed to mount: {:?}", e))?;

    // Spawn filesystem event loop on dedicated thread
    let handle = std::thread::Builder::new()
        .name("winfsp-mount".to_string())
        .spawn(move || {
            host.start(); // Blocks until unmount
        })
        .map_err(|e| format!("Failed to spawn WinFsp thread: {}", e))?;

    Ok(handle)
}
```

### Pattern 4: Windows Path to Inode Translation

**What:** WinFsp passes full Windows-style paths (`\folder\file.txt`) to callbacks, while the inode table uses parent_ino + name lookups. Need a path-to-inode translation layer.

**When to use:** Every WinFsp callback that receives a file_name parameter.

**Example:**
```rust
/// Resolve a Windows-style path (\folder\subfolder\file.txt) to an inode number.
/// Returns (ino, parent_ino) or None if not found.
fn resolve_path(fs: &CipherBoxFS, path: &str) -> Option<(u64, u64)> {
    let path = path.trim_start_matches('\\');
    if path.is_empty() {
        return Some((ROOT_INO, ROOT_INO));
    }

    let mut current_ino = ROOT_INO;
    let components: Vec<&str> = path.split('\\').collect();
    let mut parent_ino = ROOT_INO;

    for component in &components {
        parent_ino = current_ino;
        match fs.inodes.find_child(current_ino, component) {
            Some(child_ino) => current_ino = child_ino,
            None => return None,
        }
    }

    Some((current_ino, parent_ino))
}
```

### Anti-Patterns to Avoid
- **Using `&mut self` in WinFsp context:** WinFsp explicitly requires `&self` with interior mutability. Trying to force `&mut self` will cause undefined behavior due to concurrent callback invocation.
- **Blocking on network I/O in WinFsp callbacks:** Same principle as macOS FUSE-T. Use the channel-based prefetch architecture. WinFsp supports multithreading but blocking still degrades responsiveness.
- **Creating mount directory before WinFsp:** WinFsp-FUSE creates and later deletes directories used as mount points (reparse point mechanism). The directory must NOT exist before mounting. This is opposite to macOS where we create the directory first.
- **Using `libc::getuid()`/`libc::getgid()` on Windows:** These don't exist on Windows. Use Windows security descriptors or hardcoded values for file attributes.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Windows Credential Manager | Custom Windows API calls | `keyring` crate v3 with `windows-native` feature | Already used on macOS, cross-platform API, handles Windows Credential Manager natively |
| Auto-start on login | Direct registry manipulation | `tauri-plugin-autostart` v2 | Already used on macOS, handles Windows Registry `HKCU\...\Run` automatically |
| System notifications | Windows toast API | `tauri-plugin-notification` v2 | Already used on macOS, cross-platform |
| NSIS installer | Custom NSIS scripts from scratch | Tauri's built-in NSIS bundler with `installerHooks` for WinFsp | Tauri generates the main NSIS script; only need a hook for WinFsp MSI |
| WinFsp MSI bundling | Custom driver installer | `msiexec /i` in NSIS `NSIS_HOOK_PREINSTALL` macro | Standard Windows pattern for bundling MSI dependencies |
| Windows path handling | Custom path parser | `U16CStr` from winfsp + `std::path::Path` | WinFsp provides UTF-16 path types; `Path` handles backslash/forward slash |

**Key insight:** Most platform features (tray, autostart, keyring, notifications) are already abstracted by Tauri plugins and the keyring crate. The only truly new code is the WinFsp filesystem implementation.

## Common Pitfalls

### Pitfall 1: WinFsp Mount Point Must Not Pre-Exist
**What goes wrong:** WinFsp-FUSE creates a reparse point (junction) at the mount path. If the directory already exists, it fails. Windows NTFS also disallows mountpoint reparse points on non-empty directories.
**Why it happens:** Different from macOS FUSE where you create the directory first, then mount into it.
**How to avoid:** On Windows, check if mount point exists. If it does AND is not a reparse point, it's stale from a crash -- remove it. If it's a reparse point from a previous mount, remove the reparse point. Then let WinFsp create the directory.
**Warning signs:** Mount failure with "directory already exists" or "reparse point" errors.

### Pitfall 2: WinFsp FileContext Interior Mutability
**What goes wrong:** The `FileContext` associated type is only accessible through `&self` (shared reference). Attempting to mutate state causes compile errors or requires unsafe code.
**Why it happens:** WinFsp calls callbacks on any thread; Rust's aliasing rules prevent `&mut` guarantees across threads.
**How to avoid:** Use `Arc<Mutex<CipherBoxFS>>` for the main state. The `FileContext` type should be a lightweight handle (inode + file handle ID) that indexes into the locked state.
**Warning signs:** Compile errors about mutable borrows through shared references.

### Pitfall 3: Windows Platform Special Files
**What goes wrong:** Windows Explorer probes every directory with `desktop.ini`, `Thumbs.db`, `$RECYCLE.BIN`, and Zone.Identifier alternate data streams. Without filtering, these generate errors or create unwanted files.
**Why it happens:** Different platform special files than macOS (which has `.DS_Store`, `._*`, `.Spotlight-V100`).
**How to avoid:** Update `is_platform_special()` for Windows. Filter: `desktop.ini`, `Thumbs.db`, `$RECYCLE.BIN`, `System Volume Information`, `RECYCLER`, files with `:Zone.Identifier` ADS suffix, `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`. Return `STATUS_OBJECT_NAME_NOT_FOUND` in `get_security_by_name` for these.
**Warning signs:** Spurious file creation attempts, error logs for system files.

### Pitfall 4: WinFsp Uses Full Paths, Not Parent+Name
**What goes wrong:** fuser callbacks receive `(parent_ino, name)` pairs. WinFsp callbacks receive full paths like `\Documents\file.txt`. The entire lookup model differs.
**Why it happens:** Different API design philosophy between FUSE (inode-based) and WinFsp (path-based).
**How to avoid:** Create a `resolve_path()` helper that walks the inode table component-by-component from the root. Cache recent path resolutions for performance.
**Warning signs:** Every operation requires full path traversal; performance degradation with deep hierarchies.

### Pitfall 5: No `libc` on Windows
**What goes wrong:** The existing code uses `libc::getuid()`, `libc::getgid()`, `libc::O_RDONLY`, `libc::ENOENT`, etc. None of these exist on Windows.
**Why it happens:** macOS-specific POSIX assumptions throughout the FUSE layer.
**How to avoid:** The inode table's `FileAttr` type is fuser-specific (includes uid/gid/perm). On Windows, replace with a platform-agnostic attribute struct or use `#[cfg]` to use different attr types. WinFsp uses `FileInfo` with Windows-style timestamps (FILETIME) and attributes (FILE_ATTRIBUTE_DIRECTORY, etc.).
**Warning signs:** Compilation failures referencing `libc` functions on `cfg(windows)`.

### Pitfall 6: Keyring "Already Exists" on Windows
**What goes wrong:** The keyring crate may fail when overwriting existing credentials, similar to the macOS Keychain issue documented in learnings.
**Why it happens:** Windows Credential Manager has its own semantics for credential updates.
**How to avoid:** Use the same delete-before-set pattern already used on macOS. The keyring crate's cross-platform API should handle this, but test explicitly.
**Warning signs:** Intermittent credential storage failures.

### Pitfall 7: WinFsp Unmount on Windows
**What goes wrong:** On macOS, we use `umount` / `diskutil unmount force`. These don't exist on Windows.
**Why it happens:** Different OS unmount mechanisms.
**How to avoid:** Use WinFsp's own shutdown mechanism: `FileSystemHost::stop()` or signal the filesystem service to stop. For crash recovery, WinFsp's `FILE_FLAG_DELETE_ON_CLOSE` on the mount directory should handle cleanup automatically.
**Warning signs:** Stale mount points after crashes.

### Pitfall 8: NSIS WinFsp Driver Must Install Before App Runs
**What goes wrong:** The CipherBox app links against WinFsp DLL at runtime. If WinFsp isn't installed, the app crashes.
**Why it happens:** WinFsp is a separate kernel-mode driver that must be installed system-wide.
**How to avoid:** Use NSIS `NSIS_HOOK_PREINSTALL` to run `msiexec /i winfsp-2.1.25156.msi /qn INSTALLLEVEL=1000` before copying CipherBox files. Also check for existing WinFsp installation and skip if already present.
**Warning signs:** App crashes on launch with "DLL not found" errors.

## Code Examples

### WinFsp build.rs Configuration
```rust
// build.rs (Windows-specific)
fn main() {
    tauri_build::build();
    #[cfg(target_os = "windows")]
    {
        winfsp::build::winfsp_link_delayload();
    }
}
```

### NSIS Hook for WinFsp Bundling
```nsis
; src-tauri/windows/installer-hooks.nsh

!macro NSIS_HOOK_PREINSTALL
  ; Check if WinFsp is already installed
  ReadRegStr $0 HKLM "SOFTWARE\WinFsp" "InstallDir"
  ${If} $0 == ""
    ; WinFsp not installed -- install it silently
    DetailPrint "Installing WinFsp filesystem driver..."
    ExecWait '"msiexec" /i "$INSTDIR\resources\winfsp-2.1.25156.msi" /qn INSTALLLEVEL=1000'
    Pop $0
    ${If} $0 != 0
      MessageBox MB_OK|MB_ICONSTYLE "WinFsp installation failed. CipherBox requires WinFsp for virtual drive functionality."
    ${EndIf}
  ${Else}
    DetailPrint "WinFsp already installed at $0"
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Optionally uninstall WinFsp when CipherBox is removed
  ; Skip if other apps might use it
  ; ReadRegStr $0 HKLM "SOFTWARE\WinFsp" "InstallDir"
  ; ${If} $0 != ""
  ;   ExecWait '"msiexec" /x "$INSTDIR\resources\winfsp-2.1.25156.msi" /qn'
  ; ${EndIf}
!macroend
```

### tauri.conf.json Windows Configuration
```json
{
  "bundle": {
    "targets": ["nsis"],
    "windows": {
      "certificateThumbprint": null,
      "digestAlgorithm": "sha256",
      "timestampUrl": "http://timestamp.comodoca.com"
    },
    "nsis": {
      "installMode": "both",
      "installerHooks": "windows/installer-hooks.nsh"
    },
    "resources": [
      "resources/winfsp-2.1.25156.msi"
    ]
  }
}
```

### Platform-Branched Tray "Open" Handler
```rust
"open" => {
    let mount_point = dirs::home_dir()
        .map(|h| h.join("CipherBox"))
        .unwrap_or_default();

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(mount_point.to_str().unwrap())
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer.exe")
            .arg(mount_point.to_str().unwrap())
            .spawn();
    }
}
```

### Platform-Branched Autostart Init
```rust
// main.rs
.plugin(tauri_plugin_autostart::init(
    #[cfg(target_os = "macos")]
    tauri_plugin_autostart::MacosLauncher::LaunchAgent,
    #[cfg(target_os = "windows")]
    tauri_plugin_autostart::MacosLauncher::LaunchAgent, // Plugin handles Windows internally
    None,
))
```
Note: `tauri-plugin-autostart` handles Windows via Registry automatically. The `MacosLauncher` enum is misleadingly named -- on Windows the launcher parameter is ignored and the plugin uses the Registry.

### InodeTable Platform Abstraction
```rust
// fs/inode.rs - Remove fuser dependency from InodeData

/// Platform-agnostic file attributes.
#[derive(Debug, Clone)]
pub struct FileAttrs {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub crtime: SystemTime,
    pub is_dir: bool,
    pub perm: u16,
    pub nlink: u32,
}

// Then convert to platform-specific types in the operations modules:
// macOS: FileAttrs -> fuser::FileAttr (with uid/gid from libc::getuid())
// Windows: FileAttrs -> winfsp::filesystem::FileInfo (with FILETIME timestamps)
```

### GitHub Actions Windows CI Job
```yaml
build-windows:
  name: Build Windows Desktop
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4

    - name: Install WinFsp
      shell: powershell
      run: |
        choco install winfsp -y --params '/InstallDir:C:\WinFsp'
        # Or: winget install WinFsp.WinFsp --accept-package-agreements --silent

    - uses: dtolnay/rust-toolchain@stable

    - uses: swatinem/rust-cache@v2
      with:
        workspaces: apps/desktop/src-tauri

    - uses: pnpm/action-setup@v4
      with:
        version: 10

    - uses: actions/setup-node@v4
      with:
        node-version: '22'
        cache: 'pnpm'

    - name: Install dependencies
      run: pnpm install --frozen-lockfile

    - name: Build Windows desktop
      run: pnpm --filter desktop tauri build
      env:
        # Code signing env vars (from secrets)
        WINDOWS_CERTIFICATE: ${{ secrets.WINDOWS_CERTIFICATE }}
        WINDOWS_CERTIFICATE_PASSWORD: ${{ secrets.WINDOWS_CERTIFICATE_PASSWORD }}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| macFUSE kernel extension | FUSE-T (userspace NFS/SMB) | macOS deprecated kexts | macOS-specific; Windows uses WinFsp which is native kernel minifilter |
| WinFsp 1.x | WinFsp 2.1 (2025) | 2024-2025 | Uninstall/reinstall without reboot; better antivirus compatibility |
| EV cert = instant SmartScreen trust | EV cert = organic reputation building | March 2024 | Both OV and EV require time to build SmartScreen reputation; EV no longer instant bypass |
| `winfsp` crate 0.11 | `winfsp` crate 0.12.4 | Oct 2025 | Requires Rust 1.87+; new `handle-util` feature; improved safety |

**Deprecated/outdated:**
- **macFUSE kernel extensions on macOS:** Apple deprecated kexts. Project uses FUSE-T already.
- **WinFsp 1.x series:** Should use 2.x for no-reboot install/uninstall support.
- **EV certificates for instant SmartScreen bypass:** As of March 2024, even EV certs require organic reputation building. Cost ($400+) may not be justified for a technology demonstrator.

## Open Questions

1. **WinFsp mount to existing directory**
   - What we know: WinFsp-FUSE creates mount point directories and uses reparse points (junctions). The directory must not pre-exist.
   - What's unclear: The `winfsp` Rust crate's `FileSystemHost` may handle this differently from WinFsp-FUSE. Need to verify whether the crate creates the directory automatically or requires manual setup.
   - Recommendation: Test during implementation. If WinFsp creates the directory, adjust `mount_filesystem()` to only clean up stale mount points (remove reparse points) rather than pre-creating them.

2. **WinFsp concurrent callback threading model**
   - What we know: WinFsp can invoke callbacks on any thread (documented requirement for interior mutability). The macOS FUSE-T model is single-threaded.
   - What's unclear: Whether WinFsp defaults to single-threaded or multi-threaded dispatch. If multi-threaded, the `Mutex` approach works but may need more granular locking for performance.
   - Recommendation: Start with `Arc<Mutex<CipherBoxFS>>` (coarse-grained locking). Profile and optimize if contention becomes an issue.

3. **Code signing certificate cost vs. value**
   - What we know: OV certificates are cheaper ($100-200/yr). EV certificates cost $400+/yr and require hardware tokens. Neither provides instant SmartScreen bypass since March 2024.
   - What's unclear: Whether the SmartScreen warning is acceptable for a technology demonstrator, or if code signing is required.
   - Recommendation: Start without code signing for development. Add OV certificate if distributing to users. Skip EV -- not worth the cost for a demo project.

4. **WinFsp delayload and runtime detection**
   - What we know: WinFsp requires delayloading (`winfsp_link_delayload()` in build.rs). This means the DLL is loaded at runtime, not link time.
   - What's unclear: How the app should handle the case where WinFsp is not installed (user bypassed the installer, or uninstalled WinFsp after installing CipherBox).
   - Recommendation: On app startup, check WinFsp registry key (`HKLM\SOFTWARE\WinFsp\InstallDir`). If missing, show a dialog asking the user to reinstall CipherBox or install WinFsp manually.

5. **InodeData abstraction cost**
   - What we know: `InodeData` currently embeds `fuser::FileAttr` which has macOS-specific fields (uid, gid, crtime, etc.). Extracting to a platform-agnostic struct requires touching many files.
   - What's unclear: Whether to create a fully platform-agnostic `FileAttrs` struct or use `#[cfg]` on the `FileAttr` field itself.
   - Recommendation: Create a platform-agnostic `FileAttrs` struct as shown in Code Examples. This is cleaner and avoids `#[cfg]` sprinkled throughout the inode code. Convert to platform-specific types at the operations layer boundary.

## Mapping: Existing macOS FUSE Callbacks to WinFsp

| macOS (fuser::Filesystem) | WinFsp (FileSystemContext) | Notes |
|---|---|---|
| `init()` | (constructor) | WinFsp has no init callback; initialization happens when creating FileSystemHost |
| `destroy()` | `dispatcher_stopped()` | Cleanup on unmount |
| `lookup(parent, name)` | `get_security_by_name(path)` | WinFsp is path-based; combines lookup + getattr |
| `getattr(ino)` | `get_file_info(context)` | WinFsp requires open handle; info returned with open/create |
| `setattr(ino, ...)` | `set_basic_info(context, ...)` + `set_file_size(context, ...)` | Split into separate calls |
| `readdir(ino, offset)` | `read_directory(context, pattern, marker)` | WinFsp uses pattern matching + continuation marker |
| `create(parent, name, ...)` | `create(path, ...)` | Full path instead of parent+name |
| `open(ino, flags)` | `open(path, opts, access)` | Full path; access rights are Windows-style |
| `read(ino, fh, offset, size)` | `read(context, buffer, offset)` | Context is FileContext, not inode |
| `write(ino, fh, offset, data)` | `write(context, buffer, offset, ...)` | Context-based; returns bytes written |
| `release(ino, fh, flags)` | `cleanup(context, path, flags)` + `close(context)` | Split into cleanup (flush) + close (free) |
| `flush(ino, fh)` | `flush(context)` | Similar semantics |
| `unlink(parent, name)` | `set_delete(context, true)` + `cleanup()` | WinFsp uses mark-for-delete pattern |
| `mkdir(parent, name, mode)` | `create(path, FILE_DIRECTORY_FILE, ...)` | Directory creation via create with flag |
| `rmdir(parent, name)` | `set_delete(context, true)` + `cleanup()` | Same as unlink |
| `rename(parent, name, newparent, newname)` | `rename(context, path, new_path, replace)` | Full paths |
| `statfs(ino)` | `get_volume_info()` | Volume-level stats |
| `access(ino, mask)` | `get_security_by_name(path)` | Security check via NTFS security descriptors |
| `opendir(ino)` | `open(path, FILE_DIRECTORY_FILE)` | Directories opened like files |

## Shared vs. Platform-Specific Code Analysis

Based on existing codebase analysis:

### Fully Reusable (No Changes)
- `crypto/` -- All encryption is platform-agnostic (AES-GCM, ECIES, HKDF, IPNS)
- `api/` -- HTTP API client, IPFS/IPNS operations
- `state.rs` -- AppState struct (uses tokio::RwLock, no OS deps)
- `sync/` -- Background sync daemon
- `registry/` -- Device registry
- `cache.rs` -- MetadataCache, ContentCache (uses std only)
- `file_handle.rs` -- OpenFileHandle (only needs `#[cfg(unix)]` guard removed for permission setting)

### Needs Platform Abstraction
- `inode.rs` -- Uses `fuser::FileAttr`, `fuser::FileType`, `libc::getuid()` / `libc::getgid()`. Need platform-agnostic FileAttrs struct.
- `fuse/mod.rs` -- CipherBoxFS struct references `fuser::MountOption`. Shared logic (publish, drain, queue) is platform-agnostic but mount/unmount is platform-specific.
- `operations.rs` -- Entirely platform-specific (implements `fuser::Filesystem`). WinFsp needs its own operations.rs implementing `FileSystemContext`.

### Needs Minor Platform Branching
- `main.rs` -- `#[cfg(target_os = "macos")] set_activation_policy(Accessory)` (Windows doesn't need this). Autostart plugin init param.
- `tray/mod.rs` -- "Open" handler uses `open` command (macOS) vs `explorer.exe` (Windows). Unmount uses `umount` / `diskutil` (macOS) vs WinFsp stop (Windows).
- `commands.rs` -- Mount/unmount function calls need to dispatch to platform module.

## Sources

### Primary (HIGH confidence)
- [winfsp crate 0.12.4 docs](https://docs.rs/winfsp/0.12.4+winfsp-2.1/winfsp/) -- FileSystemContext trait, FileSystemHost, service architecture
- [winfsp-rs GitHub](https://github.com/SnowflakePowered/winfsp-rs) -- Build requirements, examples, license
- [WinFsp FAQ](https://winfsp.dev/doc/Frequently-Asked-Questions/) -- Mount point behavior, reparse points
- [Tauri v2 Windows Installer docs](https://v2.tauri.app/distribute/windows-installer/) -- NSIS config, installer hooks
- [Tauri v2 Windows Code Signing](https://v2.tauri.app/distribute/sign/windows/) -- OV/EV cert setup, GitHub Actions
- Existing codebase analysis (HIGH) -- `apps/desktop/src-tauri/src/` full review

### Secondary (MEDIUM confidence)
- [keyring crate Windows support](https://docs.rs/keyring/latest/x86_64-pc-windows-msvc/keyring/windows/index.html) -- Windows Credential Manager backend
- [tauri-plugin-autostart](https://v2.tauri.app/plugin/autostart/) -- Windows Registry auto-start
- [WinFsp releases](https://github.com/winfsp/winfsp/releases) -- v2.1.25156 MSI
- [WinFsp commercial license](https://winfsp.dev/com/) -- GPL/FLOSS exception details

### Tertiary (LOW confidence)
- WebSearch results for WinFsp + GitHub Actions CI patterns -- no authoritative source found; recommended pattern based on `choco install winfsp` which is the Chocolatey approach
- SmartScreen EV certificate behavior post-March 2024 -- multiple sources agree but no official Microsoft documentation found

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- winfsp crate is well-documented, versions verified via crates.io/docs.rs
- Architecture: MEDIUM-HIGH -- Platform abstraction pattern is sound but WinFsp-specific patterns (FileSystemHost lifecycle, mount directory behavior) need validation during implementation
- Pitfalls: HIGH -- Derived from direct codebase analysis + WinFsp documentation + learnings from macOS FUSE work
- CI/CD: MEDIUM -- WinFsp installation on GitHub Actions not officially documented; Chocolatey approach should work but needs testing
- Code signing: MEDIUM -- Tauri docs are clear but SmartScreen behavior is changing

**Research date:** 2026-02-22
**Valid until:** 2026-03-22 (30 days; winfsp crate and WinFsp driver are stable)
