# Desktop App (`apps/desktop`) - Development Notes

## Default API Target

The desktop app defaults to the **staging API** (`https://api-staging.cipherbox.cc`). Most development and testing tasks can be completed against staging without running a local API.

To develop against the local API instead, update `.env`:

```env
VITE_API_URL=http://localhost:3000
VITE_ENVIRONMENT=local
```

Also set `CIPHERBOX_API_URL=http://localhost:3000` in the Rust env (used by the native backend):

```bash
CIPHERBOX_API_URL=http://localhost:3000 pnpm --filter desktop dev
```

## Running the Desktop App

```bash
pnpm --filter desktop dev
```

Vite env vars are loaded from `apps/desktop/.env` automatically. No need to pass them on the command line.

## Dev-Key Mode (Headless Auth for Debugging)

Debug builds accept `--dev-key <hex>` to bypass Web3Auth login entirely, enabling fast restart cycles during FUSE/backend debugging.

**How it works:**

1. Pass a 64-char hex secp256k1 private key via `--dev-key` (value is ignored but triggers headless mode)
2. The webview detects it via the `get_dev_key` IPC command
3. Calls `POST /auth/test-login` with the configured `VITE_TEST_LOGIN_SECRET`
4. Gets `{ accessToken, refreshToken, privateKeyHex, isNewUser }` back
5. Calls `handle_test_login_complete` (debug-only Rust command) which skips `/auth/login` and uses the server-generated keypair directly

**Why the server keypair?** Test-login creates/finds a user with a deterministic keypair derived from the email. Using the CLI dev key would cause a keypair mismatch and vault ECIES decryption failures.

**Requirements:**

- `VITE_TEST_LOGIN_SECRET` must be set in `.env` (must match the API's `TEST_LOGIN_SECRET`)
- The API must have `TEST_LOGIN_SECRET` configured and `NODE_ENV` != `production`
- Staging supports this when `NODE_ENV=staging` and `TEST_LOGIN_SECRET` is set in the staging Docker Compose env

**Usage with local API:**

```bash
# Generate a dev key (any valid secp256k1 private key)
DEV_KEY=$(openssl rand -hex 32)

# Set up .env with test-login secret
echo 'VITE_TEST_LOGIN_SECRET=e2e-test-secret-do-not-use-in-production' >> apps/desktop/.env

# Also set TEST_LOGIN_SECRET in the API .env
echo 'TEST_LOGIN_SECRET=e2e-test-secret-do-not-use-in-production' >> apps/api/.env

# Run with dev key (local API)
VITE_API_URL=http://localhost:3000 pnpm --filter desktop dev -- -- --dev-key $DEV_KEY
```

**Note:** Each unique dev key creates its own vault. Use the same key across restarts to persist data.

## FUSE Mount Architecture

The desktop app mounts an encrypted vault at `~/CipherBox` using FUSE-T on macOS. Understanding this architecture is critical for debugging and porting to other platforms.

### macOS: FUSE-T with SMB Backend

**We use FUSE-T's SMB backend, not its NFS backend.** This is a deliberate choice due to a macOS kernel bug (Sequoia 15.3+) where the NFS client never sends WRITE RPCs for newly created files, causing permanent hangs. The SMB backend avoids this entirely.

Mount type shows as `smbfs` in `mount` output — this is expected.

### Vendored Fuser Crate

We vendor fuser 0.16 at `src-tauri/vendor/fuser/` with a critical patch to `channel.rs:receive()`. The patch is required because:

- Stock fuser assumes `/dev/fuse` which delivers complete FUSE messages atomically.
- FUSE-T uses a Unix domain socket where large messages (>256KB) arrive in fragments.
- Without the patch, large file writes crash the FUSE session with `Short read of FUSE request`.

The patch uses `recv(MSG_PEEK)` to read the FUSE header length, then loop-reads exactly that many bytes. It's harmless on Linux where `/dev/fuse` delivers atomic messages.

The vendor dependency is declared in `Cargo.toml` via `[patch.crates-io]`.

### Single-Thread Constraint

ALL FUSE callbacks run on a single thread. Any blocking call stalls the entire filesystem. Rules:

- **NEVER do network I/O in callbacks** (except `release()` which spawns a background task)
- `open()` fires async prefetch — `read()` checks cache, returns EIO on miss (NFS retries)
- `write()` writes to a local temp file — encrypt+upload happens on `release()`
- Background tasks communicate via `mpsc` channels, drained in `readdir()`

### Debounced Metadata Publish

File mutations (create, write, delete, rename) trigger IPNS metadata publish via a debounce queue:

- 1.5s debounce / 10s safety valve (coalesces rapid changes)
- Upload completions track per-folder pending count
- Publish uses `PublishCoordinator` for per-IPNS-name serialization and monotonic sequence numbers

### Known Limitations (macOS)

- **Rename (`mv`) fails with EPERM** — macOS SMB client rejects before reaching FUSE. Open issue.
- **Keychain prompts in debug builds** — each rebuild changes binary signature. Debug builds skip Keychain entirely (`#[cfg(debug_assertions)]`), using ephemeral UUIDs for device ID.
- **`opendir` must return non-zero file handles** — SMB treats `fh=0` as invalid.
- **No FSEvents on FUSE mounts** — Finder won't auto-refresh. CLI-created files appear in `ls` but not Finder until a new window is opened.
- **Stale mount after crash** — `~/CipherBox` may contain `.DS_Store`. App cleans stale contents before mount. Use `diskutil unmount force ~/CipherBox` if mount is stuck.

### FUSE-T Debugging

```bash
# FUSE-T's own log (NFS/SMB server side)
tail -f ~/Library/Logs/fuse-t/fuse-t.log

# Our Rust FUSE daemon log (via env_logger)
RUST_LOG=debug pnpm --filter desktop dev -- -- --dev-key test

# Force-kill stale processes after crash
ps aux | grep cipherbox-desktop | grep -v grep | awk '{print $2}' | xargs kill -9
ps aux | grep go-nfsv4 | grep -v grep | awk '{print $2}' | xargs kill -9
diskutil unmount force ~/CipherBox
```

### Platform Porting Notes

**When implementing the Linux version:**

- Use kernel FUSE (libfuse) directly — no NFS/SMB translation layer
- The vendored fuser patch is harmless on Linux (loop-read completes in one iteration with `/dev/fuse`)
- Most NFS-specific workarounds become unnecessary: no READDIR cache issue, no rename truncation, no single-thread constraint (FUSE supports multithreaded mode)
- Inode stability still matters (same requirement across all FUSE implementations)
- Channel-based prefetch architecture is still beneficial for performance
- Platform special files: filter `.Trash-*`, `.directory`, `desktop.ini` equivalents
- No Keychain — use `libsecret` or file-based credential storage

**When implementing the Windows version:**

- WinFSP or Dokan — completely different filesystem driver API, fuser not used
- Same _principle_ applies: verify IPC transport handles large messages reliably
- File IDs replace inodes — same stability requirement
- Platform special files: `desktop.ini`, `Thumbs.db`, `$RECYCLE.BIN`, Zone.Identifier ADS
- Credential storage: Windows Credential Manager (via `keyring` crate — same API)
- No SMB/NFS translation — WinFSP is native kernel minifilter

**Shared across all platforms:**

- `InodeTable`, `MetadataCache`, `ContentCache` are platform-agnostic data structures
- Channel-based async prefetch pattern (readdir triggers background fetch, read checks cache)
- Debounced publish queue with per-folder coalescing
- `PublishCoordinator` for IPNS sequence number management
- `encrypt_metadata_to_json()` and `decrypt_metadata_from_ipfs_public()` — pure crypto, no OS deps
- `FileHandle` with temp-file-backed writes — concept translates to all platforms

## Tauri Webview Constraints

- No `window.ethereum` — wallet login is not available in the Tauri webview
- OAuth popups use `on_new_window` handler with shared WKWebViewConfiguration
- Use `clearCache()` not `logout({cleanup:true})` for Web3Auth session cleanup

## Key Files

| File                                    | Purpose                                                                          |
| --------------------------------------- | -------------------------------------------------------------------------------- |
| `src-tauri/src/fuse/mod.rs`             | Mount/unmount, debounced publish, pre-populate, drain helpers                    |
| `src-tauri/src/fuse/operations.rs`      | All FUSE callbacks (lookup, getattr, readdir, read, write, create, rename, etc.) |
| `src-tauri/src/fuse/inode.rs`           | Inode table with ino reuse, populate_folder                                      |
| `src-tauri/src/fuse/cache.rs`           | Metadata and content caches with TTL                                             |
| `src-tauri/src/fuse/file_handle.rs`     | Open file handles with temp-file-backed writes                                   |
| `src-tauri/src/commands.rs`             | Tauri IPC commands (auth, mount, unmount)                                        |
| `src-tauri/src/registry/mod.rs`         | Device registry (IPNS-based cross-device awareness)                              |
| `src-tauri/vendor/fuser/src/channel.rs` | Patched fuser receive() for FUSE-T socket compat                                 |
| `src-tauri/Cargo.toml`                  | `[patch.crates-io]` for vendored fuser                                           |
