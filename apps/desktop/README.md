<!-- generated-by: gsd-doc-writer -->

# @cipherbox/desktop

Tauri-based desktop application for CipherBox. Provides a native app shell around the
Web3Auth-based login flow and mounts an encrypted virtual filesystem at `~/CipherBox`
using FUSE-T (macOS), libfuse/fuse3 (Linux), or WinFsp (Windows).

Part of the [CipherBox monorepo](../../README.md).

## Prerequisites

- **Node.js** >= 18 with **pnpm** (managed at monorepo root)
- **Rust** toolchain channel `1.88` — managed by `src-tauri/rust-toolchain.toml`; install via [rustup](https://rustup.rs/)
- **Tauri CLI v2** — installed as a dev dependency; no global install required

Platform FUSE dependencies:

- **macOS** — [FUSE-T](https://www.fuse-t.org/) (SMB backend; NFS backend is not used)
- **Linux** — `libfuse3-3` and `fuse3` (listed as `.deb` dependencies in `tauri.conf.json`)
- **Windows** — [WinFsp](https://winfsp.dev/) (bundled installer in `resources/winfsp-*.msi`)

## Development

```bash
# From the monorepo root — runs vite dev + Tauri
pnpm --filter desktop dev
```

By default the app targets the **staging API** (`https://api-staging.cipherbox.cc`).
To use a local API, set in `apps/desktop/.env`:

```env
VITE_API_URL=http://localhost:3000
VITE_ENVIRONMENT=local
```

And pass the Rust env variable:

```bash
CIPHERBOX_API_URL=http://localhost:3000 pnpm --filter desktop dev
```

## Build

```bash
# From the monorepo root — produces platform-native installer
pnpm --filter desktop build
```

The Tauri build runs `pnpm vite build` for the frontend, then compiles the Rust backend
and bundles the installer. Output lands in `src-tauri/target/release/bundle/`.

Available npm scripts:

| Script  | Description                                            |
| ------- | ------------------------------------------------------ |
| `dev`   | Start Tauri dev mode (hot-reload webview + Rust watch) |
| `build` | Build production installer for the current platform    |
| `vite`  | Run the Vite dev server standalone (no Tauri shell)    |

## Directory Structure

```text
apps/desktop/
  src/               # TypeScript/Vite frontend (auth UI, Web3Auth integration)
  src-tauri/
    src/
      fuse/          # FUSE filesystem implementation (macOS/Linux)
      commands/      # Tauri IPC command handlers
      registry/      # Device registry (IPNS-based)
      sync/          # Background sync tasks
      tray/          # System tray integration
    vendor/fuser/    # Vendored fuser 0.16 with patched channel.rs for FUSE-T socket compat
    tauri.conf.json  # Product name, bundle targets, updater, deep-link config
    Cargo.toml       # Rust dependencies; fuse/winfsp features are platform-gated
```

Workspace crates consumed by this app (from `../../crates/`):

| Crate                  | Role                                           |
| ---------------------- | ---------------------------------------------- |
| `cipherbox-fuse`       | Platform-agnostic FUSE/WinFsp filesystem logic |
| `cipherbox-core`       | Core domain types and IPFS/IPNS operations     |
| `cipherbox-crypto`     | Client-side encryption (ECIES, AES-256-GCM)    |
| `cipherbox-sdk`        | High-level vault operations                    |
| `cipherbox-api-client` | Generated HTTP client for the CipherBox API    |

## Configuration

See [../../docs/CONFIGURATION.md](../../docs/CONFIGURATION.md) for the full environment
variable reference. Key variables for local development are `VITE_API_URL`,
`VITE_ENVIRONMENT`, `CIPHERBOX_API_URL`, and `VITE_TEST_LOGIN_SECRET`.
