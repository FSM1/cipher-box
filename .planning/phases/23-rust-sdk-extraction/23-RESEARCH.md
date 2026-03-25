# Phase 23: Rust SDK Extraction - Research

**Researched:** 2026-03-24
**Domain:** Rust crate extraction, Cargo workspace architecture, cross-language crypto parity
**Confidence:** HIGH

## Summary

Phase 23 is a structural refactoring that extracts five Rust crates from the monolithic `apps/desktop/src-tauri/src/` code. The existing Rust code is already well-organized by concern (crypto/, fuse/, api/, sync/), making extraction mostly a matter of creating proper crate boundaries, managing inter-crate dependencies, and establishing a Cargo workspace.

The total extraction source is approximately 13,750 lines of Rust across four directories: `crypto/` (3,365 LOC), `fuse/` (9,020 LOC), `api/` (689 LOC), `sync/` (676 LOC), plus `state.rs` (133 LOC) and `registry/` (~120 LOC). The code already mirrors the TypeScript SDK package hierarchy established in Phase 19.1, and existing cross-language test vectors (1,717 LOC) provide a solid foundation for parity verification.

**Primary recommendation:** Extract bottom-up (crypto -> core -> api-client -> fuse -> sdk) using Cargo workspace with centralized dependency versions. Each crate extraction should be a self-contained step where the desktop app compiles and all existing tests pass before proceeding to the next crate.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

**Crate Architecture (five crates):**

1. `cipherbox-crypto` -- Pure crypto primitives + key derivation
2. `cipherbox-core` -- CipherBox domain types, metadata schemas, IPNS records
3. `cipherbox-api-client` -- Generated typed HTTP client from OpenAPI spec
4. `cipherbox-fuse` -- Platform-agnostic FUSE abstractions + platform modules
5. `cipherbox-sdk` -- Stateful orchestration (mirrors `@cipherbox/sdk` in TS)

**Crypto / Core Split Line:** Mirrors TypeScript exactly -- "Does this function need to know what a FolderMetadata or VaultBlob looks like?" If yes -> core. If it just operates on raw bytes/keys -> crypto.

**Monorepo Layout:** New `crates/` top-level directory. Cargo workspace root at repo root. Vendored fuser stays at `apps/desktop/src-tauri/vendor/fuser/` as patched dependency.

**Testing & Cross-Language Parity:** Shared JSON test vectors in `tests/vectors/` organized by crate. CI parity gate runs both Rust and TS suites against same vectors. Desktop E2E remains golden target.

**Migration Strategy:** Bottom-up extraction: crypto first, then core, then api-client, then fuse, then sdk. Desktop app compiles and passes tests after each step.

### Claude's Discretion

- OpenAPI generator choice for Rust client (openapi-generator vs progenitor vs other)
- Internal module organization within each crate
- Trait abstractions for platform-specific FUSE operations
- Error type hierarchy across crates
- Dependency version management within workspace
- Exact CI configuration for cross-platform builds and parity checks

### Deferred Ideas (OUT OF SCOPE)

- wasm-bindgen target
- Shared JSON Schema for Rust <-> TypeScript types
- npm publishing of Rust crates via wasm

</user_constraints>

## Standard Stack

### Core Dependencies (shared across crates)

| Library                | Version         | Purpose                                  | Why Standard                              |
| ---------------------- | --------------- | ---------------------------------------- | ----------------------------------------- |
| `aes-gcm`              | 0.10            | AES-256-GCM encrypt/decrypt              | Already used, proven cross-lang parity    |
| `aes` + `ctr`          | 0.8 / 0.9       | AES-256-CTR streaming encryption         | Already used, matches Web Crypto API      |
| `ecies`                | 0.2             | ECIES secp256k1 key wrapping             | Already used, compatible with eciesjs npm |
| `ed25519-dalek`        | 2.x             | Ed25519 keypair/sign/verify              | Already used, deterministic signatures    |
| `hkdf` + `sha2`        | 0.12 / 0.10     | HKDF-SHA256 key derivation               | Already used for IPNS derivation          |
| `serde` + `serde_json` | 1.x             | JSON serialization with camelCase rename | Already used, critical for TS parity      |
| `zeroize`              | 1.x             | Secure memory clearing                   | Already used, security requirement        |
| `thiserror`            | 2.x             | Error type derivation                    | Already used across all modules           |
| `prost`                | 0.13            | Protobuf encoding (IPNS records)         | Already used for IPNS marshaling          |
| `ciborium`             | 0.2             | CBOR encoding (IPNS data field)          | Already used for IPNS records             |
| `hex`                  | 0.4             | Hex encode/decode                        | Already used throughout                   |
| `base64`               | 0.22            | Base64 encode/decode                     | Already used for metadata transport       |
| `rand`                 | 0.8             | Cryptographic random generation          | Already used via OsRng                    |
| `reqwest`              | 0.12            | HTTP client (api-client crate)           | Already used, async + rustls-tls          |
| `tokio`                | 1.x             | Async runtime                            | Already used for all async operations     |
| `fuser`                | 0.16 (vendored) | FUSE filesystem (macOS/Linux)            | Vendored with socket-read patch           |
| `winfsp`               | 0.12            | WinFsp filesystem (Windows)              | Already used for Windows FUSE             |

### OpenAPI Generator (Claude's Discretion)

**Recommendation: openapi-generator with reqwest library**

| Generator                   | Pros                                                                                            | Cons                                                                                                                     | Verdict         |
| --------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | --------------- |
| openapi-generator (reqwest) | Mature, widely used, handles OpenAPI 3.0 well, generates reqwest-based async code, configurable | Requires Java/Docker to run, generates verbose code                                                                      | **Recommended** |
| progenitor (Oxide)          | Pure Rust, proc-macro or build.rs, clean output                                                 | Primarily targets Dropshot APIs, may struggle with NestJS/Swagger-generated specs, less community usage for generic APIs | Backup option   |
| openapi-client-gen          | Simple single-file output                                                                       | Less mature, fewer configuration options                                                                                 | Not recommended |

**Rationale:** The existing `packages/api-client/openapi.json` is generated by NestJS/Swagger (OpenAPI 3.0 format). The openapi-generator's Rust reqwest template has the most battle-tested support for generic OpenAPI 3.0 specs. Progenitor is excellent but optimized for Dropshot-style APIs and may require more manual fixups for NestJS-generated specs.

**Alternative approach:** If openapi-generator proves too verbose or requires Java, progenitor's build.rs mode with manual type fixups is a solid fallback. The API surface is modest (~20 endpoints), so even hand-written code with reqwest is viable as a last resort (the current approach is only ~689 LOC).

**Installation:**

```bash
# Via npm (included in project's devDependencies)
npx @openapitools/openapi-generator-cli generate \
  -i packages/api-client/openapi.json \
  -g rust \
  -o crates/api-client/src/generated \
  --library reqwest \
  --additional-properties=packageName=cipherbox-api-client,supportAsync=true
```

### Alternatives Considered

| Instead of                          | Could Use                      | Tradeoff                                                          |
| ----------------------------------- | ------------------------------ | ----------------------------------------------------------------- |
| openapi-generator                   | progenitor (build.rs)          | Better for Dropshot APIs; may need manual fixups for NestJS specs |
| Separate error crates               | Single `cipherbox-error` crate | Added complexity, not worth it for 5 crates                       |
| workspace-level `[patch.crates-io]` | Per-crate patch                | Must be at workspace root; workspace-level is correct             |

## Architecture Patterns

### Recommended Project Structure

```
crates/
  crypto/                    # cipherbox-crypto
    src/
      lib.rs                 # Re-exports
      aes.rs                 # AES-256-GCM
      aes_ctr.rs             # AES-256-CTR
      ecies.rs               # ECIES secp256k1
      ed25519.rs             # Ed25519 sign/verify
      hkdf.rs                # HKDF-SHA256 derivations
      ipns_name.rs           # IPNS name derivation (pure crypto)
      utils.rs               # Random gen, hex, clear
      error.rs               # CryptoError enum
    Cargo.toml
  core/                      # cipherbox-core
    src/
      lib.rs                 # Re-exports
      folder.rs              # FolderMetadata types + encrypt/decrypt
      file.rs                # FileMetadata types + encrypt/decrypt
      registry.rs            # DeviceRegistry types + encrypt/decrypt
      bin.rs                 # RecycleBinMetadata types + encrypt/decrypt
      vault_blob.rs          # Vault blob v2 serialize/deserialize
      ipns.rs                # IPNS record creation + marshaling
      decrypt.rs             # decrypt_metadata_from_ipfs_public
      error.rs               # CoreError enum
    Cargo.toml
  api-client/                # cipherbox-api-client
    src/
      lib.rs
      generated/             # OpenAPI-generated code
      types.rs               # Auth DTOs, vault response types
    Cargo.toml
  fuse/                      # cipherbox-fuse
    src/
      lib.rs
      inode.rs               # InodeTable, InodeData, FileAttrs
      cache.rs               # MetadataCache, ContentCache
      file_handle.rs         # FileHandle with temp-file writes
      helpers.rs             # Platform special files, path utils
      constants.rs           # Timeouts, quotas, limits
      platform/
        mod.rs               # Platform trait + re-exports
        macos.rs             # FUSE-T SMB mount, diskutil unmount
        linux.rs             # Kernel FUSE mount, fusermount3
        windows/             # WinFsp implementation
          mod.rs
          operations.rs
          read_ops.rs
          write_ops.rs
          dir_ops.rs
      operations.rs          # Shared FUSE ops (macOS/Linux fuser)
      read_ops.rs            # Read operations
      write_ops.rs           # Write operations
      dir_ops.rs             # Directory operations
    Cargo.toml
  sdk/                       # cipherbox-sdk
    src/
      lib.rs
      client.rs              # CipherBoxClient struct
      sync.rs                # SyncDaemon
      queue.rs               # WriteQueue
      state.rs               # FolderTree, key cache, IPNS tracking
      error.rs               # SdkError enum
    Cargo.toml
tests/
  vectors/
    crypto/                  # Shared test vectors for crypto crate
      aes-gcm.json
      aes-ctr.json
      ecies.json
      ed25519.json
      hkdf.json
      ipns-name.json
    core/                    # Shared test vectors for core crate
      folder-metadata.json
      file-metadata.json
      vault-blob.json
      ipns-record.json
      bin-metadata.json
Cargo.toml                   # Workspace root
```

### Pattern 1: Cargo Workspace with Centralized Dependencies

**What:** Root `Cargo.toml` defines workspace members and shared dependency versions via `[workspace.dependencies]`.

**When to use:** Always for multi-crate repos with shared dependencies.

**Example:**

```toml
# Root Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/crypto",
    "crates/core",
    "crates/api-client",
    "crates/fuse",
    "crates/sdk",
    "apps/desktop/src-tauri",
]

[workspace.dependencies]
# Crypto
aes-gcm = "0.10"
aes = "0.8"
ctr = "0.9"
ecies = { version = "0.2", default-features = false, features = ["pure"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
hkdf = "0.12"
sha2 = "0.10"
rand = "0.8"
zeroize = { version = "1", features = ["derive"] }

# Encoding
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
base64 = "0.22"
prost = "0.13"
ciborium = "0.2"

# Error handling
thiserror = "2"
log = "0.4"

# Async / HTTP
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls", "multipart"] }

# Internal crates
cipherbox-crypto = { path = "crates/crypto" }
cipherbox-core = { path = "crates/core" }
cipherbox-api-client = { path = "crates/api-client" }
cipherbox-fuse = { path = "crates/fuse" }
cipherbox-sdk = { path = "crates/sdk" }

[patch.crates-io]
fuser = { path = "apps/desktop/src-tauri/vendor/fuser" }
```

```toml
# crates/crypto/Cargo.toml
[package]
name = "cipherbox-crypto"
version = "0.1.0"
edition = "2021"

[dependencies]
aes-gcm = { workspace = true }
aes = { workspace = true }
ctr = { workspace = true }
ecies = { workspace = true }
ed25519-dalek = { workspace = true }
hkdf = { workspace = true }
sha2 = { workspace = true }
rand = { workspace = true }
zeroize = { workspace = true }
hex = { workspace = true }
thiserror = { workspace = true }
log = { workspace = true }
# No prost/ciborium -- IPNS record creation is in core, not crypto
# IPNS name derivation stays in crypto (pure byte/key operations)

[dev-dependencies]
serde_json = { workspace = true }
```

### Pattern 2: Feature Flags for Platform-Specific Compilation

**What:** Use Cargo features to conditionally compile platform-specific FUSE code, matching the existing pattern.

**When to use:** For the `cipherbox-fuse` crate which has macOS, Linux, and Windows implementations.

**Example:**

```toml
# crates/fuse/Cargo.toml
[package]
name = "cipherbox-fuse"
version = "0.1.0"
edition = "2021"

[features]
default = ["fuse"]
fuse = ["dep:fuser", "dep:unicode-normalization"]
winfsp = ["dep:winfsp", "dep:widestring"]

[dependencies]
cipherbox-crypto = { workspace = true }
cipherbox-core = { workspace = true }
cipherbox-api-client = { workspace = true }
# Platform-agnostic
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
zeroize = { workspace = true }
log = { workspace = true }
hex = { workspace = true }
base64 = { workspace = true }
reqwest = { workspace = true }
# Platform-specific
fuser = { version = "0.16", default-features = false, features = ["libfuse"], optional = true }
unicode-normalization = { version = "0.1.25", optional = true }
winfsp = { version = "0.12", optional = true, features = ["system"] }
widestring = { version = "1", optional = true }

[target.'cfg(unix)'.dependencies]
libc = "0.2"
```

### Pattern 3: Error Type Hierarchy (Claude's Discretion)

**Recommendation:** Each crate defines its own error enum. Cross-crate errors use `#[from]` for automatic conversion up the stack.

**Example:**

```rust
// crates/crypto/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES encryption failed")]
    AesEncryptionFailed,
    #[error("AES decryption failed")]
    AesDecryptionFailed,
    #[error("ECIES wrapping failed")]
    EciesWrappingFailed,
    #[error("ECIES unwrapping failed")]
    EciesUnwrappingFailed,
    #[error("Ed25519 signing failed")]
    Ed25519SigningFailed,
    #[error("Invalid key size")]
    InvalidKeySize,
    #[error("Invalid IV size")]
    InvalidIvSize,
    #[error("HKDF derivation failed")]
    HkdfDerivationFailed,
}

// crates/core/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Crypto operation failed: {0}")]
    Crypto(#[from] cipherbox_crypto::CryptoError),
    #[error("Metadata serialization failed")]
    SerializationFailed,
    #[error("Metadata deserialization failed")]
    DeserializationFailed,
    #[error("IPNS record creation failed")]
    IpnsCreationFailed,
    #[error("Vault blob format error: {0}")]
    VaultBlobError(String),
}
```

**Rationale:** The existing code already uses per-module error enums (`AesError`, `EciesError`, `Ed25519Error`, `FolderError`, `BinError`, `IpnsError`, `HkdfError`). Consolidating into per-crate error enums simplifies the public API while preserving specificity. The `#[from]` pattern means callers can use `?` across crate boundaries.

### Pattern 4: FUSE Platform Trait (Claude's Discretion)

**Recommendation:** Use a trait for platform-specific mount/unmount operations, but keep the CipherBoxFS struct shared.

```rust
// crates/fuse/src/platform/mod.rs

#[cfg(feature = "fuse")]
pub mod macos;
#[cfg(feature = "fuse")]
pub mod linux;
#[cfg(feature = "winfsp")]
pub mod windows;

/// Platform-specific mount/unmount behavior.
pub trait PlatformMount {
    /// Mount the filesystem at the given path.
    fn mount(fs: CipherBoxFS, mount_point: &std::path::Path) -> Result<(), String>;
    /// Unmount the filesystem.
    fn unmount(mount_point: &std::path::Path) -> Result<(), String>;
}
```

**Note:** The current code uses `#[cfg(target_os = "...")]` and `#[cfg(feature = "...")]` for platform dispatch. A trait is cleaner but optional -- conditional compilation already works. The trait approach is better for testing (mock mounts).

### Anti-Patterns to Avoid

- **Circular dependencies between crates:** crypto MUST NOT depend on core. The dependency chain is strictly: crypto <- core <- api-client <- fuse <- sdk. No reverse edges.
- **Leaking Tauri types into library crates:** The `cipherbox-sdk` crate should NOT depend on `tauri`. Tauri-specific code (`AppHandle`, commands, tray) stays in `apps/desktop/src-tauri/src/`. The desktop app imports `cipherbox-sdk` and wires it to Tauri.
- **Duplicating `serde(rename_all = "camelCase")` types:** All metadata types (`FolderMetadata`, `FileMetadata`, `DeviceRegistry`, `RecycleBinMetadata`) live in `cipherbox-core` only. No copies.
- **Moving test vectors into individual crates:** Test vectors go in `tests/vectors/` at repo root so BOTH Rust and TypeScript test suites can load them.

## Don't Hand-Roll

| Problem                | Don't Build              | Use Instead                           | Why                                                                                            |
| ---------------------- | ------------------------ | ------------------------------------- | ---------------------------------------------------------------------------------------------- |
| OpenAPI client         | Hand-written HTTP code   | openapi-generator or progenitor       | Auto-syncs with API spec changes, reduces 689 LOC of manual code                               |
| Error type boilerplate | Manual `From` impls      | `thiserror` with `#[from]`            | Already used, eliminates 100s of lines of boilerplate                                          |
| Protobuf encoding      | Manual byte manipulation | `prost` (already used)                | IPNS record marshaling is complex, hand-rolling is error-prone                                 |
| CBOR encoding          | Manual byte manipulation | `ciborium` (already used)             | IPNS data field requires exact CBOR format                                                     |
| Test vector loading    | Inline hex constants     | JSON files loaded by both Rust and TS | Existing tests.rs has 1,717 LOC of inline hex -- extracting to shared JSON reduces duplication |

**Key insight:** The existing code already uses the right libraries. The extraction is about reorganizing, not replacing. The one exception is the hand-written API client (`src/api/`), which should be replaced by generated code from the same OpenAPI spec that drives the TypeScript client.

## Common Pitfalls

### Pitfall 1: Breaking the `[patch.crates-io]` Path for Vendored Fuser

**What goes wrong:** Moving to a workspace root `Cargo.toml` changes relative paths. The vendored fuser at `apps/desktop/src-tauri/vendor/fuser/` must be referenced from the workspace root, not from the desktop crate.

**Why it happens:** The `[patch.crates-io]` section must be in the workspace root. Relative paths resolve from the workspace root.

**How to avoid:** Move the `[patch.crates-io]` declaration to the root `Cargo.toml` and adjust the path: `fuser = { path = "apps/desktop/src-tauri/vendor/fuser" }`.

**Warning signs:** `cargo check` fails with "can't find crate for `fuser`" or path resolution errors.

### Pitfall 2: Circular Dependency via `crate::crypto` Paths

**What goes wrong:** The existing code uses `crate::crypto::*` paths extensively. Extracting crypto into a separate crate requires changing ALL import paths to `cipherbox_crypto::*` (or `cipherbox_core::*` for domain types).

**Why it happens:** Rust's module system uses `crate::` for intra-crate references. When a module becomes a separate crate, all paths change.

**How to avoid:** For each extraction step, do a global search-and-replace of `crate::crypto::` to `cipherbox_crypto::` (or `cipherbox_core::`) in the consuming crate. The compiler will catch any missed paths.

**Warning signs:** Compilation errors like "unresolved import `crate::crypto`".

### Pitfall 3: The `bin.rs` / `folder.rs` Cross-Dependency

**What goes wrong:** `bin.rs` (RecycleBinMetadata) imports types from `folder.rs` (`FilePointer`, `FolderEntry`). If `bin.rs` goes into `cipherbox-core` but `folder.rs` also goes into `cipherbox-core`, this is fine. But if someone tries to put `bin.rs` into a separate crate, it creates a dependency.

**Why it happens:** BinEntry contains `Option<FilePointer>` and `Option<FolderEntry>` fields -- these are folder metadata types.

**How to avoid:** Both `bin.rs` and `folder.rs` MUST be in `cipherbox-core`. This is already the plan, but worth calling out.

**Warning signs:** Compilation errors about missing types when extracting.

### Pitfall 4: The `decrypt.rs` FUSE Module Depends on Both Crypto and Core

**What goes wrong:** `fuse/decrypt.rs` calls `crate::crypto::vault_blob::detect_blob_version` and `crate::crypto::folder::decrypt_folder_metadata`. After extraction, it needs to import from both `cipherbox-crypto` and `cipherbox-core`.

**Why it happens:** The decrypt module bridges IPFS transport format (base64+JSON) with domain types (FolderMetadata).

**How to avoid:** Move `decrypt_metadata_from_ipfs_public` and `decrypt_file_metadata_from_ipfs_public` into `cipherbox-core` (not fuse), since they operate on domain types. The FUSE crate then imports from `cipherbox-core`.

**Warning signs:** The fuse crate needing direct crypto imports for metadata operations.

### Pitfall 5: SyncDaemon's Tauri Dependency

**What goes wrong:** `SyncDaemon` currently imports `tauri::AppHandle` for tray status updates. If extracted to `cipherbox-sdk`, this creates a Tauri dependency in a library crate.

**Why it happens:** The sync daemon directly calls `crate::tray::update_tray_status(&self.app_handle, ...)`.

**How to avoid:** Use a callback/channel pattern. `cipherbox-sdk::SyncDaemon` accepts a generic status callback (`Box<dyn Fn(SyncStatus) + Send>`) instead of a Tauri `AppHandle`. The desktop app provides the callback that updates the tray.

**Warning signs:** `tauri` appearing in any crate's `Cargo.toml` other than `apps/desktop/src-tauri`.

### Pitfall 6: Feature Flag Confusion with Workspace

**What goes wrong:** Feature flags (`fuse`, `winfsp`) that were on the desktop crate now need to be on `cipherbox-fuse`. The desktop crate activates them when depending on `cipherbox-fuse`.

**Why it happens:** Cargo feature flags are per-crate. Moving modules between crates moves the feature gate responsibility.

**How to avoid:** Define features on `cipherbox-fuse`. Desktop crate depends with: `cipherbox-fuse = { workspace = true, features = ["fuse"] }` (macOS/Linux) or `cipherbox-fuse = { workspace = true, features = ["winfsp"] }` (Windows).

**Warning signs:** CI builds failing on specific platforms because features aren't propagated.

### Pitfall 7: `hkdf.rs` Split Between Crypto and Core

**What goes wrong:** `hkdf.rs` does HKDF-SHA256 derivation (pure crypto) but also calls `ipns::derive_ipns_name` (which is also pure crypto). The HKDF derivation functions for vault/registry/bin/file all follow the pattern: HKDF -> Ed25519 seed -> keypair -> IPNS name. This is pure crypto -- no domain types.

**Why it happens:** The function names (`derive_vault_ipns_keypair`, `derive_registry_ipns_keypair`) sound domain-aware, but they only differ in the HKDF info string constant.

**How to avoid:** Keep ALL of `hkdf.rs` in `cipherbox-crypto`. The info string constants ("cipherbox-vault-ipns-v1", "cipherbox-device-registry-ipns-v1") are just strings -- they don't reference any domain types. This mirrors the TypeScript split where `deriveVaultIpnsKeypair` is in `@cipherbox/crypto`.

**Warning signs:** Wanting to put HKDF in core "because it mentions vault".

## Code Examples

### Example 1: Crate-Level Re-exports (cipherbox-crypto/src/lib.rs)

```rust
// crates/crypto/src/lib.rs
//! CipherBox cryptographic primitives and key derivation.
//!
//! Pure crypto operations with no CipherBox domain knowledge.
//! Mirrors @cipherbox/crypto TypeScript package.

pub mod aes;
pub mod aes_ctr;
pub mod ecies;
pub mod ed25519;
pub mod hkdf;
pub mod ipns_name;
pub mod utils;
pub mod error;

// Re-export primary functions
pub use aes::{encrypt_aes_gcm, decrypt_aes_gcm, seal_aes_gcm, unseal_aes_gcm};
pub use ecies::{wrap_key, unwrap_key};
pub use ed25519::{generate_ed25519_keypair, sign_ed25519, verify_ed25519, get_public_key};
pub use hkdf::{
    derive_vault_ipns_keypair, derive_file_ipns_keypair,
    derive_registry_ipns_keypair, derive_bin_ipns_keypair,
};
pub use ipns_name::derive_ipns_name;
pub use utils::{generate_file_key, generate_iv, generate_random_bytes, clear_bytes};
pub use error::CryptoError;
```

### Example 2: Shared Test Vector Loading

```rust
// crates/crypto/tests/cross_language.rs
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct AesGcmVector {
    key: String,    // hex
    iv: String,     // hex
    plaintext: String, // hex
    ciphertext: String, // hex (includes tag)
}

fn load_vectors<T: serde::de::DeserializeOwned>(filename: &str) -> Vec<T> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../tests/vectors/crypto");
    path.push(filename);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load test vector {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap()
}

#[test]
fn aes_gcm_cross_language() {
    let vectors: Vec<AesGcmVector> = load_vectors("aes-gcm.json");
    for v in &vectors {
        let key = hex::decode(&v.key).unwrap();
        let iv = hex::decode(&v.iv).unwrap();
        let plaintext = hex::decode(&v.plaintext).unwrap();
        let expected = hex::decode(&v.ciphertext).unwrap();

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let iv_arr: [u8; 12] = iv.try_into().unwrap();

        let result = cipherbox_crypto::encrypt_aes_gcm(&plaintext, &key_arr, &iv_arr).unwrap();
        assert_eq!(hex::encode(&result), v.ciphertext,
            "Rust AES-GCM must match TypeScript output");
    }
}
```

### Example 3: Desktop App Thin Shell After Extraction

```rust
// apps/desktop/src-tauri/src/main.rs (after extraction)
use cipherbox_sdk::CipherBoxClient;
// Commands, tray, and main.rs remain in the desktop app.
// All crypto/core/fuse/sdk logic lives in crates.

mod commands;
mod tray;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_autostart::init(/* ... */))
        .invoke_handler(tauri::generate_handler![
            commands::auth::handle_auth_complete,
            commands::vault::mount_vault,
            commands::vault::unmount_vault,
            commands::sync::trigger_sync,
            // ...
        ])
        .run(tauri::generate_context!())
        .expect("error running tauri application");
}
```

## State of the Art

| Old Approach                        | Current Approach                    | When Changed | Impact                              |
| ----------------------------------- | ----------------------------------- | ------------ | ----------------------------------- |
| Inline hex test vectors in tests.rs | Shared JSON test vector files       | This phase   | Both Rust and TS load same vectors  |
| `crate::crypto::*` paths            | `cipherbox_crypto::*` imports       | This phase   | Crate boundaries enforced           |
| Hand-written API client             | Generated from OpenAPI spec         | This phase   | Auto-sync with API changes          |
| Monolithic Cargo.toml               | Workspace with centralized deps     | This phase   | Shared dep versions, faster builds  |
| SyncDaemon depends on Tauri         | Generic callback for status updates | This phase   | Library crate has no framework deps |

**Deprecated/outdated:**

- `apps/desktop/src-tauri/src/crypto/` -- After extraction, this directory is deleted. All crypto lives in `crates/crypto/` and `crates/core/`.
- `apps/desktop/src-tauri/src/api/` -- After extraction, replaced by `crates/api-client/` (generated).
- `apps/desktop/src-tauri/src/sync/` -- After extraction, lives in `crates/sdk/`.

## Release Please Integration

The project uses release-please for versioning. Rust crates need to be registered in `release-please-config.json`:

```json
{
  "packages": {
    "crates/crypto": {
      "release-type": "rust",
      "component": "cipherbox-crypto",
      "include-component-in-tag": true,
      "bump-minor-pre-major": true
    },
    "crates/core": {
      "release-type": "rust",
      "component": "cipherbox-core",
      "include-component-in-tag": true
    }
    // ... etc for each crate
  }
}
```

The root `release-please-config.json` already lists `apps/desktop/src-tauri/Cargo.toml` as an `extra-files` entry for the root package. New crates should also be registered. However, since these crates are internal (not published to crates.io), the version bumping is primarily for changelog tracking.

**Note:** The existing `extra-files` entry for `apps/desktop/src-tauri/Cargo.toml` must be updated to also include `crates/*/Cargo.toml` files if unified versioning is desired across Rust crates. Alternatively, each crate gets independent versioning via separate release-please package entries.

## CI Configuration Changes

The existing CI has three Cargo jobs: `cargo-macos`, `cargo-linux`, `cargo-windows`. These currently use `--manifest-path apps/desktop/src-tauri/Cargo.toml`. After workspace creation:

1. **Change to workspace-level commands:** `cargo check --workspace`, `cargo test --workspace`
2. **Feature matrix:** Linux and macOS use `--features fuse`, Windows uses `--features winfsp`
3. **Add parity gate job:** New CI step that runs both `cargo test -p cipherbox-crypto` and the TypeScript vector tests, comparing outputs
4. **Cache key update:** Change from `apps/desktop/src-tauri/Cargo.lock` to root `Cargo.lock` (workspace moves the lockfile to root)

**Important:** When creating a workspace, `Cargo.lock` moves to the workspace root. The desktop app's existing `Cargo.lock` at `apps/desktop/src-tauri/Cargo.lock` will no longer be used. This affects CI cache keys and `.gitignore`.

## Open Questions

1. **OpenAPI Generator Java Dependency**
   - What we know: openapi-generator-cli requires Java. The project doesn't currently have Java in CI.
   - What's unclear: Whether the Docker image or npm wrapper is sufficient for CI
   - Recommendation: Use the npm wrapper (`@openapitools/openapi-generator-cli`) which bundles Java. If CI doesn't have Java, consider progenitor (pure Rust, no Java needed) or the Docker image.

2. **Workspace Lockfile Migration**
   - What we know: Cargo workspaces use a single lockfile at the root. The current lockfile is at `apps/desktop/src-tauri/Cargo.lock`.
   - What's unclear: Whether moving the lockfile will cause CI cache misses or break anything
   - Recommendation: In the first workspace setup step, copy the existing lockfile to the root, then let Cargo reconcile it.

3. **Test Vector Generation Script**
   - What we know: Existing test vectors in `tests.rs` were generated by `generate-test-vectors.mjs` (referenced in comments)
   - What's unclear: Whether this script still exists and where it lives
   - Recommendation: Create/update the script to output JSON files to `tests/vectors/`. Run it once to generate initial vectors, then check vectors into git.

## Validation Architecture

### Test Framework

| Property           | Value                                            |
| ------------------ | ------------------------------------------------ |
| Framework          | cargo test (built-in, Rust 1.93)                 |
| Config file        | Workspace `Cargo.toml` (to be created in Wave 0) |
| Quick run command  | `cargo test -p cipherbox-crypto`                 |
| Full suite command | `cargo test --workspace`                         |

### Phase Requirements -> Test Map

Phase 23 has no formal requirement IDs yet (TBD). The following maps the implicit requirements from the CONTEXT.md decisions:

| Req ID     | Behavior                                     | Test Type   | Automated Command                                           | File Exists?                |
| ---------- | -------------------------------------------- | ----------- | ----------------------------------------------------------- | --------------------------- |
| EXTRACT-01 | cipherbox-crypto compiles independently      | unit        | `cargo check -p cipherbox-crypto`                           | No -- Wave 0                |
| EXTRACT-02 | cipherbox-core compiles with crypto dep      | unit        | `cargo check -p cipherbox-core`                             | No -- Wave 0                |
| EXTRACT-03 | Cross-language AES-GCM parity                | unit        | `cargo test -p cipherbox-crypto -- aes_gcm_cross_language`  | No -- Wave 0 (JSON vectors) |
| EXTRACT-04 | Cross-language IPNS record parity            | unit        | `cargo test -p cipherbox-core -- ipns_cross_language`       | No -- Wave 0                |
| EXTRACT-05 | Cross-language vault blob parity             | unit        | `cargo test -p cipherbox-core -- vault_blob_cross_language` | No -- Wave 0                |
| EXTRACT-06 | Desktop app compiles after crypto extraction | integration | `cargo check -p cipherbox-desktop`                          | Yes (existing)              |
| EXTRACT-07 | Desktop app compiles after core extraction   | integration | `cargo check -p cipherbox-desktop`                          | Yes (existing)              |
| EXTRACT-08 | All existing tests pass after extraction     | integration | `cargo test --workspace`                                    | Yes (existing 1,717 LOC)    |
| EXTRACT-09 | Platform features compile (macOS)            | integration | `cargo check -p cipherbox-fuse --features fuse`             | No -- Wave 0                |
| EXTRACT-10 | Platform features compile (Windows)          | integration | `cargo check -p cipherbox-fuse --features winfsp`           | No -- Wave 0 (CI only)      |

### Sampling Rate

- **Per task commit:** `cargo test --workspace --features fuse` (macOS/Linux) or `cargo test --workspace --features winfsp` (Windows)
- **Per wave merge:** `cargo test --workspace` + TypeScript vector parity check
- **Phase gate:** Full suite green on all three platforms before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `Cargo.toml` (root workspace) -- workspace definition
- [ ] `crates/crypto/Cargo.toml` -- crypto crate manifest
- [ ] `crates/core/Cargo.toml` -- core crate manifest
- [ ] `tests/vectors/crypto/aes-gcm.json` -- shared test vectors (extract from tests.rs)
- [ ] `tests/vectors/crypto/ed25519.json` -- shared test vectors
- [ ] `tests/vectors/crypto/hkdf.json` -- shared test vectors
- [ ] `tests/vectors/crypto/ipns-name.json` -- shared test vectors
- [ ] `tests/vectors/core/vault-blob.json` -- shared test vectors
- [ ] `tests/vectors/core/folder-metadata.json` -- shared test vectors
- [ ] Test vector generation script (`scripts/generate-test-vectors.mjs` or similar)

## Extraction-Specific Analysis

### File-Level Extraction Map

| Source File            | Destination Crate       | Notes                                                                              |
| ---------------------- | ----------------------- | ---------------------------------------------------------------------------------- |
| `crypto/aes.rs`        | cipherbox-crypto        | Direct move, no changes                                                            |
| `crypto/aes_ctr.rs`    | cipherbox-crypto        | Direct move, update `super::` to local                                             |
| `crypto/ecies.rs`      | cipherbox-crypto        | Direct move                                                                        |
| `crypto/ed25519.rs`    | cipherbox-crypto        | Direct move                                                                        |
| `crypto/hkdf.rs`       | cipherbox-crypto        | Direct move; update `super::ipns` to `crate::ipns_name`                            |
| `crypto/utils.rs`      | cipherbox-crypto        | Direct move                                                                        |
| `crypto/ipns.rs`       | Split                   | `derive_ipns_name` -> crypto, `create_ipns_record` + `marshal_ipns_record` -> core |
| `crypto/folder.rs`     | cipherbox-core          | Move; change `super::aes` to `cipherbox_crypto::aes`                               |
| `crypto/bin.rs`        | cipherbox-core          | Move; change `crate::crypto::ecies` to `cipherbox_crypto::ecies`                   |
| `crypto/vault_blob.rs` | cipherbox-core          | Move; no crypto deps (pure byte parsing)                                           |
| `crypto/mod.rs`        | Deleted                 | Re-exports move to each crate's lib.rs                                             |
| `crypto/tests.rs`      | Split                   | Extract to JSON vectors + per-crate test files                                     |
| `registry/types.rs`    | cipherbox-core          | Move; no changes to struct definitions                                             |
| `registry/mod.rs`      | cipherbox-sdk           | Move; change crypto/api imports to crate imports                                   |
| `fuse/inode.rs`        | cipherbox-fuse          | Move; change `crate::crypto` to `cipherbox_core`                                   |
| `fuse/cache.rs`        | cipherbox-fuse          | Direct move                                                                        |
| `fuse/file_handle.rs`  | cipherbox-fuse          | Direct move                                                                        |
| `fuse/constants.rs`    | cipherbox-fuse          | Direct move                                                                        |
| `fuse/decrypt.rs`      | cipherbox-core          | Move to core (domain logic, not FUSE-specific)                                     |
| `fuse/helpers.rs`      | cipherbox-fuse          | Move; `build_folder_path` and `versions_to_bin_entries` need crate import updates  |
| `fuse/mod.rs`          | cipherbox-fuse          | Large file (1,847 LOC); mount/unmount logic stays, Tauri refs removed              |
| `fuse/operations.rs`   | cipherbox-fuse          | Move; update imports                                                               |
| `fuse/read_ops.rs`     | cipherbox-fuse          | Move; update imports                                                               |
| `fuse/write_ops.rs`    | cipherbox-fuse          | Move; update imports                                                               |
| `fuse/dir_ops.rs`      | cipherbox-fuse          | Move; update imports                                                               |
| `fuse/windows/*`       | cipherbox-fuse          | Move; update imports                                                               |
| `api/auth.rs`          | cipherbox-api-client    | Replace or adapt with generated code                                               |
| `api/client.rs`        | cipherbox-api-client    | Replace or adapt                                                                   |
| `api/ipfs.rs`          | cipherbox-api-client    | Replace or adapt                                                                   |
| `api/ipns.rs`          | cipherbox-api-client    | Replace or adapt                                                                   |
| `api/types.rs`         | cipherbox-api-client    | Keep auth DTOs; vault types go to core                                             |
| `sync/mod.rs`          | cipherbox-sdk           | Move; remove `tauri::AppHandle`, use generic callback                              |
| `sync/queue.rs`        | cipherbox-sdk           | Direct move                                                                        |
| `sync/tests.rs`        | cipherbox-sdk           | Move; update imports                                                               |
| `state.rs`             | cipherbox-sdk (partial) | Key material management goes to sdk; Tauri MountStatus stays in desktop            |

### ipns.rs Split Detail

This is the trickiest file because it needs to be split between crypto and core:

**To cipherbox-crypto (`ipns_name.rs`):**

- `derive_ipns_name()` -- pure crypto (Ed25519 pubkey -> CIDv1 base36)
- `encode_libp2p_public_key()` -- helper for derive_ipns_name
- `encode_base36()` -- encoding utility
- `encode_unsigned_varint()` -- encoding utility

**To cipherbox-core (`ipns.rs`):**

- `create_ipns_record()` -- creates IPNS record (domain: knows about IPNS structure)
- `marshal_ipns_record()` -- protobuf marshaling
- `IpnsRecord` struct -- domain type
- `build_cbor_data()` -- CBOR encoding for IPNS
- `format_validity_timestamp()` -- RFC3339 formatting
- `civil_from_days()` -- date computation
- `compute_v1_signature()` / `compute_v2_signature()` -- calls `cipherbox_crypto::sign_ed25519`
- `encode_proto_bytes()` / `encode_proto_varint()` / `encode_varint()` -- protobuf helpers

**Rationale:** `derive_ipns_name` is a pure crypto operation (bytes in, string out). `create_ipns_record` knows about IPNS record structure, validity timestamps, sequence numbers -- domain concepts. This matches the TypeScript split where `deriveIpnsName` is in `@cipherbox/crypto` but `createIpnsRecord` is in `@cipherbox/core`.

## Sources

### Primary (HIGH confidence)

- Existing codebase analysis: `apps/desktop/src-tauri/src/crypto/` (12 files, 3,365 LOC) -- direct file reads
- Existing codebase analysis: `apps/desktop/src-tauri/src/fuse/` (11+5 files, 9,020 LOC) -- direct file reads
- Existing codebase analysis: `apps/desktop/src-tauri/Cargo.toml` -- current dependency versions
- TypeScript SDK structure: `packages/crypto/src/index.ts`, `packages/core/src/index.ts` -- mirror targets
- Phase 23 CONTEXT.md -- locked decisions
- [Cargo Workspaces - The Rust Programming Language](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html) -- workspace patterns
- Rust toolchain version: rustc 1.93.0 (verified locally)

### Secondary (MEDIUM confidence)

- [openapi-generator rust docs](https://openapi-generator.tech/docs/generators/rust/) -- OpenAPI generator Rust support
- [progenitor README](https://github.com/oxidecomputer/progenitor/blob/main/README.md) -- Alternative Rust OpenAPI generator
- [release-please config](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md) -- Rust release-type support
- [Cargo Workspace Best Practices](https://earthly.dev/blog/cargo-workspace-crates/) -- Monorepo patterns

### Tertiary (LOW confidence)

- OpenAPI generator choice for NestJS-generated specs -- needs validation during implementation. The recommendation is based on general ecosystem knowledge, not tested against this specific spec.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- All dependencies are already in use and proven; no new libraries needed
- Architecture: HIGH -- Crate boundaries map directly to existing module boundaries; TypeScript SDK provides proven split
- Pitfalls: HIGH -- All pitfalls identified from direct code analysis of import chains and dependencies
- OpenAPI generator choice: MEDIUM -- Recommendation based on ecosystem research, not tested against this specific spec
- CI configuration: MEDIUM -- Changes are straightforward but untested

**Research date:** 2026-03-24
**Valid until:** 2026-04-24 (stable domain, no fast-moving dependencies)
