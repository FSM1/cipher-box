# Phase 40: Desktop vault settings integration - Research

**Researched:** 2026-03-31
**Domain:** Rust SDK / Desktop FUSE / Cross-language crypto parity
**Confidence:** HIGH

## Summary

Phase 40 propagates user-configurable vault settings (created in Phase 39's TypeScript web app) to the Rust SDK and desktop app. The work is a mechanical replication of three established patterns: (1) HKDF IPNS keypair derivation (5 existing derivation functions in `crates/crypto/src/hkdf.rs`), (2) IPNS-resolve-then-ECIES-decrypt loading (as done for vault key blob and BYO config), and (3) cross-language test vectors (existing JSON-based parity framework in `tests/vectors/`).

The implementation touches four Rust crates (`crypto`, `core`, `fuse`, `sdk`) and the desktop app's auth flow. The FUSE crate currently uses two hardcoded constants (`MAX_VERSIONS_PER_FILE = 10`, `VERSION_COOLDOWN_MS = 15 * 60 * 1000`) that must be replaced with values loaded from the user's encrypted vault settings. The settings blob format is ECIES-encrypted JSON (same as BYO config), NOT AES-GCM encrypted (which is used for folder metadata). This distinction is critical.

**Primary recommendation:** Follow the exact existing patterns for each layer. No new libraries or architectural changes needed. The work is purely additive Rust code mirroring well-tested TypeScript implementations with cross-language vector verification.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Add `VAULT_SETTINGS_HKDF_INFO = b"cipherbox-vault-settings-v1"` to `crates/crypto/src/hkdf.rs` and implement `derive_vault_settings_ipns_keypair()` following the existing pattern. Must produce identical IPNS names as the TypeScript `deriveVaultSettingsIpnsKeypair()` -- verify with shared test vectors.

- **D-02:** Add `VaultSettings` struct to `crates/core` matching the TypeScript type: `version`, `recycleBinRetentionDays`, `deleteBehavior`, `maxVersionsPerFile`, `versionCooldownMinutes`. Include `validateVaultSettings()` with same clamping rules (0-365, 0-100, 0-1440) and unknown-version guard.

- **D-03:** Load vault settings in `complete_auth_setup()` alongside vault key decryption. Pattern: derive IPNS keypair -> resolve IPNS -> fetch from IPFS -> ECIES decrypt with userPrivateKey -> parse JSON -> validate. Graceful fallback to defaults on any failure (same as web app).

- **D-04:** Replace hardcoded `MAX_VERSIONS_PER_FILE` and `VERSION_COOLDOWN_MS` in `crates/fuse/src/constants.rs` with values loaded from VaultSettings. Store settings in `KeyState` or a new `VaultSettingsState` accessible to the FUSE mount.

- **D-05:** Desktop app only reads vault settings (no save/edit UI). Users configure settings via the web app's Vault tab. Desktop picks up changes on next login or when IPNS polling detects an update.

### Claude's Discretion

- Whether to add VaultSettings to existing `KeyState` or create a separate state struct
- Whether to add IPNS polling for settings changes (vs load-once-at-login)
- Error handling granularity for settings load failures
- Test vector file format and location

### Deferred Ideas (OUT OF SCOPE)

- Settings save/edit UI in desktop app (users configure via web only for now)
- Real-time settings polling (load-once-at-login is sufficient initially)

</user_constraints>

## Standard Stack

### Core

No new dependencies needed. The phase uses only existing crates already in the Cargo workspace.

| Library                | Version   | Purpose                                 | Why Standard                            |
| ---------------------- | --------- | --------------------------------------- | --------------------------------------- |
| `cipherbox-crypto`     | workspace | HKDF derivation, ECIES unwrap           | Already has 5 HKDF derivation functions |
| `cipherbox-core`       | workspace | Domain types (new VaultSettings module) | All CipherBox domain types live here    |
| `cipherbox-sdk`        | workspace | KeyState management                     | Holds all in-memory key/config state    |
| `cipherbox-fuse`       | workspace | FUSE constants, CipherBoxFS struct      | Where versioning logic lives            |
| `cipherbox-api-client` | workspace | IPNS resolve, IPFS fetch                | HTTP calls to backend                   |
| `serde` / `serde_json` | workspace | JSON deserialization of settings blob   | Standard Rust serialization             |

### Supporting

| Library   | Version   | Purpose                          | When to Use                                 |
| --------- | --------- | -------------------------------- | ------------------------------------------- |
| `zeroize` | workspace | Clear sensitive data from memory | When handling decrypted settings blob bytes |
| `hex`     | workspace | Hex encoding for test vectors    | In cross-language test assertions           |

### Alternatives Considered

None. All libraries are already in the workspace and are the only sensible choice.

## Architecture Patterns

### Recommended Project Structure (new/modified files)

```
crates/
  crypto/src/
    hkdf.rs                    # ADD: VAULT_SETTINGS_HKDF_INFO + derive_vault_settings_ipns_keypair()
    lib.rs                     # ADD: re-export derive_vault_settings_ipns_keypair
  core/src/
    vault_settings.rs          # NEW: VaultSettings struct, DEFAULT_VAULT_SETTINGS, validate_vault_settings()
    lib.rs                     # ADD: pub mod vault_settings, re-exports
  sdk/src/
    state.rs                   # ADD: vault_settings field to KeyState
  fuse/src/
    constants.rs               # MODIFY: make constants non-const or remove, add configurable fields
    lib.rs                     # ADD: vault settings fields to CipherBoxFS struct
    read_ops.rs                # MODIFY: use fs.max_versions_per_file / fs.version_cooldown_ms instead of constants
    platform/windows/write_ops.rs  # MODIFY: same as read_ops.rs
apps/desktop/
  src-tauri/src/
    commands/auth.rs           # MODIFY: load vault settings in complete_auth_setup()
    commands/vault.rs          # ADD: load_vault_settings() helper function
    fuse/mod.rs                # MODIFY: pass vault settings to CipherBoxFS
tests/vectors/crypto/
  hkdf.json                   # ADD: vault-settings test vector entry
```

### Pattern 1: HKDF Derivation (copy existing pattern exactly)

**What:** Add a new constant + public function following the identical pattern of the 5 existing derivations.
**When to use:** Adding any new IPNS-addressed content type.
**Example:**

```rust
// Source: crates/crypto/src/hkdf.rs (existing pattern)
/// HKDF info for vault settings IPNS keypair derivation.
const VAULT_SETTINGS_HKDF_INFO: &[u8] = b"cipherbox-vault-settings-v1";

/// Derive the deterministic Ed25519 IPNS keypair for vault settings.
///
/// Uses HKDF info "cipherbox-vault-settings-v1" for domain separation.
pub fn derive_vault_settings_ipns_keypair(
    user_private_key: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, String), CryptoError> {
    derive_ipns_keypair(user_private_key, VAULT_SETTINGS_HKDF_INFO)
}
```

### Pattern 2: VaultSettings Type (mirror TypeScript exactly)

**What:** Rust struct with serde deserialization matching the TypeScript `VaultSettings` type.
**When to use:** Any domain type that must round-trip between TypeScript and Rust.
**Example:**

```rust
// Source: packages/core/src/vault/types.ts (TypeScript reference)
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultSettings {
    pub version: String,
    #[serde(rename = "recycleBinRetentionDays")]
    pub recycle_bin_retention_days: u32,
    #[serde(rename = "deleteBehavior")]
    pub delete_behavior: DeleteBehavior,
    #[serde(rename = "maxVersionsPerFile")]
    pub max_versions_per_file: u32,
    #[serde(rename = "versionCooldownMinutes")]
    pub version_cooldown_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum DeleteBehavior {
    Bin,
    Permanent,
}
```

### Pattern 3: ECIES Decrypt Load Flow (same as BYO config / vault key blob)

**What:** Derive IPNS keypair, resolve IPNS to CID, fetch IPFS, ECIES unwrap, parse JSON.
**When to use:** Loading any zero-knowledge encrypted config stored on IPFS.
**Example:**

```rust
// Source: apps/desktop/src-tauri/src/commands/vault.rs (existing pattern)
pub async fn load_vault_settings(
    api: &ApiClient,
    private_key: &[u8; 32],
) -> VaultSettings {
    let result: Result<VaultSettings, String> = async {
        let (_priv, _pub, ipns_name) =
            cipherbox_crypto::hkdf::derive_vault_settings_ipns_keypair(private_key)
                .map_err(|e| format!("HKDF: {:?}", e))?;
        let resolved = cipherbox_api_client::ipns::resolve_ipns(api, &ipns_name)
            .await.map_err(|e| format!("{}", e))?;
        let encrypted = cipherbox_api_client::ipfs::fetch_content(api, &resolved.cid)
            .await.map_err(|e| format!("{}", e))?;
        let plaintext = cipherbox_crypto::ecies::unwrap_key(&encrypted, private_key)
            .map_err(|e| format!("ECIES: {:?}", e))?;
        let parsed: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("JSON: {}", e))?;
        Ok(cipherbox_core::vault_settings::validate_vault_settings(&parsed))
    }.await;

    match result {
        Ok(settings) => settings,
        Err(e) => {
            log::warn!("Vault settings load failed (using defaults): {}", e);
            cipherbox_core::vault_settings::DEFAULT_VAULT_SETTINGS
        }
    }
}
```

### Pattern 4: CipherBoxFS Configurable Fields (replacing constants)

**What:** Add fields to CipherBoxFS struct, pass values from mount setup, use in version logic.
**When to use:** Replacing any hardcoded constant with user-configurable value.
**Example:**

```rust
// In CipherBoxFS struct (crates/fuse/src/lib.rs)
pub max_versions_per_file: usize,
pub version_cooldown_ms: u64,

// In read_ops.rs / write_ops.rs, change:
//   now_ms.saturating_sub(newest.timestamp) >= VERSION_COOLDOWN_MS
// to:
//   now_ms.saturating_sub(newest.timestamp) >= fs.version_cooldown_ms

// In read_ops.rs / write_ops.rs, change:
//   if versions.len() > MAX_VERSIONS_PER_FILE
// to:
//   if versions.len() > fs.max_versions_per_file
```

### Anti-Patterns to Avoid

- **Using AES-GCM decrypt for vault settings:** Vault settings use ECIES (wrapKey/unwrapKey), NOT AES-GCM. The `decrypt_metadata_from_ipfs_public()` function is for folder metadata only.
- **Making settings load failure fatal:** The web app gracefully falls back to defaults on any settings load error. The desktop must do the same.
- **Blocking the FUSE thread for settings:** Settings are loaded during auth, before FUSE mount. Never load settings lazily from a FUSE callback.
- **Using `snake_case` JSON field names:** The TypeScript serializes with `camelCase` field names (`maxVersionsPerFile`). Use `#[serde(rename = "...")]` or `#[serde(rename_all = "camelCase")]` on the Rust struct.

## Don't Hand-Roll

| Problem                | Don't Build           | Use Instead                                          | Why                                                |
| ---------------------- | --------------------- | ---------------------------------------------------- | -------------------------------------------------- |
| HKDF-SHA256 derivation | Custom HKDF           | `crate::hkdf::derive_ipns_keypair()` internal helper | Already exists, battle-tested, handles zeroization |
| ECIES decryption       | Manual ECIES          | `cipherbox_crypto::ecies::unwrap_key()`              | Cross-compatible with `eciesjs` npm package        |
| JSON field name casing | Manual rename         | `#[serde(rename_all = "camelCase")]`                 | Automatic, less error-prone                        |
| Validation clamping    | Manual if/else chains | Dedicated `validate_vault_settings()` function       | Mirrors TypeScript exactly, testable               |

## Common Pitfalls

### Pitfall 1: ECIES vs AES-GCM Decrypt Confusion

**What goes wrong:** Using `decrypt_metadata_from_ipfs_public()` (AES-GCM) to decrypt vault settings (ECIES-encrypted).
**Why it happens:** Both follow "fetch from IPFS -> decrypt" pattern but use different crypto.
**How to avoid:** The CONTEXT.md explicitly notes the settings blob uses `unwrapKey` (ECIES), not `decrypt_metadata_from_ipfs_public` (AES-GCM).
**Warning signs:** Decryption error on valid settings blob, "AES-GCM tag mismatch" error.

### Pitfall 2: JSON Field Name Casing Mismatch

**What goes wrong:** Rust deserialization fails because TypeScript writes `maxVersionsPerFile` but Rust struct has `max_versions_per_file`.
**Why it happens:** Rust conventions use snake_case, TypeScript uses camelCase.
**How to avoid:** Use `#[serde(rename_all = "camelCase")]` on the struct or individual `#[serde(rename = "...")]` attributes.
**Warning signs:** Serde parse error "missing field", all settings fall back to defaults.

### Pitfall 3: Constants Used in Both macOS and Windows Code Paths

**What goes wrong:** Updating `read_ops.rs` but forgetting `platform/windows/write_ops.rs`.
**Why it happens:** The versioning logic is duplicated across platform-specific write operation files.
**How to avoid:** Search for ALL usages of `MAX_VERSIONS_PER_FILE` and `VERSION_COOLDOWN_MS` before marking done.
**Warning signs:** Hardcoded values still in Windows code path after changes.

**Files using these constants:**

- `crates/fuse/src/read_ops.rs:19` (import), lines 728, 749-750, 755
- `crates/fuse/src/platform/windows/write_ops.rs:16` (import), lines 750, 771-772

### Pitfall 4: Version Cooldown Unit Mismatch

**What goes wrong:** `versionCooldownMinutes` is in minutes (TypeScript/settings), but `VERSION_COOLDOWN_MS` is in milliseconds (Rust FUSE).
**Why it happens:** Different units at different layers.
**How to avoid:** Convert minutes to milliseconds when storing in CipherBoxFS: `settings.version_cooldown_minutes as u64 * 60 * 1000`.
**Warning signs:** Cooldown is either way too short (using raw minutes as ms) or way too long (double conversion).

### Pitfall 5: Test Vector Must Be Generated from TypeScript First

**What goes wrong:** Writing the Rust derivation function and test, but no cross-language verification.
**Why it happens:** The test vector for `cipherbox-vault-settings-v1` does not yet exist in `tests/vectors/crypto/hkdf.json`.
**How to avoid:** Generate the expected output from TypeScript first (run the existing `@cipherbox/crypto` vault-settings test with a known key), add to the shared vectors JSON, then verify Rust produces identical output.
**Warning signs:** Rust tests pass in isolation but cross-language parity test panics with "Unknown HKDF info string: cipherbox-vault-settings-v1".

### Pitfall 6: IPNS Resolve 404 for New Users

**What goes wrong:** New users (or users who never configured settings via web) have no IPNS record for vault settings. `resolve_ipns()` returns `IpnsNotFound` error.
**Why it happens:** Settings IPNS record only exists after the user saves settings in the web app.
**How to avoid:** Catch `IpnsNotFound` (or any error) and fall back to `DEFAULT_VAULT_SETTINGS`. This is the same pattern the web app uses.
**Warning signs:** Login fails for users who haven't configured vault settings.

## Code Examples

### Existing HKDF Pattern (verified from source)

```rust
// Source: crates/crypto/src/hkdf.rs lines 27-36 (existing constants)
const VAULT_HKDF_INFO: &[u8] = b"cipherbox-vault-ipns-v1";
const VAULT_KEY_HKDF_INFO: &[u8] = b"cipherbox-vault-key-ipns-v1";
const REGISTRY_HKDF_INFO: &[u8] = b"cipherbox-device-registry-ipns-v1";
const BIN_HKDF_INFO: &[u8] = b"cipherbox-recycle-bin-ipns-v1";
const FILE_HKDF_INFO_PREFIX: &str = "cipherbox-file-ipns-v1:";

// Source: crates/crypto/src/hkdf.rs lines 81-85 (vault derivation)
pub fn derive_vault_ipns_keypair(
    user_private_key: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, String), CryptoError> {
    derive_ipns_keypair(user_private_key, VAULT_HKDF_INFO)
}
```

### Existing ECIES Unwrap (verified from source)

```rust
// Source: crates/crypto/src/ecies.rs lines 35-46
pub fn unwrap_key(wrapped: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if private_key.len() != SECP256K1_PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidPrivateKey);
    }
    if wrapped.len() < ECIES_MIN_CIPHERTEXT_SIZE {
        return Err(CryptoError::EciesUnwrappingFailed);
    }
    ecies::decrypt(private_key, wrapped).map_err(|_| CryptoError::EciesUnwrappingFailed)
}
```

### Existing Vault Key Load Pattern (verified from source)

```rust
// Source: apps/desktop/src-tauri/src/commands/vault.rs lines 190-208
// Resolve vault key IPNS, fetch v2 blob, extract rootFolderKey
let resolved = cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, &vault_key_ipns_name)
    .await.map_err(|e| format!("Vault key IPNS resolve failed: {}", e))?;
let blob_bytes = cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resolved.cid)
    .await.map_err(|e| format!("IPFS fetch failed for vault key blob: {}", e))?;
```

### TypeScript VaultSettings Load (reference for Rust port)

```typescript
// Source: apps/web/src/services/vault-settings.service.ts lines 38-68
export async function loadVaultSettings(userPrivateKey: Uint8Array): Promise<VaultSettings> {
  const inner = async (): Promise<VaultSettings> => {
    const keypair = await deriveVaultSettingsIpnsKeypair(userPrivateKey);
    const resolved = await resolveIpnsRecord(keypair.ipnsName);
    if (!resolved?.cid) return { ...DEFAULT_VAULT_SETTINGS };
    const encrypted = await fetchFromIpfs(resolved.cid);
    const plaintext = await unwrapKey(encrypted, userPrivateKey);
    let parsed: unknown;
    try {
      const json = new TextDecoder().decode(plaintext);
      parsed = JSON.parse(json);
    } finally {
      clearBytes(plaintext);
    }
    return validateVaultSettings(parsed);
  };
  try {
    const result = await Promise.race([
      inner(),
      new Promise<VaultSettings>((resolve) =>
        setTimeout(() => resolve({ ...DEFAULT_VAULT_SETTINGS }), LOAD_TIMEOUT_MS)
      ),
    ]);
    return result;
  } catch {
    return { ...DEFAULT_VAULT_SETTINGS };
  }
}
```

### Existing CipherBoxFS Struct Fields (where to add settings)

```rust
// Source: crates/fuse/src/lib.rs lines 470-498
pub struct CipherBoxFS {
    pub inodes: inode::InodeTable,
    pub metadata_cache: cache::MetadataCache,
    pub content_cache: cache::ContentCache,
    pub api: Arc<ApiClient>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub public_key: Zeroizing<Vec<u8>>,
    pub root_folder_key: Zeroizing<Vec<u8>>,
    pub root_ipns_name: String,
    pub rt: tokio::runtime::Handle,
    // ... (channels, caches, coordinator)
    pub tee_public_key: Option<Vec<u8>>,
    pub tee_key_epoch: Option<u32>,
    // ADD HERE:
    // pub max_versions_per_file: usize,
    // pub version_cooldown_ms: u64,
}
```

### Cross-Language Test Vector Format (verified from source)

```json
// Source: tests/vectors/crypto/hkdf.json (add new entry)
{
  "description": "HKDF vault settings IPNS keypair derivation (info: cipherbox-vault-settings-v1)",
  "private_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "info": "cipherbox-vault-settings-v1",
  "expected_ed25519_private_key": "<generate from TypeScript>",
  "expected_ed25519_public_key": "<generate from TypeScript>",
  "expected_ipns_name": "<generate from TypeScript>"
}
```

### Cross-Language Test Router (add new match arm)

```rust
// Source: crates/crypto/tests/cross_language.rs lines 200-218
// Add new match arm:
"cipherbox-vault-settings-v1" => {
    cipherbox_crypto::derive_vault_settings_ipns_keypair(&pk).unwrap()
}
```

## Discretion Recommendations

### VaultSettings in KeyState (Recommended: Add to existing KeyState)

**Recommendation:** Add a `vault_settings` field to `KeyState` rather than creating a separate struct.

**Rationale:**

- `KeyState` already holds all auth-time loaded state (private key, root folder key, root IPNS name, TEE keys)
- Vault settings are loaded during `complete_auth_setup()` alongside these other values
- The settings are cleared on logout (same lifecycle as KeyState fields)
- Adding a separate struct would require a second `Arc<RwLock<...>>` in `AppState` with identical lifecycle management
- The field type should be `RwLock<VaultSettings>` (non-optional, defaults to `DEFAULT_VAULT_SETTINGS`)

### IPNS Polling for Settings (Recommended: Load-once-at-login only)

**Recommendation:** Load-once-at-login is sufficient. Skip IPNS polling for settings.

**Rationale:**

- Settings change rarely (user action in web app required)
- Desktop picks up new settings on next login
- Polling adds complexity for minimal benefit
- Deferred in CONTEXT.md scope anyway

### Error Handling Granularity (Recommended: Single catch-all with log)

**Recommendation:** Wrap the entire load flow in a single `match/Err` that logs the error and returns defaults.

**Rationale:**

- Mirrors the TypeScript pattern exactly (try/catch returning defaults)
- Granular error handling provides no user-facing benefit (settings are invisible to users)
- Log the error for debugging but never fail auth over settings

### Test Vector Format (Recommended: Add entry to existing hkdf.json)

**Recommendation:** Add a single new entry to `tests/vectors/crypto/hkdf.json` with the `cipherbox-vault-settings-v1` info string.

**Rationale:**

- All HKDF derivation test vectors live in one file
- Cross-language test already iterates all entries with info-string routing
- Adding a new file would require loader changes in both TypeScript and Rust
- Generate expected values by running TypeScript derivation with the standard test key (`0102...1f20`)

## State of the Art

| Old Approach                            | Current Approach                     | When Changed                        | Impact                             |
| --------------------------------------- | ------------------------------------ | ----------------------------------- | ---------------------------------- |
| Hardcoded `MAX_VERSIONS_PER_FILE = 10`  | User-configurable via vault settings | Phase 39 (web) + Phase 40 (desktop) | Users can tune versioning behavior |
| Hardcoded `VERSION_COOLDOWN_MS = 15min` | User-configurable via vault settings | Phase 39 (web) + Phase 40 (desktop) | Users can tune version cooldown    |
| No vault settings concept               | Encrypted IPNS-stored settings blob  | Phase 39                            | Zero-knowledge user preferences    |

## Validation Architecture

### Test Framework

| Property           | Value                                                                                                |
| ------------------ | ---------------------------------------------------------------------------------------------------- |
| Framework          | cargo test (Rust) + vitest (TypeScript cross-reference)                                              |
| Config file        | Cargo.toml workspace settings                                                                        |
| Quick run command  | `cargo test -p cipherbox-crypto -- vault_settings && cargo test -p cipherbox-core -- vault_settings` |
| Full suite command | `cargo test --workspace`                                                                             |

### Phase Requirements -> Test Map

No formal requirement IDs for this phase (follow-up to Phase 39), but the following behaviors need verification:

| Behavior                                        | Test Type   | Automated Command                                              | File Exists?              |
| ----------------------------------------------- | ----------- | -------------------------------------------------------------- | ------------------------- |
| HKDF derivation produces valid 32-byte keys     | unit        | `cargo test -p cipherbox-crypto -- vault_settings`             | No (Wave 0)               |
| Cross-language HKDF parity with TypeScript      | unit        | `cargo test -p cipherbox-crypto --test cross_language -- hkdf` | Yes (needs new match arm) |
| VaultSettings default values correct            | unit        | `cargo test -p cipherbox-core -- vault_settings`               | No (Wave 0)               |
| validate_vault_settings clamps out-of-range     | unit        | `cargo test -p cipherbox-core -- vault_settings`               | No (Wave 0)               |
| validate_vault_settings handles corrupt input   | unit        | `cargo test -p cipherbox-core -- vault_settings`               | No (Wave 0)               |
| CipherBoxFS uses configurable versioning values | integration | Compile-time verification (constants removed)                  | N/A                       |

### Sampling Rate

- **Per task commit:** `cargo test -p cipherbox-crypto -- vault_settings && cargo test -p cipherbox-core -- vault_settings`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `crates/crypto/src/hkdf.rs` -- add `derive_vault_settings` unit tests
- [ ] `crates/crypto/tests/cross_language.rs` -- add `cipherbox-vault-settings-v1` match arm
- [ ] `tests/vectors/crypto/hkdf.json` -- add vault-settings test vector (generated from TypeScript)
- [ ] `crates/core/src/vault_settings.rs` -- add unit tests for defaults, validation, clamping

## Environment Availability

Step 2.6: SKIPPED (no external dependencies identified). This phase is purely code/config changes within the existing Rust/TypeScript workspace. All tools (cargo, pnpm, rustc) are confirmed available.

## Project Constraints (from CLAUDE.md)

- **Terminology:** Use `privateKey`, `publicKey` (not `privkey`, `pubkey`)
- **Security:** Never store `privateKey` in persistent storage; use `Uint8Array` for binary data; clear sensitive data from memory
- **Code:** TypeScript for JS code, `camelCase` for API fields, `snake_case` for database columns
- **API workflow:** Run `pnpm api:generate` after modifying API endpoints (not applicable here -- no API changes)
- **Git:** Never push directly to `main`; use feature branches; conventional commits
- **ECIES for key wrapping:** Always use ECIES for key wrapping (confirmed for vault settings blob)
- **AES-256-GCM for content encryption:** Only for file/folder content, NOT for vault settings
- **Desktop defaults to staging API:** No need for local API for testing

## Open Questions

1. **Test vector generation timing**
   - What we know: The vault-settings HKDF test vector must be generated from the TypeScript reference implementation using the standard test key `0102...1f20`.
   - What's unclear: Whether to generate it in Wave 0 via a vitest helper script or manually compute and hardcode it.
   - Recommendation: Use a simple vitest test with `console.log` to output the expected hex values, then add to `hkdf.json`. This ensures TypeScript is the source of truth.

## Sources

### Primary (HIGH confidence)

- `crates/crypto/src/hkdf.rs` -- All 5 existing HKDF derivation functions (pattern template)
- `crates/crypto/src/ecies.rs` -- ECIES unwrap_key (decryption primitive)
- `crates/fuse/src/constants.rs` -- Current hardcoded MAX_VERSIONS_PER_FILE and VERSION_COOLDOWN_MS
- `crates/fuse/src/lib.rs` -- CipherBoxFS struct definition with all current fields
- `crates/sdk/src/state.rs` -- KeyState struct definition
- `crates/fuse/src/read_ops.rs` -- Versioning logic using constants (macOS/Linux)
- `crates/fuse/src/platform/windows/write_ops.rs` -- Versioning logic using constants (Windows)
- `packages/crypto/src/vault/derive-ipns.ts` -- TypeScript reference for deriveVaultSettingsIpnsKeypair
- `packages/core/src/vault/settings.ts` -- TypeScript reference for VaultSettings type and validation
- `packages/core/src/vault/types.ts` -- TypeScript VaultSettings type definition
- `apps/web/src/services/vault-settings.service.ts` -- TypeScript reference for loadVaultSettings pattern
- `apps/desktop/src-tauri/src/commands/auth.rs` -- complete_auth_setup() integration point
- `apps/desktop/src-tauri/src/commands/vault.rs` -- fetch_and_decrypt_vault() pattern reference
- `apps/desktop/src-tauri/src/fuse/mod.rs` -- mount_filesystem() where CipherBoxFS is constructed
- `crates/api-client/src/ipns.rs` -- resolve_ipns() function
- `crates/api-client/src/ipfs.rs` -- fetch_content() function
- `tests/vectors/crypto/hkdf.json` -- Existing cross-language test vector format
- `crates/crypto/tests/cross_language.rs` -- Cross-language test with info-string routing

### Secondary (MEDIUM confidence)

- None required. All findings are from direct source code inspection.

### Tertiary (LOW confidence)

- None. No external research needed for this phase.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- all libraries already in workspace, no new dependencies
- Architecture: HIGH -- 100% based on existing patterns in codebase (5 HKDF functions, vault key load, BYO config load)
- Pitfalls: HIGH -- all identified from direct source code analysis of exact files being modified

**Research date:** 2026-03-31
**Valid until:** 2026-04-30 (stable; all patterns are internal to the project)
