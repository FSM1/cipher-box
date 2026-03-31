# Phase 40: Desktop vault settings integration - Context

**Gathered:** 2026-03-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Propagate user-configurable vault settings (Phase 39) to the Rust SDK and desktop app. The web app already stores VaultSettings as an encrypted IPNS entry; the desktop app must derive the same IPNS keypair, resolve/decrypt the settings blob, and use the values to drive FUSE file operations (versioning limits, cooldown) instead of hardcoded constants.

</domain>

<decisions>
## Implementation Decisions

### HKDF derivation parity

- **D-01:** Add `VAULT_SETTINGS_HKDF_INFO = b"cipherbox-vault-settings-v1"` to `crates/crypto/src/hkdf.rs` and implement `derive_vault_settings_ipns_keypair()` following the existing pattern. Must produce identical IPNS names as the TypeScript `deriveVaultSettingsIpnsKeypair()` — verify with shared test vectors.

### VaultSettings type in Rust

- **D-02:** Add `VaultSettings` struct to `crates/core` matching the TypeScript type: `version`, `recycleBinRetentionDays`, `deleteBehavior`, `maxVersionsPerFile`, `versionCooldownMinutes`. Include `validateVaultSettings()` with same clamping rules (0-365, 0-100, 0-1440) and unknown-version guard.

### Settings loading during login

- **D-03:** Load vault settings in `complete_auth_setup()` alongside vault key decryption. Pattern: derive IPNS keypair -> resolve IPNS -> fetch from IPFS -> ECIES decrypt with userPrivateKey -> parse JSON -> validate. Graceful fallback to defaults on any failure (same as web app).

### Wiring into FUSE operations

- **D-04:** Replace hardcoded `MAX_VERSIONS_PER_FILE` and `VERSION_COOLDOWN_MS` in `crates/fuse/src/constants.rs` with values loaded from VaultSettings. Store settings in `KeyState` or a new `VaultSettingsState` accessible to the FUSE mount.

### Settings are read-only on desktop

- **D-05:** Desktop app only reads vault settings (no save/edit UI). Users configure settings via the web app's Vault tab. Desktop picks up changes on next login or when IPNS polling detects an update.

### Claude's Discretion

- Whether to add VaultSettings to existing `KeyState` or create a separate state struct
- Whether to add IPNS polling for settings changes (vs load-once-at-login)
- Error handling granularity for settings load failures
- Test vector file format and location

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### TypeScript reference implementation (Phase 39)

- `packages/crypto/src/vault/derive-ipns.ts` — `deriveVaultSettingsIpnsKeypair()` with info string `cipherbox-vault-settings-v1`
- `packages/core/src/vault/settings.ts` — `VaultSettings` type, `DEFAULT_VAULT_SETTINGS`, `validateVaultSettings()`
- `packages/core/src/vault/types.ts:73-83` — `VaultSettings` type definition
- `apps/web/src/services/vault-settings.service.ts` — `loadVaultSettings()` / `saveVaultSettings()` (ECIES encrypt/decrypt + IPNS)

### Rust HKDF derivation (existing pattern)

- `crates/crypto/src/hkdf.rs` — All HKDF info strings and derivation functions (vault, vault-key, registry, bin, file)
- `crates/crypto/src/ecies.rs` — ECIES encrypt/decrypt for key wrapping

### Desktop login flow

- `apps/desktop/src-tauri/src/commands/auth.rs:94-266` — `complete_auth_setup()` where vault is initialized
- `apps/desktop/src-tauri/src/commands/vault.rs:148-221` — `fetch_and_decrypt_vault()` for IPNS resolve + decrypt pattern

### FUSE constants (to be replaced)

- `crates/fuse/src/constants.rs:12` — `MAX_VERSIONS_PER_FILE = 10`
- `crates/fuse/src/constants.rs:16` — `VERSION_COOLDOWN_MS = 15 * 60 * 1000`

### Shared test vectors

- `tests/vectors/` — Existing cross-platform test vector files (Rust + TypeScript)

### IPNS resolution

- `crates/api-client/src/ipns.rs:14-54` — `resolve_ipns()` via backend API
- `crates/core/src/decrypt.rs:10-51` — Metadata decryption pattern (JSON `{iv, data}` -> AES-GCM)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `derive_vault_ipns_keypair()` pattern in `crates/crypto/src/hkdf.rs` — exact same structure, just different info string
- ECIES decrypt in `crates/crypto/src/ecies.rs` — for unwrapping the settings blob
- `fetch_content()` in `crates/api-client/src/ipfs.rs` — fetch encrypted blob from IPFS by CID
- `resolve_ipns()` in `crates/api-client/src/ipns.rs` — resolve IPNS name to CID

### Established Patterns

- Vault settings blob is ECIES-encrypted with user's secp256k1 publicKey (same as BYO config, vault key blob)
- IPNS resolution goes through CipherBox backend API, not direct DHT
- Desktop stores in-memory state in `KeyState` (Arc<RwLock<...>> pattern)
- Cross-platform test vectors in `tests/vectors/` JSON files verify TypeScript/Rust parity

### Integration Points

- `crates/crypto/src/hkdf.rs` — add new info string + derivation function
- `crates/core/src/` — add new `vault_settings.rs` module with type + validation
- `crates/sdk/src/state.rs` — add VaultSettings to KeyState or new struct
- `apps/desktop/src-tauri/src/commands/auth.rs` — load settings in `complete_auth_setup()`
- `crates/fuse/src/constants.rs` — replace hardcoded values with loaded settings
- `tests/vectors/` — add vault-settings derivation test vector

</code_context>

<specifics>
## Specific Ideas

- Note: the encrypted vault settings blob uses the same format as BYO-IPFS config (JSON -> ECIES wrapKey -> IPFS), NOT the folder metadata format (JSON -> AES-GCM encrypt). The decrypt path uses `unwrapKey` (ECIES), not `decrypt_metadata_from_ipfs_public` (AES-GCM).

</specifics>

<deferred>
## Deferred Ideas

- Settings save/edit UI in desktop app (users configure via web only for now)
- Real-time settings polling (load-once-at-login is sufficient initially)

</deferred>

---

_Phase: 40-desktop-vault-settings-integration_
_Context gathered: 2026-03-31_
