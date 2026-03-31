# Phase 39: User-Configurable Vault Parameters - Research

**Researched:** 2026-03-31
**Status:** Complete

## Executive Summary

This phase adds user-controlled vault settings stored as encrypted metadata on IPFS/IPNS, following the established BYO-IPFS config pattern. Users gain control over: recycle bin retention period, delete behavior (soft vs hard), and file versioning defaults (max versions, version cooldown).

## Existing Architecture

### Current Hardcoded Values

| Parameter             | Location(s)                                                                                                                                                           | Current Value        |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| Bin retention         | `apps/api` env `RECYCLE_BIN_RETENTION_DAYS` (default 30), `apps/web/src/stores/bin.store.ts` (default 30)                                                             | 30 days              |
| Max versions per file | `packages/sdk-core/src/file/index.ts:28`, `apps/web/src/services/file-metadata.service.ts:30`, `crates/fuse/src/constants.rs:12`                                      | 10                   |
| Version cooldown      | `packages/sdk-core/src/file/index.ts` (no constant, cooldown not used in SDK), `apps/web/src/services/file-metadata.service.ts:33`, `crates/fuse/src/constants.rs:16` | 15 minutes           |
| Delete behavior       | `apps/web/src/hooks/useFolderMutations.ts:324` — tries soft-delete first, falls back to hard delete if bin not loaded                                                 | Soft delete (to bin) |

### BYO-IPFS Config Pattern (Reference Implementation)

The BYO-IPFS config established the pattern for user-specific encrypted settings on IPNS:

1. **HKDF derivation**: `deriveByoConfigIpnsKeypair()` in `packages/crypto/src/vault/derive-ipns.ts` uses info string `cipherbox-byo-ipfs-config-v1`
2. **Encryption**: JSON serialized, ECIES-wrapped with user's publicKey (`wrapKey`/`unwrapKey`)
3. **Storage**: Uploaded to IPFS, published to derived IPNS name
4. **Loading**: On login, resolved from IPNS with timeout, graceful fallback to defaults
5. **Saving**: StorageTab component handles encrypt -> IPFS upload -> IPNS publish

### Vault Retention Config (Current)

Currently, retention is server-driven:

- `GET /vault/config` returns `{ recycleBinRetentionDays: number }` from env var
- Web app calls this at login (`useAuth.ts:371`) and stores in `useBinStore.setRetentionDays()`
- `purgeExpired()` in `bin.service.ts` uses this value to filter expired entries

### Delete Flow

- `useFolderMutations.handleDelete()` tries `client.deleteToBin()` first
- Falls back to `client.deleteItem()` (hard delete) only if `BinNotLoadedError`
- No user-facing toggle between soft and hard delete exists

### Versioning Flow

- `shouldCreateVersion()` in `file-metadata.service.ts` checks cooldown (`VERSION_COOLDOWN_MS = 15 min`)
- `updateFileMetadata()` prunes to `MAX_VERSIONS_PER_FILE = 10`
- Same constants in `sdk-core/src/file/index.ts` and Rust `crates/fuse/src/constants.rs`
- Web re-upload always forces versioning (`forceVersion: true`)

## Recommended Approach

### Storage Model: Dedicated IPNS Record

Follow the BYO-IPFS config pattern exactly:

1. **New HKDF info string**: `cipherbox-vault-settings-v1` for domain separation
2. **New derivation function**: `deriveVaultSettingsIpnsKeypair()` in `packages/crypto/src/vault/derive-ipns.ts`
3. **New type**: `VaultSettings` in `packages/core/src/vault/types.ts`
4. **Encrypt/decrypt helpers**: ECIES wrap/unwrap (same as BYO config)
5. **Load on login**: Resolve IPNS, decrypt, merge with defaults
6. **Save from Settings UI**: New "Vault" tab in Settings page

### VaultSettings Type

```typescript
export type VaultSettings = {
  /** Schema version for future migrations */
  version: 'v1';
  /** Recycle bin retention period in days (default: 30, range: 0-365; 0 disables / immediate purge) */
  recycleBinRetentionDays: number;
  /** Delete behavior: 'bin' = soft delete to recycle bin, 'permanent' = immediate hard delete */
  deleteBehavior: 'bin' | 'permanent';
  /** Maximum number of past versions retained per file (default: 10, range: 0-100) */
  maxVersionsPerFile: number;
  /** Cooldown period for automatic version creation in minutes (default: 15, range: 0-1440) */
  versionCooldownMinutes: number;
};
```

### Default Values (Matching Current Behavior)

```typescript
export const DEFAULT_VAULT_SETTINGS: VaultSettings = {
  version: 'v1',
  recycleBinRetentionDays: 30,
  deleteBehavior: 'bin',
  maxVersionsPerFile: 10,
  versionCooldownMinutes: 15,
};
```

### Consumer Changes

**Where hardcoded values need to be replaced:**

1. `apps/web/src/stores/bin.store.ts` — `retentionDays: 30` default
2. `apps/web/src/hooks/useBin.ts` — `purgeExpired` retentionDays
3. `apps/web/src/hooks/useFolderMutations.ts` — delete behavior (check setting before soft/hard)
4. `apps/web/src/services/file-metadata.service.ts` — `MAX_VERSIONS_PER_FILE`, `VERSION_COOLDOWN_MS`
5. `packages/sdk-core/src/file/index.ts` — `MAX_VERSIONS_PER_FILE` (SDK needs settings injection)
6. `crates/fuse/src/constants.rs` — `MAX_VERSIONS_PER_FILE`, `VERSION_COOLDOWN_MS` (desktop deferred — out of scope for web-only phase)

**Note on desktop:** The Rust FUSE constants would need a mechanism to receive user settings from the Tauri webview. This is a cross-concern that should be deferred to a future desktop phase. For now, desktop keeps its hardcoded defaults.

### Settings UI

Add a "Vault" tab to the existing Settings page (`apps/web/src/routes/SettingsPage.tsx`):

- Tab joins existing tabs: LINKED METHODS | SECURITY | STORAGE | **VAULT**
- Sections:
  - Recycle Bin: retention slider/input (0-365 days; 0 disables / immediate purge)
  - Delete Behavior: radio group (soft delete to bin / permanent delete)
  - File Versioning: max versions input (0-100), cooldown input (0-1440 min)
- Save button encrypts settings JSON, uploads to IPFS, publishes to IPNS
- Reset to defaults button

### API Changes

**Minimal.** The `GET /vault/config` endpoint currently returns server-side retention. Two options:

1. **Keep endpoint but make it advisory** — server default serves as the initial/fallback value; user settings override it
2. **Deprecate endpoint** — user settings fully replace server config

Recommended: Option 1 (backward compatibility). The server config becomes the fallback when no user settings exist.

## Validation Architecture

### Verification Dimensions

1. **Crypto integrity**: Settings encrypted with ECIES, only user's privateKey can decrypt
2. **IPNS publish/resolve**: Settings round-trip through IPFS+IPNS correctly
3. **Default fallback**: Missing/corrupt settings gracefully fall back to defaults
4. **Consumer integration**: Hardcoded values replaced by settings in all web app locations
5. **UI interaction**: Settings tab renders, validates input, saves, and displays current values
6. **Cross-session persistence**: Settings survive logout/login cycle

### Test Scenarios

- Save settings -> logout -> login -> settings loaded correctly
- Corrupt settings blob -> defaults used
- Settings with out-of-range values -> clamped to valid range
- Delete behavior toggle -> actual delete flow changes
- Version cooldown = 0 -> every save creates a version

## Risks and Mitigations

| Risk                                                    | Mitigation                                                                         |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| IPNS resolve adds latency to login                      | Load settings in parallel with BYO config, use timeout + defaults fallback         |
| Desktop doesn't respect user settings                   | Explicitly out of scope for this phase; desktop uses hardcoded defaults            |
| SDK consumers need settings injection                   | Pass settings as parameter to functions that use version/cooldown constants        |
| Race condition: settings saved while delete in progress | Settings applied at load time, mid-operation changes take effect on next operation |

## RESEARCH COMPLETE
