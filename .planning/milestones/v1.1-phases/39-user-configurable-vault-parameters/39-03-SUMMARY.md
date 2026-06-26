# Plan 39-03 Summary: Wire vault settings into consumers

## Status: COMPLETE

## Changes Made

### apps/web/src/hooks/useAuth.ts
- Added imports for `loadVaultSettings` and `useVaultSettingsStore`
- Replaced sequential `loadByoConfig` call with `Promise.all([loadByoConfig, loadVaultSettings])` for parallel loading
- After loading, populates vault settings store via `useVaultSettingsStore.getState().setSettings()`
- Sets bin store retention from `vaultSettings.recycleBinRetentionDays`
- Removed non-blocking API `/vault/config` fetch (replaced by encrypted IPNS settings)

### apps/web/src/lib/clear-user-stores.ts
- Added `useVaultSettingsStore` import
- Added `useVaultSettingsStore.getState().clearSettings()` to centralized logout cleanup

### apps/web/src/hooks/useFolderMutations.ts
- Added `useVaultSettingsStore` import
- `handleDelete`: reads `deleteBehavior` from vault settings; when `'permanent'`, calls `client.deleteItem()` directly (skip bin)
- `handleDeleteItems`: same pattern applied to batch delete

### apps/web/src/services/file-metadata.service.ts
- Removed hardcoded `MAX_VERSIONS_PER_FILE = 10` and `VERSION_COOLDOWN_MS = 15 * 60 * 1000`
- Added `getMaxVersionsPerFile()` and `getVersionCooldownMs()` helper functions reading from vault settings store
- Updated `shouldCreateVersion()`, `updateFileMetadata()`, and `restoreVersion()` to use store-backed functions

### apps/web/src/hooks/useBin.ts
- Added `useVaultSettingsStore` import
- Changed `retentionDays` source from `useBinStore((s) => s.retentionDays)` to `useVaultSettingsStore((s) => s.settings.recycleBinRetentionDays)`

## Verification
- `pnpm typecheck` passes with zero errors
- Default behavior unchanged when no user settings exist (DEFAULT_VAULT_SETTINGS matches previous hardcoded values)
