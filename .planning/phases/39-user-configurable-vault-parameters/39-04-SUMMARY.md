# Plan 39-04 Summary: Vault settings tab UI

## Status: COMPLETE

## Changes Made

### apps/web/src/components/settings/VaultTab.tsx (NEW)
- Created VaultTab component with four settings sections:
  1. **Recycle Bin**: number input for retention period (1-365 days)
  2. **Delete Behavior**: radio group with 'bin' (soft delete) and 'permanent' options
  3. **File Versioning**: number inputs for max versions per file (0-100) and version cooldown (0-1440 minutes)
  4. **Actions**: [SAVE SETTINGS] and [RESET TO DEFAULTS] buttons
- Local form state mirrors store (not two-way bound)
- `useEffect` syncs form when store updates (e.g., after initial load)
- Save calls `validateVaultSettings()` then `saveVaultSettings()`, updates both vault settings store and bin store
- Reset restores `DEFAULT_VAULT_SETTINGS` values to form fields
- Loading, saving, success (auto-dismiss 3s), and error states displayed
- Accessibility: proper ARIA roles on radio group, labels linked via htmlFor/id, focus-visible styles

### apps/web/src/routes/SettingsPage.tsx
- Added `VaultTab` import
- Extended `SettingsTabId` type with `'vault'`
- Extended `TAB_IDS` array with `'vault'`
- Added VAULT tab button with matching ARIA attributes and keyboard navigation
- Added vault tab panel with lazy rendering pattern

### apps/web/src/App.css
- Added `.vault-settings` container styles
- Added `.vault-settings-section` with bottom border separator
- Added `.vault-settings-label`, `.vault-settings-input` matching terminal aesthetic
- Added `.vault-settings-radio-group`, `.vault-settings-radio-option`, `.vault-settings-radio-label`
- Added `.vault-settings-description` for muted hint text
- Added `.vault-settings-actions`, `.vault-settings-save-btn`, `.vault-settings-reset-btn`
- Added `.vault-settings-success` (green) and `.vault-settings-error` (red) feedback styles
- All interactive elements have `:focus-visible` styles per CLAUDE.md guidelines

## Verification
- `pnpm typecheck` passes with zero errors
- Settings page has four tabs: LINKED METHODS, SECURITY, STORAGE, VAULT
- Keyboard navigation works across all four tabs (Arrow keys, Home/End)
