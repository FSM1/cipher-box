# Phase 39: User-configurable vault parameters - Context

**Gathered:** 2026-03-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Add end-user vault settings stored in encrypted vault metadata, giving users control over: recycle bin retention period (default 30 days), delete behavior (soft delete to bin vs hard delete), and file versioning defaults (max versions per file, version cooldown period). Settings UI in the web app with sensible defaults matching current hardcoded values.

</domain>

<decisions>
## Implementation Decisions

### Settings UI placement

- **D-01:** Add a new "Vault" tab to the Settings page (4th tab alongside Linked Methods, Security, Storage). Keeps Storage tab focused on IPFS/pinning, and vault behavior settings (retention, versioning, delete mode) get their own dedicated tab.

### Delete behavior UX

- **D-02:** Vault setting controls default delete mode (soft-delete to bin vs hard-delete). When hard-delete is the user's default, each individual delete shows a confirmation dialog warning that data is unrecoverable. Soft-delete requires no extra confirmation.

### Retention & versioning controls

- **D-03:** 0 disables the feature: 0 retention days = purge immediately on delete, 0 max versions = overwrite with no history kept, 0 cooldown = no cooldown between versions.
- **D-04:** Number input fields with preset buttons for quick selection. Retention: preset buttons for 7/14/30/90 days. Version cooldown: dropdown with options (5m/15m/30m/1h/off). Max versions: number input with presets.

### Migration & defaults

- **D-05:** When vault metadata has no settings field, auto-populate with hardcoded defaults matching current values: 30-day retention, 10 max versions, 15-minute cooldown, soft-delete mode. No migration wizard — just read with fallback.
- **D-06:** Deprecate the server-side `RECYCLE_BIN_RETENTION_DAYS` environment variable. Client controls retention entirely via encrypted vault metadata. Simpler model — settings live in one place only.

### Claude's Discretion

- Exact layout and spacing of the Vault tab
- Form validation rules and error messages
- Whether to group related settings into subsections
- How preset buttons look and behave

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Vault metadata (settings storage pattern)

- `packages/core/src/vault/types.ts` — Existing vault types including `ByoIpfsConfig` stored in encrypted vault metadata (pattern to follow for vault settings)
- `apps/web/src/stores/vault.store.ts` — Vault store managing metadata state

### Current hardcoded values (to be made configurable)

- `apps/web/src/services/file-metadata.service.ts` — `MAX_VERSIONS_PER_FILE = 10`, `VERSION_COOLDOWN_MS = 15min` (lines 30-33)
- `packages/sdk-core/src/file/index.ts` — `MAX_VERSIONS_PER_FILE = 10` (line 28, SDK duplicate)
- `apps/api/src/vault/vault.service.ts` — `RECYCLE_BIN_RETENTION_DAYS` env var handling (lines 37-46)
- `apps/api/src/vault/dto/vault-config.dto.ts` — `recycleBinRetentionDays` DTO
- `apps/api/src/vault/vault.controller.ts` — `/vault/config` endpoint exposing retention period

### Settings UI (integration point)

- `apps/web/src/routes/SettingsPage.tsx` — Settings page with tab system (add 4th "Vault" tab here)
- `apps/web/src/components/settings/StorageTab.tsx` — Existing settings tab pattern to follow

### Bin service (retention consumer)

- `apps/web/src/services/bin.service.ts` — `purgeExpired` function uses `retentionDays` param (lines 613-629)
- `apps/web/src/hooks/useBin.ts` — Hook calling bin operations

### Metadata schemas

- `docs/METADATA_SCHEMAS.md` — All 10 metadata objects with field tables (must update for new vault settings schema)
- `docs/METADATA_EVOLUTION_PROTOCOL.md` — Formal rules for schema changes

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `ByoIpfsConfig` type and storage pattern — proven pattern for storing user settings in encrypted vault metadata on IPFS. Phase 39 settings follow the same approach.
- `SettingsPage.tsx` tab system — established tab navigation with keyboard support, easy to extend with a 4th tab
- `StorageTab.tsx` — reference implementation for a settings tab component

### Established Patterns

- Vault metadata is encrypted client-side and stored on IPFS. Server never sees plaintext settings (zero-knowledge preserved).
- Settings read with fallback: if field is absent in metadata, use hardcoded default (same pattern as `ByoIpfsConfig` defaulting when absent)
- Number inputs + preset buttons pattern: not yet used in app but standard UX pattern

### Integration Points

- `packages/core/src/vault/types.ts` — new `VaultSettings` type definition needed
- `SettingsPage.tsx` — add 4th "Vault" tab to `TAB_IDS` array and render new `VaultTab` component
- `file-metadata.service.ts` and `sdk-core/src/file/index.ts` — replace hardcoded `MAX_VERSIONS_PER_FILE` and `VERSION_COOLDOWN_MS` with vault settings values
- `useBin.ts` — replace hardcoded/API-fetched retention days with vault settings
- `apps/api/src/vault/vault.service.ts` — deprecate `RECYCLE_BIN_RETENTION_DAYS` env var handling

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

_Phase: 39-user-configurable-vault-parameters_
_Context gathered: 2026-03-31_
