---
phase: 39-user-configurable-vault-parameters
verified: 2026-06-27T00:00:00Z
status: gaps_found
score: 4/6 deliverables fully verified
---

# Phase 39: User-Configurable Vault Parameters Verification Report

**Phase Goal:** Add end-user vault settings (recycle-bin retention, soft/hard delete mode, max versions, version cooldown) stored in encrypted vault metadata, with a Vault tab in the web Settings UI and defaults matching prior hardcoded values.
**Verified:** 2026-06-27
**Status:** GAPS FOUND
**Re-verification:** Retroactive milestone-audit closure (phase shipped 2026-03-31, PR #423 / commit `fa7b44399`; VERIFICATION.md was never authored). Code has evolved since (notably Phase 60 strict-IPNS-sequence hardening — `saveVaultSettings` now embeds `sequenceNumber: 1n` on first publish); deliverables re-checked against the current working tree.

## Goal Achievement

### Observable Truths (from ROADMAP Success Criteria)

The ROADMAP Phase 39 section (lines 530-543) states no formal success-criteria checklist beyond the goal sentence; it lists 4 plans and "Requirements: None (deferred items from Phases 13, 17)". The observable truths below are derived from the phase goal and the per-plan `must_haves.truths` frontmatter.

| #   | Truth                                                                                                    | Status   | Evidence                                                                                                                                                  |
| --- | ------------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `VaultSettings` type with 5 fields is defined and exported from `@cipherbox/core`                        | VERIFIED | `packages/core/src/vault/types.ts:73-84` (version, recycleBinRetentionDays, deleteBehavior, maxVersionsPerFile, versionCooldownMinutes); re-export `packages/core/src/index.ts:72` |
| 2   | `DEFAULT_VAULT_SETTINGS` matches prior hardcoded behavior (30d, bin, 10 versions, 15m cooldown)          | VERIFIED | `packages/core/src/vault/settings.ts:14-20`                                                                                                              |
| 3   | `validateVaultSettings()` clamps out-of-range / corrupt input and returns defaults                       | VERIFIED | `packages/core/src/vault/settings.ts:31-65`; 30+ unit tests `packages/core/src/__tests__/vault-settings.test.ts:34-147`                                  |
| 4   | A Vault tab is wired into Settings as a 4th tab alongside Linked Methods / Security / Storage            | VERIFIED | `apps/web/src/routes/SettingsPage.tsx:14,16,151,193,197` (`'vault'` in type+TAB_IDS, `tab-vault` button, `panel-vault`, renders `<VaultTab />`)            |
| 5   | Controls exist for retention, delete mode (soft/hard), max versions, version cooldown                    | PARTIAL  | `apps/web/src/components/settings/VaultTab.tsx:118-216` — number inputs for all three numerics + radio for delete mode. **No 7/14/30/90 retention presets, no 5m/15m/30m/1h/off cooldown dropdown, no hard-delete confirmation dialog** (see Gaps) |
| 6   | `0` disables a feature (retention purge-immediately, 0 max versions, 0 cooldown)                         | VERIFIED | Validation min is `0` for all three: `settings.ts:38-56`; inputs `min={0}`: `VaultTab.tsx:122,189,207`; test `vault-settings.test.ts:52-55`              |
| 7   | Defaults auto-populate when vault metadata lacks a settings field (read-with-fallback; no migration)     | VERIFIED | `loadVaultSettings` returns `DEFAULT_VAULT_SETTINGS` on missing CID / decrypt error / timeout: `apps/web/src/services/vault-settings.service.ts:43,55,62,67` |
| 8   | Settings load on login (parallel w/ BYO config) and clear on logout                                     | VERIFIED | `apps/web/src/hooks/useAuth.ts:298-304` (`Promise.all([loadByoConfig, loadVaultSettings])` → `setSettings`); logout clear `apps/web/src/lib/clear-user-stores.ts:41` |
| 9   | Consumers read settings from the store instead of hardcoded constants                                   | VERIFIED | versions/cooldown `file-metadata.service.ts:31-37,254,302,407`; retention `useBin.ts:23,47`; delete mode `useFolderMutations.ts:23-33`                    |
| 10  | Server-side `RECYCLE_BIN_RETENTION_DAYS` env var deprecated/removed (client controls retention)          | PARTIAL  | Client no longer reads `/vault/config` (zero matches in `apps/web/src`), so it is dead-on-client. **But the server still reads the env var and exposes it** — `apps/api/src/vault/vault.service.ts:50-56`, `vault.controller.ts:58`, `dto/vault-config.dto.ts:11` (see Gaps) |

**Score: 8/10 truths fully verified (2 partial)**

---

### Required Artifacts (per plan)

#### Plan 39-01 — Core VaultSettings type, defaults, validation, HKDF derivation

| Artifact                                          | Expected                                              | Status   | Details (file:line)                                                                                          |
| ------------------------------------------------- | ----------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `packages/core/src/vault/types.ts`                | `VaultSettings` type with 5 fields                    | VERIFIED | `export type VaultSettings` at `types.ts:73-84`                                                              |
| `packages/core/src/vault/settings.ts`             | `DEFAULT_VAULT_SETTINGS` + `validateVaultSettings`    | VERIFIED | `settings.ts:14` (const), `settings.ts:31` (function); clamp/toNumber helpers `settings.ts:67-74`           |
| `packages/core/src/vault/index.ts` / `index.ts`   | Re-exports from `@cipherbox/core`                      | VERIFIED | `vault/index.ts:15-16`; root `index.ts:67,68,72`                                                             |
| `packages/crypto/src/vault/derive-ipns.ts`        | `deriveVaultSettingsIpnsKeypair` (domain-separated)   | VERIFIED | HKDF info `cipherbox-vault-settings-v1` `derive-ipns.ts:32`; function `derive-ipns.ts:167`; export `crypto/src/vault/index.ts:12` |
| `packages/core/src/__tests__/vault-settings.test.ts` | Unit tests (validation, defaults, clamping)        | VERIFIED | 148 lines, 30+ assertions covering defaults, clamps, 0-disable, NaN, version coercion (`:34-147`)           |

#### Plan 39-02 — Zustand store + encrypted IPNS load/save service

| Artifact                                          | Expected                                              | Status   | Details (file:line)                                                                                          |
| ------------------------------------------------- | ----------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `apps/web/src/stores/vault-settings.store.ts`     | `useVaultSettingsStore` w/ defaults + `clearSettings` | VERIFIED | `vault-settings.store.ts:28` (create), `:29` (defaults), `:33-35` (clearSettings)                           |
| `apps/web/src/services/vault-settings.service.ts` | `loadVaultSettings` + `saveVaultSettings` via ECIES/IPNS | VERIFIED | `loadVaultSettings` `:38`, `saveVaultSettings` `:85`; `LOAD_TIMEOUT_MS = 10_000` `:21`; uses `deriveVaultSettingsIpnsKeypair`, `validateVaultSettings` |

#### Plan 39-03 — Consumer integration (delete / versioning / retention)

| Artifact                                          | Expected                                              | Status   | Details (file:line)                                                                                          |
| ------------------------------------------------- | ----------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `apps/web/src/hooks/useAuth.ts`                   | Load on login (parallel), populate store              | VERIFIED | `useAuth.ts:298-304`                                                                                         |
| `apps/web/src/lib/clear-user-stores.ts`           | Clear on logout                                        | VERIFIED | `clear-user-stores.ts:21,41` (logout clear was moved to the centralized helper, not inline in useAuth — a correct deviation from the plan's "in useAuth logout" wording) |
| `apps/web/src/hooks/useFolderMutations.ts`        | `deleteBehavior` respected (permanent skips bin)      | VERIFIED | `useFolderMutations.ts:23-33` (`if (deleteBehavior === 'permanent') deleteItem` else `deleteToBin` w/ fallback) |
| `apps/web/src/services/file-metadata.service.ts`  | Store-backed max versions + cooldown (no constants)   | VERIFIED | `getMaxVersionsPerFile()` `:31`, `getVersionCooldownMs()` `:36`; no `MAX_VERSIONS_PER_FILE`/`VERSION_COOLDOWN_MS` consts remain; used `:254,302,407` |
| `apps/web/src/hooks/useBin.ts`                    | Retention from vault settings store                   | VERIFIED | `useBin.ts:23` (`useVaultSettingsStore((s) => s.settings.recycleBinRetentionDays)`), `:47`                  |

#### Plan 39-04 — Vault settings tab UI

| Artifact                                          | Expected                                              | Status   | Details (file:line)                                                                                          |
| ------------------------------------------------- | ----------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `apps/web/src/components/settings/VaultTab.tsx`   | Form: retention, delete radio, max versions, cooldown, save/reset | VERIFIED | `VaultTab.tsx` — retention input `:118`, delete radiogroup `:137-175`, max versions `:185`, cooldown `:202`, save/reset `:220-230` |
| `apps/web/src/routes/SettingsPage.tsx`            | VAULT tab + panel wired                                | VERIFIED | `SettingsPage.tsx:8,14,16,151-156,193-197`                                                                   |
| vault-settings CSS                                 | Styles for the form                                   | VERIFIED | 24 `vault-settings*` rules in `apps/web/src/App.css` (39-04 summary notes CSS landed in `App.css`, not `styles/settings.css` — correct deviation) |

---

### Key Link Verification

| From                                              | To                                               | Via                                              | Status | Details                                                                 |
| ------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------ | ------ | ---------------------------------------------------------------------- |
| `core/src/vault/settings.ts`                      | `core/src/vault/types.ts`                        | `import type { VaultSettings }`                  | WIRED  | `settings.ts:8`                                                        |
| `core/src/index.ts`                               | `core/src/vault/index.ts`                        | re-exports type + helpers                         | WIRED  | `index.ts:67,68,72`                                                    |
| `vault-settings.service.ts`                       | `@cipherbox/crypto`                              | `deriveVaultSettingsIpnsKeypair`, `wrapKey`, `unwrapKey` | WIRED  | `vault-settings.service.ts:12,40,107`                                  |
| `vault-settings.service.ts`                       | `@cipherbox/core`                                | `validateVaultSettings`, `DEFAULT_VAULT_SETTINGS` | WIRED  | `vault-settings.service.ts:16,43,55`                                   |
| `useAuth.ts`                                       | `vault-settings.service.ts`                      | `loadVaultSettings` on login                     | WIRED  | `useAuth.ts:39,300`                                                    |
| `useAuth.ts`                                       | `vault-settings.store.ts`                        | `useVaultSettingsStore.setSettings`              | WIRED  | `useAuth.ts:40,304`                                                    |
| `clear-user-stores.ts`                            | `vault-settings.store.ts`                        | `clearSettings` on logout                        | WIRED  | `clear-user-stores.ts:21,41`                                           |
| `useFolderMutations.ts`                           | `vault-settings.store.ts`                        | reads `deleteBehavior`                            | WIRED  | `useFolderMutations.ts:8,23`                                           |
| `file-metadata.service.ts`                        | `vault-settings.store.ts`                        | reads max versions + cooldown                    | WIRED  | `file-metadata.service.ts:25,32,37`                                    |
| `useBin.ts`                                        | `vault-settings.store.ts`                        | reads retention                                  | WIRED  | `useBin.ts:3,23`                                                       |
| `VaultTab.tsx`                                     | `vault-settings.service.ts`                      | `saveVaultSettings` on save                      | WIRED  | `VaultTab.tsx:4,65`                                                    |
| `SettingsPage.tsx`                                 | `VaultTab.tsx`                                   | renders in vault panel                            | WIRED  | `SettingsPage.tsx:8,197`                                               |

---

### Requirements Coverage

This phase maps to **NO formal REQ-ID** (ROADMAP line 533: "Requirements: None (deferred items from Phases 13, 17)"). Verification is against the CONTEXT decisions D-01..D-06.

| Deliverable | Source        | Description                                                                 | Status    | Evidence                                                                                              |
| ----------- | ------------- | -------------------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------- |
| D-01        | 39-CONTEXT    | New "Vault" tab as 4th Settings tab                                         | SATISFIED | `SettingsPage.tsx:16,151,197`; `VaultTab.tsx`                                                         |
| D-02        | 39-CONTEXT    | Setting controls default delete mode; hard-delete shows confirmation dialog | PARTIAL   | Soft/hard setting + wiring present (`VaultTab.tsx:137-175`, `useFolderMutations.ts:23-33`); **per-delete hard-delete confirmation dialog NOT implemented** |
| D-03        | 39-CONTEXT    | `0` disables a feature (retention/versions/cooldown)                        | SATISFIED | Validation min 0 (`settings.ts:38-56`); inputs `min={0}`; test `:52-55`                               |
| D-04        | 39-CONTEXT    | Number inputs + preset buttons (retention 7/14/30/90, cooldown dropdown 5m/15m/30m/1h/off) | PARTIAL   | Number inputs present for all three numerics; **preset buttons and cooldown dropdown NOT built** (CONTEXT marked exact layout "Claude's discretion"; executed 39-04 plan specced number inputs only) |
| D-05        | 39-CONTEXT    | Read-with-fallback to defaults, no migration wizard                         | SATISFIED | `loadVaultSettings` defaults on missing/error (`vault-settings.service.ts:43,55,62,67`)               |
| D-06        | 39-CONTEXT    | Deprecate server `RECYCLE_BIN_RETENTION_DAYS`; client controls retention    | PARTIAL   | Client fully migrated (no `/vault/config` reads in `apps/web/src`); **server still reads + exposes the env var** (`vault.service.ts:50`, `vault.controller.ts:58`, `dto/vault-config.dto.ts:11`) |

---

### Anti-Patterns Found

- No TODO/FIXME/placeholder stubs found in the phase artifacts.
- No empty/no-op implementations; all consumers actively read the store.
- Security hygiene preserved: `clearBytes` on plaintext buffers in `vault-settings.service.ts` (ECIES round-trip), matching the BYO-config pattern.
- Note (not a defect): `saveVaultSettings` now embeds `sequenceNumber: 1n` on the first publish (`vault-settings.service.ts:113`), a post-merge Phase 60 strict-IPNS-sequence-gate adaptation. This is consistent with the project invariant "every first IPNS publish must embed sequence 1" and is correct.

---

### Human Verification Required

None required for the verified deliverables — all are statically verifiable. The two manual-only checks from 39-VALIDATION.md (Settings > Vault visual layout; cross-session IPNS persistence round-trip) remain runtime concerns but do not affect the static-deliverable score.

---

### Gaps Summary

Three deviations from the CONTEXT decisions were found. Two are scoped-out UX polish; one is a real backend cleanup that was never done.

1. **D-06 (server-side env var) — PARTIAL / real gap.** The client side is fully migrated (retention now comes from encrypted vault settings; `apps/web/src` no longer calls `/vault/config`), so the env var is functionally dead from the user's perspective. However, the server was never deprecated or removed: `apps/api/src/vault/vault.service.ts:50-56` still parses `RECYCLE_BIN_RETENTION_DAYS`, `vault.controller.ts:58` still documents and exposes it via `/vault/config`, the `VaultConfigDto.recycleBinRetentionDays` field still exists (`dto/vault-config.dto.ts:11`), and `vault.service.spec.ts` still tests it. CONTEXT D-06 explicitly said "deprecate the server-side env var … settings live in one place only." This is residual dead surface, not a functional regression — recommend a follow-up to remove the endpoint field + env var or document it as intentionally retained.

2. **D-02 hard-delete confirmation dialog — PARTIAL.** CONTEXT D-02 specified that when the user's default is hard-delete, "each individual delete shows a confirmation dialog warning that data is unrecoverable." The executed code (`useFolderMutations.ts:23-33`) calls `client.deleteItem()` directly when `deleteBehavior === 'permanent'` with no confirmation prompt. No confirmation dialog tied to permanent delete exists anywhere in `apps/web/src`. The soft/hard *setting* itself works; only the per-action safety prompt is missing.

3. **D-04 preset buttons / cooldown dropdown — PARTIAL (cosmetic).** CONTEXT D-04 specified retention preset buttons (7/14/30/90) and a cooldown dropdown (5m/15m/30m/1h/off). The shipped `VaultTab.tsx` uses plain `<input type="number">` for all three numeric fields and a radio group only for delete mode. CONTEXT explicitly delegated "exact layout … preset buttons look and behave" to Claude's discretion, and the executed 39-04 plan action text specced number inputs — so this is a sanctioned simplification, not a plan-vs-code drift. Functionality (all four settings editable, validated, 0-disable) is intact.

Additionally (informational, not a plan must-have): `docs/METADATA_SCHEMAS.md` has no VaultSettings schema entry, though 39-CONTEXT's canonical refs noted the schema doc "must update for new vault settings schema." None of the 4 plans listed the doc as a `must_haves.artifacts` item, so it is not counted against the score.

Core data contract (D-01), defaults/fallback (D-05), 0-disable semantics (D-03), the Vault tab (D-01), and all consumer wiring are fully verified. The phase achieved its primary goal; the gaps are one backend cleanup miss (D-06) and two UX items (D-02 confirmation, D-04 presets) that diverge from CONTEXT but were largely sanctioned by the executed plans.

_Verified: 2026-06-27_
_Verifier: Claude (retroactive milestone-audit closure)_
