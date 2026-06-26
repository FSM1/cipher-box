# Phase 39: User-configurable vault parameters - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-31
**Phase:** 39-user-configurable-vault-parameters
**Areas discussed:** Settings UI placement, Delete behavior UX, Retention & versioning controls, Migration & defaults

---

## Settings UI placement

| Option                     | Description                                                                       | Selected |
| -------------------------- | --------------------------------------------------------------------------------- | -------- |
| New 'Vault' tab            | Add a 4th tab for vault behavior settings. Keeps Storage focused on IPFS/pinning. | ✓        |
| Under existing Storage tab | Add section below BYO-IPFS settings. Fewer tabs but longer scroll.                |          |
| You decide                 | Claude picks the best layout.                                                     |          |

**User's choice:** New 'Vault' tab
**Notes:** Clean separation of concerns — Storage for IPFS/pinning, Vault for behavior settings.

---

## Delete behavior UX

| Option                                | Description                                                                 | Selected |
| ------------------------------------- | --------------------------------------------------------------------------- | -------- |
| Settings toggle + per-delete confirm  | Global setting sets default. Hard-delete shows confirmation on each action. | ✓        |
| Settings toggle only                  | Global setting, no per-delete confirmation.                                 |          |
| Per-delete choice (no global setting) | Every delete offers bin vs permanent as inline choice.                      |          |

**User's choice:** Settings toggle + per-delete confirm
**Notes:** Safety guardrail: when hard-delete is default, each delete warns data is unrecoverable.

---

## Retention & versioning controls

### Zero = disable?

| Option               | Description                                                            | Selected |
| -------------------- | ---------------------------------------------------------------------- | -------- |
| Yes, 0 disables      | 0 retention = purge immediately. 0 versions = no history. Clear model. | ✓        |
| No, enforce minimums | Min 1 day retention, min 1 version. Prevents accidental data loss.     |          |
| You decide           | Claude picks sensible boundaries.                                      |          |

**User's choice:** Yes, 0 disables

### Input controls

| Option                     | Description                                                                   | Selected |
| -------------------------- | ----------------------------------------------------------------------------- | -------- |
| Number inputs with presets | Numeric fields with quick-select buttons (7/14/30/90d). Cooldown as dropdown. | ✓        |
| Sliders with labels        | Range sliders showing current value.                                          |          |
| You decide                 | Claude picks per setting.                                                     |          |

**User's choice:** Number inputs with presets
**Notes:** Retention presets: 7/14/30/90 days. Cooldown: dropdown (5m/15m/30m/1h/off).

---

## Migration & defaults

### Existing vault handling

| Option                 | Description                                                                        | Selected |
| ---------------------- | ---------------------------------------------------------------------------------- | -------- |
| Auto-populate defaults | No settings field = use hardcoded defaults (30d/10v/15m/soft). Read with fallback. | ✓        |
| First-time wizard      | Setup wizard on first Vault tab visit, pre-filled with defaults.                   |          |
| You decide             | Claude picks best approach.                                                        |          |

**User's choice:** Auto-populate defaults
**Notes:** No migration needed. Absent field = current behavior preserved.

### Server-side env var

| Option                        | Description                                                                              | Selected |
| ----------------------------- | ---------------------------------------------------------------------------------------- | -------- |
| Deprecate server var          | Client controls retention entirely. Server var removed. Settings in vault metadata only. | ✓        |
| Server floor, client override | Server sets minimum, client can only increase. Operator safety net.                      |          |
| You decide                    | Claude picks based on security implications.                                             |          |

**User's choice:** Deprecate server var
**Notes:** Simpler model — one source of truth in encrypted vault metadata.

---

## Claude's Discretion

- Exact layout and spacing of the Vault tab
- Form validation rules and error messages
- Whether to group settings into subsections
- Preset button appearance and behavior

## Deferred Ideas

None — discussion stayed within phase scope
