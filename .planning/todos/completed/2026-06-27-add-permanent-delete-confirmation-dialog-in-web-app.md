---
created: 2026-06-27T00:00:00Z
title: Add permanent-delete confirmation dialog in web app
area: ui
files:
  - apps/web/src/hooks/useFolderMutations.ts:23-33
  - apps/web/src/components/settings/VaultTab.tsx
source: 39-VERIFICATION.md (Phase 39 D-02 gap), v1.1-MILESTONE-AUDIT.md
---

## Problem

The web app performs permanent/hard delete with **no confirmation dialog**. When the
user's vault default delete mode is `'permanent'`, `useFolderMutations.ts`
(`deleteWithBehavior`, ~lines 23-33) calls `client.deleteItem()` directly with no
"this data is unrecoverable" prompt.

Phase 39 CONTEXT decision **D-02** required that, when hard-delete is the user's
default, each individual delete shows a confirmation dialog warning that data is
unrecoverable (soft-delete-to-bin needs no extra confirmation). The soft/hard
**setting** itself works and is fully wired (VaultTab → `useVaultSettingsStore` →
`deleteWithBehavior` branch); only the per-action safety prompt was never built. No
confirmation dialog tied to permanent delete exists anywhere in `apps/web/src`.

Surfaced by the 2026-06-27 v1.1 milestone audit
(`.planning/phases/39-user-configurable-vault-parameters/39-VERIFICATION.md`, D-02
gap; `.planning/v1.1-MILESTONE-AUDIT.md`). Data-safety UX gap — without it a user who
opted into permanent-delete-by-default can irreversibly destroy files/folders with a
single click and no warning.

## Solution

Add a confirmation dialog on the permanent-delete path, gated on
`deleteBehavior === 'permanent'`:

- Warn explicitly that the data is unrecoverable (no recycle bin).
- Cover BOTH single-item delete and batch/multi-select delete.
- Soft-delete-to-bin keeps its current no-extra-confirmation flow.
- Wire it through `deleteWithBehavior` (or its callers) so the prompt is consistent
  across file-browser context menu, toolbar, and keyboard shortcut delete paths.
- Match the existing terminal-aesthetic dialog component used elsewhere in the web app.

## Resolution

RESOLVED (destructive-action safety gap closed). `FileBrowser.tsx` renders a
`ConfirmDialog` with "This cannot be undone." before both single-item
(`:272-277`) and batch (`:356-361`) deletes, and `useFileBrowserActions.ts`
gates deletion on that confirmation (`:498-512`, `:557-567`). The todo's "single
click, no warning" premise no longer holds.

Caveat (intentionally not pursued): the prompt is shown unconditionally rather
than gated on `deleteBehavior === 'permanent'`, so the literal D-02
wording-differentiation between soft-delete and permanent-delete is not
implemented. Reopen only if per-mode wording is desired — the safety gap itself
is closed.

Retired 2026-07-11 via pending-todo triage.
