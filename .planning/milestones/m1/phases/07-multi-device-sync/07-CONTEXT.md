# Phase 7: Multi-Device Sync - Context

**Gathered:** 2026-01-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Changes sync across devices via IPNS polling. Users see their files update within ~30 seconds when modified on another device. Includes loading states during IPNS resolution and basic offline handling.

</domain>

<decisions>
## Implementation Decisions

### Sync feedback

- Sync icon in header (spinning during sync, checkmark when done)
- No timestamp display — just the icon state
- Instant refresh when sync detects changes (no toast/prompt)
- On initial load: show cached/last-known state with "Syncing..." indicator
- On sync failure: subtle warning icon on sync indicator, cached data remains visible

### Conflict handling

- Last write wins — most recent timestamp overwrites, no user intervention
- No conflict copies or resolution dialogs
- Folder deleted while open on another device: navigate to parent + toast notification
- In-progress upload wins over synced file with same name
- No history or audit trail for sync overwrites

### Polling behavior

- Fixed 30s interval, no user settings to adjust
- After local changes (upload/delete/rename): wait for next interval, don't poll immediately

### Offline experience

- Block uploads when offline (disable button with tooltip)
- Block downloads when offline — no cached file access
- When connection returns: auto-sync immediately

### Claude's Discretion

- Polling behavior when tab is backgrounded (continue, pause, or slow down)
- Whether to poll immediately when tab regains focus
- Offline UI treatment (toast vs persistent banner vs blocking)

</decisions>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

_Phase: 07-multi-device-sync_
_Context gathered: 2026-01-22_
