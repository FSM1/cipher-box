# Phase 17: Recycle Bin - Context

**Gathered:** 2026-03-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Deleted files and folders are moved to a recycle bin with time-limited retention instead of being permanently destroyed. Users can recover items to their original vault location and manually empty the bin to free storage space. Both web and desktop (FUSE) deletions go to the bin; restore and bin management are web-only.

</domain>

<decisions>
## Implementation Decisions

### Bin browsing & layout

- Flat list display — all deleted items in a single list regardless of original folder structure
- Full context metadata per item: name, file type icon, deletion date, original path, file size, days remaining before auto-purge
- Always-visible sidebar nav item (same level as Files and Shared)
- Sorting/filtering: Claude's discretion

### Delete & restore behavior

- Soft-delete: deleting moves items to bin metadata, not permanent destruction
- Confirmation dialog behavior: Claude's discretion (files vs folders vs always)
- Restore recreates original folder path if parent was deleted (not just restore to root)
- Both "Empty Bin" button (all items) and per-item "Delete permanently" via right-click context menu
- Multi-select support: batch restore and batch permanent delete, reusing existing FileBrowser multi-select pattern

### Retention & auto-purge

- Retention period is environment-configurable via `RECYCLE_BIN_RETENTION_DAYS` (staging: 2 days, production: 30 days)
- Future: user-configurable or organization-level override (not in this phase)
- Client-side purge on load — when app loads or user opens bin, expired items are permanently deleted
- "X days left" countdown displayed per item
- Permanent delete confirmation: Claude's discretion

### Desktop FUSE integration

- FUSE `unlink`/`rmdir` performs soft-delete (moves to bin metadata) — recoverable from web app
- Restore and bin management are web-only — no desktop UI for browsing/restoring bin
- No `.Trash` folder integration in FUSE mount
- Minimal desktop Rust changes — just change delete path from permanent to soft-delete

### Bin metadata architecture

- Encrypted IPNS record, same pattern as folder metadata (zero-knowledge, server never sees contents)
- Each bin entry stores: item name, original parent IPNS name, deletion timestamp, item's own IPNS reference, file size, mime type
- Syncs across devices via IPNS polling (same mechanism as folder sync)

### Claude's Discretion

- Sort/filter options for bin view
- Confirmation dialog behavior (which actions require confirmation)
- Permanent delete confirmation UX pattern
- Loading/empty states for the bin view

</decisions>

<specifics>
## Specific Ideas

- Retention should be environment-configurable now with a path to user/org-level override later — the env variable approach doesn't lock out future configurability
- Flat list can be upgraded to folder-hierarchy view later without data model changes (original path already stored per item)
- Desktop changes should be absolutely minimal — just redirect FUSE delete operations to bin metadata instead of permanent delete

</specifics>

<deferred>
## Deferred Ideas

- User-configurable retention period (per-user settings)
- Organization-level retention policy
- Desktop .Trash folder integration (Finder/Explorer native trash)
- Desktop bin browsing and restore UI
- Folder-hierarchy view in bin (group by original path)

</deferred>

---

_Phase: 17-recycle-bin_
_Context gathered: 2026-03-04_
