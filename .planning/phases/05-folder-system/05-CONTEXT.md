# Phase 5: Folder System - Context

**Gathered:** 2026-01-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Encrypted folder hierarchy where users can create, nest (up to 20 levels), rename, move, and delete folders. Each folder has its own IPNS keypair for metadata. Files can be renamed and moved between folders. This phase builds the data model and operations — UI is Phase 6.

</domain>

<decisions>
## Implementation Decisions

### Metadata structure
- Start minimal: name, parent reference, child references (folders and files)
- Include schema version field (e.g., `v1`) for future extensibility
- Files listed in parent folder's metadata (file CID, name, size) — not separate tracking
- Design allows future migration to richer metadata without breaking existing vaults

### Folder operations UX
- Always confirm folder deletion with modal ("Delete folder X and N items?")
- Move operations block on name collision — show error, user must rename first
- No undo/trash for v1.0 — defer soft delete to future phase
- Claude's discretion: optimistic vs wait-for-server per operation type

### IPNS publishing strategy
- Publish immediately after every change (rename, add file, move, delete)
- On publish failure: retry silently in background; user sees success but sync indicator shows pending
- Sync indicator appears only during activity, disappears when idle
- Retry queue is session-only for v1.0 — cleared on page refresh

### Root folder behavior
- Root is hidden/implicit — user sees top-level contents without visible "root" folder
- Files allowed directly at root level (no forced folder structure)
- New vaults start completely empty — no pre-created folders
- Root folder corruption is catastrophic (all folder keys lost) — backend redundancy critical

### Backend redundancy (critical)
- Backend tracks ALL folder IPNS names and latest metadata CIDs, not just root
- IPFS content is immutable (content-addressed) — "corruption" isn't the risk
- Risk is losing IPNS pointer or IPFS GC — backend ensures replication and tracking
- This protects against IPNS resolution failures and ensures recovery path exists

### Claude's Discretion
- Optimistic UI updates for fast operations (rename) vs wait-for-server for destructive (delete)
- Exact retry timing and backoff strategy for IPNS publish failures
- Sync indicator UI design and animation

</decisions>

<specifics>
## Specific Ideas

- Metadata schema versioning allows future additions (created/modified dates, item counts, colors) without breaking v1 vaults
- User expressed concern about catastrophic root corruption — backend redundancy is non-negotiable
- Longer term may add visible root folder name (e.g., "My Vault") but start hidden for simplicity

</specifics>

<deferred>
## Deferred Ideas

- Undo/trash/soft delete — future phase (user explicitly deferred)
- Persistent retry queue (IndexedDB) for IPNS publish failures — future enhancement
- Rich metadata (created date, modified date, item count, total size, custom colors) — future version
- Visible/renamable root folder — evaluate after v1.0

</deferred>

---

*Phase: 05-folder-system*
*Context gathered: 2026-01-21*
