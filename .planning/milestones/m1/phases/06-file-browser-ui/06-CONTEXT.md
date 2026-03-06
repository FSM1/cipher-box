# Phase 6: File Browser UI - Context

**Gathered:** 2026-01-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Web interface providing complete file management experience. Users can log in via Web3Auth, browse files/folders in a sidebar+content layout, upload files via drag-drop, and perform actions (rename, delete, move, download) through context menus. Responsive design supports mobile web.

</domain>

<decisions>
## Implementation Decisions

### Layout & Navigation
- Folder tree sidebar: auto-collapse on mobile (visible on desktop, slides out as overlay on mobile)
- Breadcrumbs: simple back navigation with current folder name and back arrow (structure should allow dropdown-per-segment in future)
- Empty folder state: large drop zone with "Drag files here or click to upload" prompt
- Toolbar: minimal menu-based (single '+' or menu button with actions in dropdown)

### File List Display
- Default view mode: list view (rows with name, size, date)
- Metadata shown: name + size + date (standard trio)
- Default sort: name alphabetical (A-Z), folders first then files
- Selection: single selection only for v1 (one file at a time)

### Upload Experience
- Drop zone: dedicated bordered area (visible in empty state or toolbar area)
- Progress: modal dialog showing all queued files with individual progress bars
- Error handling: show error in dialog, offer retry button per file (no auto-retry)
- Cancel: per-file cancel button (X) on each uploading file

### Context Menus & Actions
- File actions: Download, Rename, Move, Delete
- Folder actions: Rename, Move, Delete (same menu structure)
- Delete confirmation: always confirm with modal dialog
- Move action: drag-drop only (no menu-based move, drag to sidebar folder tree)
- Keyboard shortcuts: none for v1 (all actions via context menu)

### Claude's Discretion
- Context menu styling and positioning
- Exact modal dialog designs
- Loading states and skeletons
- Animation/transition details
- Error message wording
- Mobile gesture handling beyond basic touch

</decisions>

<specifics>
## Specific Ideas

- Keep v1 simple — single selection, no keyboard shortcuts, minimal toolbar
- Breadcrumb structure should be extensible for future dropdown-per-segment feature
- Upload modal should feel like a proper queue manager, not just a toast

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 06-file-browser-ui*
*Context gathered: 2026-01-21*
