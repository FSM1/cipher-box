# Phase 36: Refactor Upload Progress — Inline Display - Context

**Gathered:** 2026-03-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace the floating UploadModal popup (bottom-right corner) with inline upload progress rows integrated directly into the file browser list. Remove the popup widget entirely. The upload pipeline (encrypt → IPFS → register) and Zustand store remain unchanged — this is a UI-only refactor of how progress is displayed.

</domain>

<decisions>
## Implementation Decisions

### Inline Placement

- **D-01:** Upload progress rows appear inline in the file list at their alphabetical position — the same position the file will occupy once the upload completes.
- **D-02:** Uploading files are sorted alongside existing files/folders, not grouped at the top or bottom.

### Per-file Detail

- **D-03:** Each uploading row shows a minimal thin progress bar underneath the filename. No percentage text, no status text labels.
- **D-04:** The progress bar alone communicates upload state — the bar filling is sufficient visual feedback.

### Lifecycle & Dismissal

- **D-05:** On successful upload, the row shows a brief green "complete" state (~1 second, progress bar fills green), then transitions to a normal file row with size/date columns.
- **D-06:** The transition from upload row to normal file row should feel smooth — the file "becomes real" after the flash.

### Cancel UX

- **D-07:** Each uploading row has its own per-file [✕] cancel button. Cancelling one file does not affect other files in the batch.
- **D-08:** A cancelled row disappears immediately from the file list.

### Error UX

- **D-09:** Failed uploads show an inline error state — red progress bar, error icon, with retry [↻] and dismiss [✕] buttons.
- **D-10:** The error row stays visible until the user either retries or dismisses it.

### Removal

- **D-11:** The UploadModal.tsx component, UploadItem.tsx component, and all popup-related CSS (.upload-popup classes) are removed entirely — not hidden, deleted.

### Claude's Discretion

- Upload row icon/indicator style (↑ arrow, spinner, etc.)
- Exact animation/transition timing for the green flash and swap
- How the progress bar integrates with the existing file list row layout
- Whether to keep the existing upload store shape or simplify it given the simpler UI

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Upload UI Components (to be replaced)

- `apps/web/src/components/file-browser/UploadModal.tsx` — Current popup progress widget (DELETE)
- `apps/web/src/components/file-browser/UploadItem.tsx` — Current per-file row in popup (DELETE)
- `apps/web/src/styles/upload.css` — Contains .upload-popup styles to remove, .upload-zone styles to keep

### Upload State & Hooks (to be modified)

- `apps/web/src/stores/upload.store.ts` — Zustand store with upload status, progress, per-file tracking
- `apps/web/src/hooks/useDropUpload.ts` — Drop handler that calls store actions (startUpload, setUploading, fileComplete)
- `apps/web/src/hooks/useFileUpload.ts` — Upload hook wrapping upload.service

### File Browser (integration point)

- `apps/web/src/components/file-browser/UploadZone.tsx` — Drag-drop trigger, references isUploading state
- `apps/web/src/components/file-browser/ReplaceFileDialog.tsx` — Duplicate file handling (keep as-is)

### Upload Service Layer (unchanged)

- `apps/web/src/services/upload.service.ts` — Sequential multi-file upload orchestration
- `apps/web/src/lib/api/ipfs.ts` — IPFS upload with axios progress events

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `useUploadStore` (Zustand): Already tracks per-file status, progress percentage, and batch state. Can be extended to track per-file progress for inline display.
- `useDropUpload` hook: Handles file validation, duplicate detection, and progress callbacks — integration point for new inline rows.
- `UploadZone.tsx`: Drag-drop zone can remain as-is, just needs to stop referencing the popup modal.

### Established Patterns

- File list uses a mapped array of file/folder items — uploading files can be injected into this array as virtual entries sorted alphabetically.
- Terminal aesthetic CSS with green accents — progress bars should match existing color scheme.
- Zustand store subscriptions via hooks — inline rows will subscribe to individual file progress.

### Integration Points

- File browser component renders the file list — needs to merge real files with in-progress uploads.
- The store's `startUpload()` / `fileComplete()` / `setError()` actions drive UI state transitions.
- `ReplaceFileDialog` for duplicate handling remains independent of progress display.

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

### Reviewed Todos (not folded)

- "Offload large file encryption to Web Worker" — separate concern (performance), not progress display UI

</deferred>

---

_Phase: 36-refactor-upload-progress-in-web-app-to-an-inline-progress-display-and-remove-the-popup-upload-progress_
_Context gathered: 2026-03-30_
