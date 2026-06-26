# Phase 36: Inline Upload Progress - Research

**Researched:** 2026-03-30
**Domain:** React UI refactor (Zustand store + component architecture)
**Confidence:** HIGH

## Summary

This is a UI-only refactor replacing the floating UploadModal popup (bottom-right corner) with inline upload progress rows integrated directly into the file browser list. The upload pipeline (encrypt, IPFS upload, register) and its service layer remain unchanged. The work touches three layers: (1) the Zustand upload store needs per-file tracking instead of batch-level tracking, (2) a new `UploadListItem` component renders inline progress rows matching the `FileListItem` grid layout, and (3) the `FileList` component merges upload-in-progress entries into the sorted file array alongside real files.

The existing code is well-structured for this change. The `useUploadStore` already has per-file lifecycle actions (`setEncrypting`, `setUploading`, `fileComplete`), but tracks only the _current_ file name and batch-level progress. The store needs a `files` map for concurrent per-file state. The `FileList` component's `sortItems()` function is the natural merge point -- upload entries get injected as virtual `FolderChild`-compatible objects sorted alphabetically alongside real files. The `UploadModal.tsx`, `UploadItem.tsx`, and all `.upload-popup*` CSS rules are deleted entirely.

**Primary recommendation:** Restructure the upload store first (add per-file map), then build the new `UploadListItem` component, then wire it into `FileList`, then delete the old popup components. This ordering ensures the store contract is stable before UI work begins.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Upload progress rows appear inline in the file list at their alphabetical position -- the same position the file will occupy once the upload completes.
- **D-02:** Uploading files are sorted alongside existing files/folders, not grouped at the top or bottom.
- **D-03:** Each uploading row shows a minimal thin progress bar underneath the filename. No percentage text, no status text labels.
- **D-04:** The progress bar alone communicates upload state -- the bar filling is sufficient visual feedback.
- **D-05:** On successful upload, the row shows a brief green "complete" state (~1 second, progress bar fills green), then transitions to a normal file row with size/date columns.
- **D-06:** The transition from upload row to normal file row should feel smooth -- the file "becomes real" after the flash.
- **D-07:** Each uploading row has its own per-file [x] cancel button. Cancelling one file does not affect other files in the batch.
- **D-08:** A cancelled row disappears immediately from the file list.
- **D-09:** Failed uploads show an inline error state -- red progress bar, error icon, with retry and dismiss buttons.
- **D-10:** The error row stays visible until the user either retries or dismisses it.
- **D-11:** The UploadModal.tsx component, UploadItem.tsx component, and all popup-related CSS (.upload-popup classes) are removed entirely -- not hidden, deleted.

### Claude's Discretion

- Upload row icon/indicator style (up-arrow, spinner, etc.)
- Exact animation/transition timing for the green flash and swap
- How the progress bar integrates with the existing file list row layout
- Whether to keep the existing upload store shape or simplify it given the simpler UI

### Deferred Ideas (OUT OF SCOPE)

- None -- discussion stayed within phase scope.
- "Offload large file encryption to Web Worker" -- separate concern (performance), not progress display UI

</user_constraints>

## Project Constraints (from CLAUDE.md)

- **TypeScript for all JavaScript code** -- no plain JS files.
- **Terminal aesthetic CSS** -- green-on-black, monospace font, no border-radius. Use existing CSS custom properties.
- **Conventional Commits** -- commit messages must follow `type(scope): description` format.
- **Modern CSS color syntax** -- use `rgb(0 0 0 / 50%)` not `rgba(0,0,0,0.5)`.
- **ARIA roles require keyboard handlers** -- any `role="button"` needs Enter/Space handlers.
- **Focus-visible on interactive elements** -- every `:hover` must have a matching `:focus-visible`.
- **Never use `.buffer` on Uint8Array** -- pass typed array directly (not relevant here but general rule).
- **`pnpm api:generate`** after API changes -- not applicable (UI-only phase).
- **Biome lint** -- `//` text in JSX must be wrapped in braces.
- **Branch protection** -- never push directly to `main`. Use feature branch.

## Standard Stack

### Core

| Library    | Version | Purpose                 | Why Standard                                    |
| ---------- | ------- | ----------------------- | ----------------------------------------------- |
| React      | 19.0.0  | Component rendering     | Already in project                              |
| Zustand    | 5.0.10  | Upload state management | Already in project, per-file map fits naturally |
| TypeScript | 5.x     | Type safety             | Project-wide requirement                        |

### Supporting

| Library        | Version  | Purpose                               | When to Use                  |
| -------------- | -------- | ------------------------------------- | ---------------------------- |
| axios          | existing | CancelToken for per-file cancellation | Already used in upload store |
| react-dropzone | existing | File drop handling                    | UploadZone unchanged         |

No new dependencies are needed. This is a pure refactor of existing components.

## Architecture Patterns

### Recommended Changes Structure

```
apps/web/src/
├── stores/
│   └── upload.store.ts        # MODIFY: add per-file tracking map
├── components/file-browser/
│   ├── UploadListItem.tsx      # NEW: inline upload row component
│   ├── FileList.tsx            # MODIFY: merge upload entries into sorted items
│   ├── FileBrowser.tsx         # MODIFY: remove UploadModal import/render
│   ├── UploadModal.tsx         # DELETE
│   ├── UploadItem.tsx          # DELETE
│   └── index.ts               # MODIFY: remove UploadModal/UploadItem exports
├── hooks/
│   └── useDropUpload.ts        # MODIFY: use per-file store actions
├── styles/
│   └── upload.css              # MODIFY: delete .upload-popup* and .upload-modal-btn* rules, add .upload-inline-* rules
└── services/
    └── upload.service.ts       # MODIFY: use per-file store actions
```

### Pattern 1: Per-File Upload Store

**What:** Extend `useUploadStore` with a `Map<string, PerFileUpload>` to track individual file status, progress, and errors.

**When to use:** Always -- this is the core state change enabling inline per-file rows.

**Key design decisions:**

- Each file gets a unique ID: `upload-{filename}-{timestamp}` (avoids collision with real file IDs).
- The `files` map replaces the single `currentFile` / `progress` / `status` batch-level tracking.
- The `cancelSource` becomes per-file (each file needs independent cancellation per D-07).
- Batch-level `status` field can be derived: `'idle'` when map is empty, `'uploading'` when any file is active, `'success'` when all complete, `'error'` when any has error.

**Store shape:**

```typescript
type PerFileUpload = {
  id: string;              // upload-{filename}-{timestamp}
  filename: string;
  status: 'encrypting' | 'uploading' | 'complete' | 'error' | 'cancelled';
  progress: number;        // 0-100
  error: string | null;
  cancelSource: ReturnType<typeof axios.CancelToken.source> | null;
};

// Extended UploadState fields:
files: Map<string, PerFileUpload>;

// New actions:
addFile: (id: string, filename: string) => void;
updateFileProgress: (id: string, progress: number) => void;
setFileStatus: (id: string, status: PerFileUpload['status'], error?: string) => void;
setFileComplete: (id: string) => void;
removeFile: (id: string) => void;
cancelFile: (id: string) => void;
```

**Important:** Keep `pendingReplacements` field and its actions unchanged -- the `ReplaceFileDialog` workflow is independent of progress display.

### Pattern 2: Virtual Entry Merging in FileList

**What:** Before rendering, merge upload-in-progress entries from the store into the `items` array as synthetic `FolderChild`-compatible objects.

**When to use:** In `FileList` component, before `sortItems()`.

**Design:**

```typescript
type UploadVirtualEntry = {
  type: 'file';
  id: string; // upload-{filename}-{timestamp}
  name: string;
  fileMetaIpnsName: ''; // empty -- no IPNS record yet
  createdAt: number;
  modifiedAt: number;
  _uploading: true; // discriminator flag
};
```

The `_uploading` flag lets `FileList` distinguish upload rows from real files and render `UploadListItem` instead of `FileListItem`. The sort function already sorts files alphabetically by name -- upload entries sort naturally.

**Critical:** Only show upload entries for the _current folder_. The store must track which folder each upload targets. Check `folderId` match before injecting virtual entries.

### Pattern 3: Completion Swap Animation

**What:** When upload completes, show green flash for 1000ms, then crossfade to real `FileListItem` over 200ms.

**When to use:** Per D-05 and D-06.

**Implementation approach:**

1. `setFileComplete(id)` sets status to `'complete'` and starts a 1000ms timer.
2. After 1000ms, set a `swapping` flag on the file entry.
3. During `swapping`, render both `UploadListItem` (fading out) and `FileListItem` (fading in) in the same row position using CSS opacity transitions over 200ms.
4. After 200ms, `removeFile(id)` removes the upload entry entirely. The real file (now in `currentFolder.children` from IPNS sync) takes over.

**Caveat:** The real `FileListItem` only appears once the IPNS sync picks up the newly uploaded file. If the file already appears in `children` (because SDK's `uploadFile` triggers an immediate folder refresh), the swap is seamless. If not yet synced, the upload row stays in `complete` state until the next sync cycle brings the real file into `children`.

### Pattern 4: Per-File Cancellation (D-07)

**What:** Each upload file gets its own `axios.CancelToken.source()`. Cancelling one file does not affect others.

**Current limitation:** The existing store has a single `cancelSource` for the entire batch. The `useDropUpload` hook loops through files sequentially, so only one file is actively uploading at a time.

**Solution:** Create a new `CancelToken.source()` per file in the `addFile` action. In the upload loop (`useDropUpload`), pass the file-specific cancel token. The `cancelFile(id)` action triggers `cancelSource.cancel()` for that file only and sets its status to `'cancelled'`, which causes it to disappear from the list immediately (D-08).

**Sequential upload consideration:** Since files upload sequentially (not in parallel), cancelling a queued file just removes it from the pending list. Cancelling the _currently uploading_ file cancels the axios request.

### Anti-Patterns to Avoid

- **Batch-level status for UI rendering:** Do not derive per-file visual state from the batch `status` field. Each file has its own lifecycle.
- **Blocking the upload loop for animations:** The completion flash (1000ms) is a UI-only timer. Never delay the next file's upload to wait for the previous file's animation.
- **Using `useUploadStore()` hook selectors in upload loop:** This causes stale closure bugs (documented in CLAUDE.md memory). Always use `useUploadStore.getState()` inside async callbacks.
- **Re-rendering all rows on every progress update:** The progress bar updates frequently (every axios progress event). Use fine-grained Zustand selectors so only the specific `UploadListItem` re-renders.

## Don't Hand-Roll

| Problem                 | Don't Build                        | Use Instead                                    | Why                                                             |
| ----------------------- | ---------------------------------- | ---------------------------------------------- | --------------------------------------------------------------- |
| File sorting            | Custom sort merging upload entries | Extend existing `sortItems()` in `FileList`    | Already handles folders-first + alphabetical                    |
| Cancel tokens           | Custom AbortController wrapper     | `axios.CancelToken.source()`                   | Already used in the project, matches upload service             |
| Timed state transitions | Manual `setTimeout` chains         | `useEffect` + `useRef` for timers with cleanup | React lifecycle requires proper cleanup to avoid memory leaks   |
| Portal rendering        | Keep Portal for inline rows        | Render directly in FileList                    | Upload rows are inline, not floating -- Portal is wrong pattern |

## Common Pitfalls

### Pitfall 1: Stale Zustand State in Async Upload Loop

**What goes wrong:** The `useDropUpload` hook's `handleFileDrop` callback reads store state, but closures capture stale values during the sequential upload loop.
**Why it happens:** React hook selectors capture state at render time. Inside async functions, the store changes between awaits.
**How to avoid:** Always use `useUploadStore.getState()` for reads inside async callbacks. This pattern is already used in the existing `useDropUpload.ts` (lines 118, 123, 126, 132, etc.).
**Warning signs:** Upload rows show wrong progress or wrong file name.

### Pitfall 2: Upload Row Appears in Wrong Folder

**What goes wrong:** User navigates to a different folder while upload is in progress. Upload rows from folder A appear in folder B's file list.
**Why it happens:** The store tracks uploads globally but the file list renders for the current folder only.
**How to avoid:** Each `PerFileUpload` must include a `targetFolderId` field. The `FileList` merge logic must filter: only show uploads where `targetFolderId === currentFolderId`.
**Warning signs:** Upload progress rows appearing in folders where no upload was initiated.

### Pitfall 3: Completion Swap Race with IPNS Sync

**What goes wrong:** The upload completes and the green flash starts, but the real file hasn't appeared in `children` yet (IPNS sync hasn't run). The upload row disappears after the flash, leaving a gap until the next sync cycle adds the real file.
**Why it happens:** SDK's `uploadFile()` publishes to IPNS, but the folder store's children array only updates on the next sync poll (30s interval) or manual refresh.
**How to avoid:** The SDK's `uploadFile()` calls `client.uploadFile()` which publishes the updated folder metadata to IPNS. The `onUploadComplete` callback in `UploadZone` calls `refreshFolder()`. Ensure this refresh path updates `currentFolder.children` immediately. If the file is already in children, swap seamlessly. If not, keep the upload row in `complete` state until it appears.
**Warning signs:** Brief visual gap where neither upload row nor real file row is visible.

### Pitfall 4: Memory Leak from Uncleared Timers

**What goes wrong:** User navigates away while upload is in progress. Completion flash timers fire on unmounted components.
**Why it happens:** `setTimeout` callbacks run regardless of component lifecycle.
**How to avoid:** Use `useRef` to track timer IDs and `useEffect` cleanup to clear them on unmount. This pattern is already used in the existing `UploadModal.tsx`.
**Warning signs:** React "Cannot update a component that is not mounted" warnings in console.

### Pitfall 5: Duplicate File Entries During Swap

**What goes wrong:** Both the upload-in-progress virtual entry AND the real file appear simultaneously in the file list during the swap window.
**Why it happens:** The real file appears in `children` (from IPNS sync) while the upload row is still showing the green completion flash.
**How to avoid:** During the merge in `FileList`, skip real files whose name matches an active upload entry that is in `complete` or `swapping` state. The upload row takes visual precedence until it finishes its animation and is removed.
**Warning signs:** Duplicate rows with the same filename in the file list.

### Pitfall 6: Progress Bar Causing Excessive Re-renders

**What goes wrong:** Axios progress events fire many times per second. If each progress update triggers a re-render of the entire `FileList`, performance degrades.
**Why it happens:** Zustand store update -> all subscribers re-render.
**How to avoid:** Use fine-grained selectors. `UploadListItem` should subscribe to only its own file's progress: `useUploadStore(s => s.files.get(fileId)?.progress)`. The `FileList` component subscribes to only the _set of upload file IDs_ (for merging), not their progress values.
**Warning signs:** Jank during upload, React DevTools showing frequent `FileList` re-renders.

## Code Examples

### Upload Store Extension

```typescript
// Source: Existing upload.store.ts pattern + UI-SPEC recommendation
type PerFileUpload = {
  id: string;
  filename: string;
  targetFolderId: string;
  status: 'encrypting' | 'uploading' | 'complete' | 'error' | 'cancelled';
  progress: number;
  error: string | null;
  cancelSource: ReturnType<typeof axios.CancelToken.source> | null;
};

// In create<UploadState>:
files: new Map<string, PerFileUpload>(),

addFile: (id, filename, targetFolderId) =>
  set((state) => {
    const next = new Map(state.files);
    next.set(id, {
      id,
      filename,
      targetFolderId,
      status: 'encrypting',
      progress: 0,
      error: null,
      cancelSource: axios.CancelToken.source(),
    });
    return { files: next };
  }),

updateFileProgress: (id, progress) =>
  set((state) => {
    const file = state.files.get(id);
    if (!file) return state;
    const next = new Map(state.files);
    next.set(id, { ...file, status: 'uploading', progress });
    return { files: next };
  }),
```

### Virtual Entry Merging in FileList

```typescript
// Source: FileList.tsx sortItems pattern + D-01/D-02 decisions
import { useUploadStore } from '../../stores/upload.store';

// Inside FileList component:
const uploadFiles = useUploadStore((s) => {
  const entries: PerFileUpload[] = [];
  for (const f of s.files.values()) {
    if (f.targetFolderId === parentId && f.status !== 'cancelled') {
      entries.push(f);
    }
  }
  return entries;
});

// Create virtual FolderChild entries for uploads
const uploadEntries: (FolderChild & { _uploading: true })[] = uploadFiles.map((f) => ({
  type: 'file' as const,
  id: f.id,
  name: f.filename,
  fileMetaIpnsName: '',
  createdAt: Date.now(),
  modifiedAt: Date.now(),
  _uploading: true as const,
}));

// Merge and sort
const allItems = [...items, ...uploadEntries];
const sortedItems = sortItems(allItems);

// In render, check _uploading flag:
{sortedItems.map((item) =>
  '_uploading' in item ? (
    <UploadListItem key={item.id} fileId={item.id} />
  ) : (
    <FileListItem key={item.id} item={item} ... />
  )
)}
```

### UploadListItem Component

```typescript
// Source: UI-SPEC interaction contract + existing FileListItem grid layout
function UploadListItem({ fileId }: { fileId: string }) {
  const file = useUploadStore((s) => s.files.get(fileId));
  const cancelFile = useUploadStore((s) => s.cancelFile);
  const removeFile = useUploadStore((s) => s.removeFile);

  if (!file) return null;

  const isError = file.status === 'error';
  const isComplete = file.status === 'complete';

  return (
    <div
      className={`file-list-item upload-inline-row ${isError ? 'upload-inline-row--error' : ''}`}
      role="row"
    >
      <div className="file-list-item-row-top" role="gridcell">
        <span className="file-list-item-icon upload-inline-icon" aria-hidden="true">
          {isError ? '[!]' : '[^]'}
        </span>
        <div className="upload-inline-name-wrapper">
          <span className="file-list-item-name">{file.filename}</span>
          <div className={`upload-inline-progress-bar ${file.status === 'encrypting' ? 'upload-inline-progress-bar--pulse' : ''}`}>
            <div
              className="upload-inline-progress-fill"
              style={{ width: `${file.progress}%` }}
              data-status={file.status}
              role="progressbar"
              aria-valuenow={file.progress}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`Upload progress for ${file.filename}`}
            />
          </div>
        </div>
      </div>
      <div className="file-list-item-row-bottom">
        <span className="file-list-item-size" role="gridcell">{'--'}</span>
        <span className="file-list-item-date" role="gridcell">
          {/* Action buttons in date column area */}
          {!isComplete && !isError && (
            <button type="button" className="upload-inline-btn" onClick={() => cancelFile(fileId)}
              aria-label={`Cancel upload of ${file.filename}`}>
              {'[x]'}
            </button>
          )}
          {isError && (
            <>
              <button type="button" className="upload-inline-btn upload-inline-btn--retry"
                aria-label={`Retry upload of ${file.filename}`} title="Retry upload">
                {'[R]'}
              </button>
              <button type="button" className="upload-inline-btn"
                onClick={() => removeFile(fileId)}
                aria-label={`Dismiss failed upload of ${file.filename}`} title="Dismiss error">
                {'[x]'}
              </button>
            </>
          )}
        </span>
      </div>
    </div>
  );
}
```

## State of the Art

| Old Approach                       | Current Approach           | When Changed | Impact                                              |
| ---------------------------------- | -------------------------- | ------------ | --------------------------------------------------- |
| Floating popup modal (UploadModal) | Inline rows in file list   | This phase   | Users see upload progress in context of their files |
| Batch-level progress tracking      | Per-file progress tracking | This phase   | Enables independent cancel/retry/dismiss per file   |
| Single CancelToken for batch       | Per-file CancelToken       | This phase   | Cancel one file without affecting batch             |

## Validation Architecture

### Test Framework

| Property           | Value                                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------ |
| Framework          | Playwright (web E2E)                                                                                               |
| Config file        | `tests/web-e2e/playwright.config.ts`                                                                               |
| Quick run command  | `pnpm --filter @cipherbox/web-e2e exec playwright test tests/full-workflow.spec.ts --timeout 180000`               |
| Full suite command | `BASE_URL=https://app-staging.cipherbox.cc pnpm --filter @cipherbox/web-e2e exec playwright test --timeout 180000` |

### Phase Requirements to Test Map

This phase has no formal requirement IDs. Validation is against the user decisions (D-01 through D-11).

| Decision  | Behavior                                           | Test Type  | Automated?       | Notes                                      |
| --------- | -------------------------------------------------- | ---------- | ---------------- | ------------------------------------------ |
| D-01/D-02 | Upload rows appear inline at alphabetical position | E2E/visual | Playwright MCP   | Verify row position after upload starts    |
| D-03/D-04 | Progress bar visible, no percentage text           | E2E/visual | Playwright MCP   | Screenshot + DOM assertion                 |
| D-05/D-06 | Green flash then swap to real file                 | Manual     | No               | Timing-dependent animation                 |
| D-07      | Per-file cancel button works                       | E2E        | Playwright MCP   | Click cancel, verify row disappears        |
| D-08      | Cancelled row disappears immediately               | E2E        | Playwright MCP   | Assert row removed from DOM                |
| D-09/D-10 | Error state with retry/dismiss                     | Manual     | No               | Requires simulating upload failure         |
| D-11      | UploadModal/UploadItem deleted                     | Static     | Grep/build check | Verify files deleted, no import references |

### Sampling Rate

- **Per task commit:** `pnpm typecheck` + `pnpm lint`
- **Per wave merge:** Full E2E suite against staging
- **Phase gate:** Full suite green + Playwright MCP visual verification

### Wave 0 Gaps

- No unit tests exist for upload store -- not blocking (store logic is simple Zustand set/get)
- E2E upload tests (`full-workflow.spec.ts`) test the upload zone page object -- may need updates if CSS class names change
- Upload zone page object (`upload-zone.page.ts`) references `.upload-zone-uploading` class -- verify this still works after refactor

## Open Questions

1. **Retry mechanism for failed uploads**
   - What we know: D-09 specifies retry button. The existing `upload.service.ts` has `withRetry()` with exponential backoff for individual IPFS calls, but no retry at the per-file level from the UI.
   - What's unclear: Should retry re-encrypt the file from the original `File` object, or cache the encrypted blob? Caching encrypted data avoids re-encryption cost but increases memory usage.
   - Recommendation: Re-encrypt from scratch on retry. The `File` object reference is kept in the closure of `useDropUpload.handleFileDrop`. For retry to work, the file ID and original `File` reference need to be stored somewhere accessible. The simplest approach: store the `File` reference in `PerFileUpload` (it's already in memory during the upload loop). The upload loop should continue past failed files and let the user retry individually.

2. **Upload entries for duplicate/replacement files**
   - What we know: `useDropUpload` handles duplicate files separately (encrypts + uploads to IPFS but doesn't register in folder). These show up in the `pendingReplacements` array for the `ReplaceFileDialog`.
   - What's unclear: Should duplicate file uploads also show inline progress rows?
   - Recommendation: Yes, show inline progress for duplicate uploads too. They go through the same encrypt+upload pipeline. After upload completes, the `ReplaceFileDialog` appears for the user to decide. The inline row can transition to `complete` state normally since the file is uploaded (just not registered yet).

3. **SharedFileBrowser upload integration**
   - What we know: `SharedFileBrowser` has its own upload mechanism that doesn't use `UploadModal` or `useUploadStore`. It uses a direct file input + SDK `uploadFile()`.
   - What's unclear: Should shared folder uploads also get inline progress?
   - Recommendation: Out of scope for this phase. The SharedFileBrowser is a separate component with its own state management. Inline progress for shared folders can be a follow-up.

## Sources

### Primary (HIGH confidence)

- Direct source code analysis of all referenced files in CONTEXT.md canonical_refs
- `apps/web/src/stores/upload.store.ts` -- current store shape and actions
- `apps/web/src/components/file-browser/FileList.tsx` -- current sort and render pattern
- `apps/web/src/components/file-browser/FileListItem.tsx` -- grid layout and interaction patterns
- `apps/web/src/styles/file-browser.css` -- grid template: `1fr 120px 180px`
- `apps/web/src/styles/responsive.css` -- mobile breakpoint: `1fr auto` (date/size hidden)
- `apps/web/src/hooks/useDropUpload.ts` -- upload loop using `useUploadStore.getState()` pattern
- `.planning/phases/36-inline-upload-progress/36-UI-SPEC.md` -- visual and interaction contract
- `packages/core/src/folder/types.ts` -- `FolderChild = FolderEntry | FilePointer` type definition
- `packages/core/src/file/types.ts` -- `FilePointer` type with required fields

### Secondary (MEDIUM confidence)

- `apps/web/CLAUDE.md` -- coding guidelines (ARIA, focus-visible, modern CSS syntax)
- `tests/web-e2e/page-objects/file-browser/upload-zone.page.ts` -- E2E test patterns for upload

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- no new dependencies, pure refactor of existing code
- Architecture: HIGH -- well-understood patterns (Zustand store extension, component composition, CSS grid matching)
- Pitfalls: HIGH -- based on direct analysis of existing code patterns and documented gotchas in project memory (stale Zustand closures, timer cleanup)

**Research date:** 2026-03-30
**Valid until:** 2026-04-30 (stable -- no external dependency changes expected)
