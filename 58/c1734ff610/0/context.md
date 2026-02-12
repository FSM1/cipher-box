# Session Context

**Session ID:** 2847f9c8-1e3e-4a28-8c8d-024789eba97d

**Commit Message:** Implement the following plan:

# Plan: Always-Visible Checkboxes + Multi

## Prompt

Implement the following plan:

# Plan: Always-Visible Checkboxes + Multi-Select DnD

## Context

Two UX issues with the multi-file selection feature on branch `claude/multi-file-actions-selection-9fl2H`:

1. **Checkboxes hidden by default** — Item and header checkboxes use `display: none` and only appear on hover or when multi-select is active. User wants them always visible.
2. **DnD ignores multi-selection** — Dragging a selected item only moves that single item. When multiple items are selected and you drag one of them, all selected items should move together.

## Files to Modify

| File | Change |
|------|--------|
| `apps/web/src/styles/file-browser.css` | Make checkboxes always visible |
| `apps/web/src/components/file-browser/FileListItem.tsx` | Include `selectedIds` in drag data; always show checkbox |
| `apps/web/src/components/file-browser/FileList.tsx` | Pass `selectedIds` to FileListItem; always show header checkbox |
| `apps/web/src/components/file-browser/FileBrowser.tsx` | Handle multi-item drop in `handleDropOnFolder` |
| `apps/web/src/components/file-browser/Breadcrumbs.tsx` | Handle multi-item drop payload |

---

## 1. Always-Visible Checkboxes

### CSS (`file-browser.css` lines 532-588)

Change both `.file-list-header-checkbox` and `.file-list-item-checkbox` from `display: none` to `display: inline`. Remove the `--visible` modifier rules and the hover rules since they're now redundant.

**Before:**
```css
.file-list-header-checkbox { display: none; ... }
.file-list-header-checkbox--visible { display: inline; }
.file-list-item-checkbox { display: none; ... }
.file-list-item-checkbox--visible { display: inline; }
.file-list-item:hover .file-list-item-checkbox { display: inline; }
.file-list:hover .file-list-header-checkbox { display: inline; }
```

**After:**
```css
.file-list-header-checkbox { display: inline; ... }
/* Remove --visible modifier rules */
/* Remove hover display rules */
.file-list-item-checkbox { display: inline; ... }
```

### Component cleanup

- **FileListItem.tsx** (line 342): Remove the conditional `--visible` class toggle — checkbox span no longer needs it. Simplify to just `className="file-list-item-checkbox"`.
- **FileList.tsx** (line 107): Same for header checkbox — simplify to `className="file-list-header-checkbox"`.
- **FileList.tsx**: The `multiSelectActive` prop can remain (used for other things potentially) but no longer drives checkbox visibility.

---

## 2. Multi-Select Drag and Drop

### Approach

When dragging an item that is part of a multi-selection, include all selected items in the drag data. Drop handlers then move all items, not just one.

### Drag data format change

**Current** (single item):
```json
{ "id": "abc", "type": "file", "parentId": "xyz" }
```

**New** (always an array — even single items wrapped for consistency):
```json
{
  "items": [
    { "id": "abc", "type": "file" },
    { "id": "def", "type": "folder" }
  ],
  "parentId": "xyz"
}
```

### FileListItem.tsx changes

- Add `selectedIds: Set<string>` prop (needed to know which items are part of the drag)
- Add `allItems: FolderChild[]` prop (needed to get type info for selected items)
- In `handleDragStart`: if `isSelected && selectedIds.size > 1`, serialize all selected items. Otherwise serialize just the dragged item. Either way, use the new `items` array format.

### FileList.tsx changes

- Pass `selectedIds` and `items` to each `<FileListItem>`.

### FileListItem.tsx drop handler

- In `handleDrop`: parse new format. If `items` array has multiple entries, call a new `onDropMultiple` callback. If single item, call existing `onDrop`.
- Add `onDropMultiple?: (items: Array<{id: string; type: 'file'|'folder'}>, sourceParentId: string) => void` prop.

### FileBrowser.tsx changes

- `handleDropOnFolder`: Check for multi-item payload. If multi-item, call `moveItems(items, sourceParentId, destFolderId)` then `clearSelection()`. If single item, call existing `moveItem()`.
- Simplify: change `handleDropOnFolder` signature to accept the new format directly, or create a new handler.

**Simpler approach**: Keep `handleDropOnFolder` taking the same 4 args for single-item, but add a new `handleDropMultipleOnFolder` for multi-item drops. FileList passes both down.

**Even simpler approach**: Change `handleDropOnFolder` to accept an array:
```ts
const handleDropOnFolder = useCallback(
  async (
    items: Array<{ id: string; type: 'file' | 'folder' }>,
    sourceParentId: string,
    destFolderId: string
  ) => {
    if (items.length === 1) {
      await moveItem(items[0].id, items[0].type, sourceParentId, destFolderId);
    } else {
      await moveItems(items, sourceParentId, destFolderId);
      clearSelection();
    }
  },
  [moveItem, moveItems, clearSelection]
);
```

This changes the signature, so all callers (FileListItem `onDrop`, Breadcrumbs `onDrop`, the direct breadcrumb prop) need updating.

### Breadcrumbs.tsx changes

- Update `onDrop` prop type and the `handleDrop` internal function to parse the new `items` array format.
- Call `onDrop(items, parentId, destFolderId)` with the new signature.

### FileListItem.tsx `onDrop` signature change

- Change from `onDrop?(sourceId, sourceType, sourceParentId)` to `onDrop?(items: Array<{id: string; type: 'file'|'folder'}>, sourceParentId: string)`.
- Update `handleDrop` to parse new drag data format and call with new signature.

### FileList.tsx `onDropOnFolder` signature change

- Update prop type to match: `(items: Array<...>, sourceParentId: string, destFolderId: string) => void`
- Update the inline callback that wraps it.

---

## Verification

1. `npx tsc --noEmit` — no type errors
2. `pnpm --filter web dev` — start the app
3. Manual verification via Playwright MCP:
   - Checkboxes visible without hovering
   - Select 2 files, drag one to a folder → both move
   - Select 2 files, drag one to breadcrumb → both move
   - Single item drag still works (drag unselected item → only that item moves)
4. Run E2E tests: `pnpm --filter e2e test`


If you need specific details from before exiting plan mode (like exact code snippets, error messages, or content you generated), read the full transcript at: /Users/michael/.REDACTED.jsonl

## Summary

All changes are complete. Here's a summary:

### Changes Made

**1. Always-visible checkboxes**
- `file-browser.css`: Changed `.file-list-header-checkbox` and `.file-list-item-checkbox` from `display: none` to `display: inline`. Removed `--visible` modifier rules and hover display rules.
- `FileListItem.tsx`: Removed `multiSelectActive` prop (no longer needed) and simplified checkbox className.
- `FileList.tsx`: Removed `multiSelectActive` prop and its forwarding to FileListItem. Simplified header checkbox className.
- `FileBrowser.tsx`: Removed `multiSelectActive` prop from `<FileList>` usage.

**2. Multi-select drag and drop**
- `FileListItem.tsx`: Added `selectedIds` and `allItems` props. `handleDragStart` now serializes all selected items when dragging a selected item in multi-select mode using new format `{ items: [...], parentId }`. `handleDrop` parses the new format. Changed `onDrop` signature to `(items: DragItem[], sourceParentId: string)`. Exported `DragItem` type.
- `FileList.tsx`: Updated `onDropOnFolder` prop to new signature `(items, sourceParentId, destFolderId)`. Passes `selectedIds` and `items` to each FileListItem.
- `FileBrowser.tsx`: `handleDropOnFolder` now accepts an items array — single items use `moveItem()`, multi-items use `moveItems()` + `clearSelection()`.
- `Breadcrumbs.tsx`: Updated `onDrop` prop type and `handleDrop` to parse the new `{ items, parentId }` format.

**Verification**: `tsc --noEmit` passes with 0 errors, `eslint` passes clean. Visual verification blocked by Docker services being down — will need manual testing when services are available.

## Key Actions

- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/styles/file-browser.css
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/components/file-browser/FileListItem.tsx
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/components/file-browser/FileList.tsx
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/components/file-browser/FileBrowser.tsx
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/components/file-browser/Breadcrumbs.tsx
- - **TaskCreate**: Change checkbox display from none to inline, remove --visible modifiers and hover rules
- - **TaskCreate**: Change drag data format to items array, update all drag/drop handlers across FileListItem, FileList, FileBrowser, and Breadcrumbs
- - **TaskCreate**: Run tsc --noEmit to verify no type errors, then visually verify with Playwright
- - **TaskUpdate**: 
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/styles/file-browser.css
