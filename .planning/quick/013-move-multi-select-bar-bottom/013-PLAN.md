---
phase: quick
plan: 013
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/components/file-browser/FileBrowser.tsx
  - apps/web/src/styles/file-browser.css
autonomous: true

must_haves:
  truths:
    - 'When 2+ items are selected, the action bar appears at the bottom of the file list, not above it'
    - 'The action bar stays visually anchored to the bottom of the file list container'
    - 'All batch action buttons (download, move, delete, clear) still function correctly'
  artifacts:
    - path: 'apps/web/src/components/file-browser/FileBrowser.tsx'
      provides: 'SelectionActionBar rendered after FileList'
    - path: 'apps/web/src/styles/file-browser.css'
      provides: 'Updated selection-action-bar CSS with border-top instead of border-bottom'
  key_links:
    - from: 'FileBrowser.tsx'
      to: 'SelectionActionBar'
      via: 'JSX render order — bar appears after FileList'
      pattern: 'FileList.*SelectionActionBar'
---

<objective>
Move the multi-select action bar from above the file list to below it.

Purpose: The selection action bar currently appears between the toolbar/breadcrumbs and the file list, which visually separates the user from their files. Placing it at the bottom keeps the file list anchored to the toolbar and puts the action bar closer to where selected items visually end.

Output: Updated FileBrowser.tsx render order and CSS border adjustment.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/components/file-browser/FileBrowser.tsx
@apps/web/src/components/file-browser/SelectionActionBar.tsx
@apps/web/src/styles/file-browser.css
</context>

<tasks>

<task type="auto">
  <name>Task 1: Move SelectionActionBar below FileList and update CSS</name>
  <files>
    apps/web/src/components/file-browser/FileBrowser.tsx
    apps/web/src/styles/file-browser.css
  </files>
  <action>
In `FileBrowser.tsx`, move the SelectionActionBar JSX block (currently at lines 907-917, between the vault-syncing state and the file list) to render AFTER the FileList and EmptyState blocks. Specifically, move it from its current position to just after the EmptyState conditional (line 939), so the render order becomes:

1. Toolbar (breadcrumbs + actions)
2. OfflineBanner
3. Loading state
4. Vault syncing state
5. FileList (or EmptyState)
6. **SelectionActionBar** (moved here)
7. Context menu, dialogs, etc.

The JSX block to move is:

```tsx
{
  /* Selection action bar */
}
{
  multiSelectActive && selectedIds.size > 1 && (
    <SelectionActionBar
      selectedItems={selectedItems}
      isLoading={isOperating || isDownloading}
      onClearSelection={clearSelection}
      onDownload={handleBatchDownload}
      onMove={handleBatchMoveClick}
      onDelete={handleBatchDeleteClick}
    />
  );
}
```

In `file-browser.css`, update the `.selection-action-bar` rule (around line 576-586):

- Change `border-bottom` to `border-top` (since the bar now sits below the file list, the accent border should be on top)
- Keep all other styles the same (flex layout, padding, background, font)

The updated rule should be:

```css
.selection-action-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-md);
  padding: var(--spacing-xs) 20px;
  background-color: var(--color-green-darker);
  border-top: var(--border-thickness) solid var(--color-green-primary);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-sm);
}
```

  </action>
  <verify>
Run `pnpm --filter web build` to confirm no TypeScript or build errors. Visually verify in browser at http://localhost:5173 by selecting 2+ files — the action bar should appear below the file list with a green top border.
  </verify>
  <done>
SelectionActionBar renders below the FileList. The green accent border is on top of the bar. All batch actions (download, move, delete, clear) remain functional.
  </done>
</task>

</tasks>

<verification>
- `pnpm --filter web build` passes without errors
- Select 2+ items in the file browser: action bar appears at the bottom of the file list, not above it
- Action bar has `border-top` (green accent line on top edge)
- Batch download, move, delete, and clear selection buttons all work
- Mobile responsive layout still stacks the action bar correctly (flex-wrap in responsive.css is unaffected)
</verification>

<success_criteria>
The multi-select action bar appears at the bottom of the file list when 2+ items are selected, with the green accent border on top. Build passes. No functional regressions.
</success_criteria>

<output>
After completion, create `.planning/quick/013-move-multi-select-bar-bottom/013-SUMMARY.md`
</output>
