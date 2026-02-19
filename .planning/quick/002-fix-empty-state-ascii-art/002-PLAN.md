---
phase: quick-002
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/components/file-browser/EmptyState.tsx
  - apps/web/src/components/file-browser/FileBrowser.tsx
  - apps/web/src/styles/file-browser.css
  - apps/web/src/index.css
autonomous: true

must_haves:
  truths:
    - 'Empty folder shows terminal-window ASCII art with box-drawing characters'
    - 'Terminal shows $ ls -la command, total 0 output, and $ cursor with block'
    - 'No embedded UploadZone inside the empty state (toolbar upload is sufficient)'
    - 'ASCII art is green (#00D084), label is muted (#8b9a8f), hint is dim (#4a5a4e)'
  artifacts:
    - path: 'apps/web/src/components/file-browser/EmptyState.tsx'
      provides: 'Terminal-style empty state without UploadZone'
      contains: 'ls -la'
    - path: 'apps/web/src/styles/file-browser.css'
      provides: 'Empty state styles without .empty-state-upload class'
  key_links:
    - from: 'apps/web/src/components/file-browser/FileBrowser.tsx'
      to: 'EmptyState'
      via: 'import and render without folderId prop'
      pattern: '<EmptyState'
---

<objective>
Replace the basic ASCII art box in EmptyState with a polished terminal-window design using
box-drawing characters, and remove the redundant embedded UploadZone component (the toolbar
already provides upload functionality).

Purpose: Close the cosmetic UAT gap from Phase 6.3 -- the empty state should match the
approved "EmptyState - Improved" design from the Pencil file.

Output: Updated EmptyState.tsx (no props, no UploadZone, terminal ASCII art), updated
FileBrowser.tsx (no folderId prop passed), updated CSS (new color tokens, removed unused class).
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/components/file-browser/EmptyState.tsx
@apps/web/src/components/file-browser/FileBrowser.tsx
@apps/web/src/styles/file-browser.css
@apps/web/src/index.css
@designs/cipher-box-design.pen (frame "EmptyState - Improved", node XyFqv)
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add CSS color tokens and update empty state styles</name>
  <files>
    apps/web/src/index.css
    apps/web/src/styles/file-browser.css
  </files>
  <action>
In `apps/web/src/index.css`, add two new design tokens in the `:root` block, after the
existing `--color-text-secondary` line (around line 26):

```css
--color-text-muted: #8b9a8f; /* Muted gray-green for labels */
--color-text-dim: #4a5a4e; /* Dim gray-green for hints */
```

In `apps/web/src/styles/file-browser.css`, make these changes to the Empty State section
(lines ~377-436):

1. Update `.empty-state-ascii` color from `var(--color-text-secondary)` to
   `var(--color-green-primary)` -- the terminal art should be bright green (#00D084).

2. Update `.empty-state-text` color from `var(--color-text-primary)` to
   `var(--color-text-muted)` -- the "// EMPTY DIRECTORY" label uses the muted tone (#8b9a8f).

3. Update `.empty-state-hint` color from `var(--color-text-secondary)` to
   `var(--color-text-dim)` -- the hint text uses the dimmer tone (#4a5a4e).

4. DELETE the `.empty-state-upload` rule block entirely (lines ~432-434):

   ```css
   .empty-state-upload {
     margin-top: var(--spacing-md);
   }
   ```

   This class is no longer used since UploadZone is removed from EmptyState.
   </action>
   <verify>
   Grep for `.empty-state-upload` in file-browser.css -- should return zero matches.
   Grep for `--color-text-muted` in index.css -- should return one match.
   Grep for `--color-text-dim` in index.css -- should return one match.
   Grep for `color-green-primary` in the `.empty-state-ascii` rule -- should match.
   </verify>
   <done>
   New color tokens exist in index.css. Empty state CSS uses correct design colors.
   The unused .empty-state-upload class is removed.
   </done>
   </task>

<task type="auto">
  <name>Task 2: Replace ASCII art and remove UploadZone from EmptyState</name>
  <files>
    apps/web/src/components/file-browser/EmptyState.tsx
    apps/web/src/components/file-browser/FileBrowser.tsx
  </files>
  <action>
Rewrite `apps/web/src/components/file-browser/EmptyState.tsx`:

1. REMOVE the `import { UploadZone }` import.
2. REMOVE the `EmptyStateProps` type and the `folderId` prop entirely. The component takes no props.
3. Replace the `asciiArt` constant with a terminal-window design using box-drawing characters.
   The exact string (use template literal, no leading whitespace on the box lines):

   ```ts
   const terminalArt = `┌──────────────────────┐
   │ $ ls -la             │
   │ total 0              │
   │ $ █                  │
   └──────────────────────┘`;
   ```

   IMPORTANT: The box must be visually aligned -- all lines the same width between the
   vertical bars. Use spaces to pad each line to equal length inside the box. The block
   cursor character is U+2588 (FULL BLOCK).

4. Update the JSX:
   - Replace `{asciiArt}` with `{terminalArt}` in the `<pre>`.
   - Change the hint text from `"drag files here or use upload"` to
     `"drag files here or use --upload"` (with `--` prefix for terminal aesthetic).
   - REMOVE the `<div className="empty-state-upload">` wrapper and the `<UploadZone>` inside it.
   - The component signature becomes `export function EmptyState()` with no arguments.

5. Update the JSDoc to reflect the component no longer accepts props or contains an upload zone.

In `apps/web/src/components/file-browser/FileBrowser.tsx`:

1. Find the line (around line 358): `<EmptyState folderId={currentFolderId} />`
2. Change it to: `<EmptyState />`
   (Remove the folderId prop since EmptyState no longer accepts it.)
   </action>
   <verify>
   Run `npx tsc --noEmit` from `apps/web/` to confirm no TypeScript errors.
   Grep EmptyState.tsx for "UploadZone" -- should return zero matches.
   Grep EmptyState.tsx for "folderId" -- should return zero matches.
   Grep EmptyState.tsx for "ls -la" -- should return one match.
   Grep FileBrowser.tsx for "folderId={currentFolderId}" near EmptyState -- should return zero matches.
   </verify>
   <done>
   EmptyState renders terminal-window ASCII art with box-drawing characters showing
   `$ ls -la` / `total 0` / `$ cursor`. No UploadZone, no props. FileBrowser passes
   no props to EmptyState. TypeScript compiles cleanly.
   </done>
   </task>

</tasks>

<verification>
1. `npx tsc --noEmit` in apps/web passes (no type errors from prop removal)
2. No references to UploadZone remain in EmptyState.tsx
3. No references to folderId remain in EmptyState.tsx
4. The terminal art contains box-drawing characters and "ls -la"
5. CSS color tokens --color-text-muted and --color-text-dim exist in index.css
6. .empty-state-upload CSS class is removed from file-browser.css
7. Visual check (Playwright if available): empty state shows terminal box, green art,
   muted label, dim hint text
</verification>

<success_criteria>

- EmptyState component renders a terminal-window with box-drawing chars (no old box ASCII)
- Terminal shows: $ ls -la, total 0, $ cursor-block
- No UploadZone inside EmptyState (toolbar handles uploads)
- EmptyState takes no props; FileBrowser renders `<EmptyState />` with no args
- Colors match design: ASCII art #00D084, label #8b9a8f, hint #4a5a4e
- TypeScript compilation succeeds
  </success_criteria>

<output>
After completion, create `.planning/quick/002-fix-empty-state-ascii-art/002-SUMMARY.md`
</output>
