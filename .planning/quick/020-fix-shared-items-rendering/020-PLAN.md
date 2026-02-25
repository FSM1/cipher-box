---
phase: quick
plan: 020
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/styles/shared-browser.css
  - apps/web/src/styles/responsive.css
autonomous: true

must_haves:
  truths:
    - "Shared items in list view display as a horizontal grid row with NAME, SHARED BY, and DATE columns"
    - "Items inside a shared folder display as a horizontal grid row with NAME, SIZE, and MODIFIED columns"
    - "Parent directory row [..] displays as a horizontal grid row matching the column layout"
    - "On mobile (<768px), shared rows collapse to single-column NAME-only layout, hiding SIZE/DATE/SHARED BY"
  artifacts:
    - path: "apps/web/src/styles/shared-browser.css"
      provides: "Grid layout styles for .file-list-row and .file-list-cell-* classes"
      contains: "grid-template-columns"
    - path: "apps/web/src/styles/responsive.css"
      provides: "Mobile responsive overrides for shared browser rows"
      contains: "file-list-row"
  key_links:
    - from: "apps/web/src/components/file-browser/SharedFileBrowser.tsx"
      to: "apps/web/src/styles/shared-browser.css"
      via: "CSS class names: .file-list-row, .file-list-cell-name, .file-list-cell-size, .file-list-cell-date"
      pattern: "file-list-row|file-list-cell"
---

<objective>
Fix the completely broken rendering of shared items in the "shared with me" view. Rows currently stack vertically because CSS class names used in SharedFileBrowser.tsx (.file-list-row, .file-list-cell-*) have NO CSS definitions anywhere. Add grid layout styles matching the existing .file-list-item pattern from file-browser.css.

Purpose: The shared browser is visually unusable -- cells stack vertically instead of displaying as horizontal grid rows.
Output: Properly styled shared item rows with 3-column grid layout on desktop and collapsed layout on mobile.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/styles/shared-browser.css
@apps/web/src/styles/file-browser.css
@apps/web/src/styles/responsive.css
@apps/web/src/components/file-browser/SharedFileBrowser.tsx
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add grid layout styles for shared browser rows and cells</name>
  <files>apps/web/src/styles/shared-browser.css</files>
  <action>
Add CSS rules to shared-browser.css for the missing classes. Model these after the .file-list-item styles in file-browser.css (lines 296-306) but adapted for the shared browser's class names.

Add these rule blocks (insert after the existing `.shared-list-row:focus-visible` block, before the `/* Error state */` section):

1. `.file-list-row` -- base row style:
   - `display: grid`
   - `grid-template-columns: 1fr 120px 180px` (matches .file-list-header and .file-list-item)
   - `gap: var(--spacing-md)`
   - `padding: var(--spacing-sm) var(--spacing-md)`
   - `cursor: pointer`
   - `transition: background-color 0.15s ease`
   - `border-bottom: var(--border-thickness) solid var(--color-border-dim)`
   - `font-family: var(--font-family-mono)`

2. `.file-list-row:last-child` -- remove bottom border on last row:
   - `border-bottom: none`

3. `.file-list-row:hover` -- hover highlight:
   - `background-color: var(--color-green-darker)`

4. `.file-list-row:focus-visible` -- keyboard focus (accessibility requirement per CLAUDE.md):
   - `outline: 1px solid var(--color-green-primary)`
   - `outline-offset: -1px`

5. `.file-list-row--parent` -- parent directory row:
   - `cursor: pointer`

6. `.file-list-row--parent:hover`:
   - `background-color: var(--color-green-darker)`

7. `.file-list-cell` -- base cell style:
   - `display: flex`
   - `align-items: center`
   - `min-width: 0` (prevent overflow)

8. `.file-list-cell-name` -- name column:
   - `display: flex`
   - `align-items: center`
   - `gap: 6px`
   - `min-width: 0` (allow text truncation)

9. `.file-list-cell-size` -- size column:
   - `display: flex`
   - `align-items: center`
   - `color: var(--color-text-secondary)`
   - `font-size: var(--font-size-sm)`

10. `.file-list-cell-date` -- date column:
    - `display: flex`
    - `align-items: center`
    - `color: var(--color-text-secondary)`
    - `font-size: var(--font-size-sm)`

11. `.file-icon` -- icon in shared rows:
    - `font-size: var(--font-size-sm)`
    - `flex-shrink: 0`

12. `.file-name` -- file/folder name text:
    - `white-space: nowrap`
    - `overflow: hidden`
    - `text-overflow: ellipsis`
    - `color: var(--color-text-primary)`
    - `font-size: var(--font-size-sm)`

IMPORTANT: Use modern CSS color syntax (space-separated, NOT comma rgba()) per CLAUDE.md coding guidelines.
IMPORTANT: Scope all these rules inside `.shared-browser` to avoid leaking styles to the main file browser. Use `.shared-browser .file-list-row` etc. This prevents conflicts with file-browser.css which uses different class names (.file-list-item).
  </action>
  <verify>
Run `cd /home/user/cipher-box && npx grep-css-classes` or manually verify:
1. `grep 'file-list-row' apps/web/src/styles/shared-browser.css` returns multiple matches
2. `grep 'grid-template-columns' apps/web/src/styles/shared-browser.css` returns at least 1 match
3. `grep 'file-list-cell' apps/web/src/styles/shared-browser.css` returns multiple matches
4. `grep 'file-icon' apps/web/src/styles/shared-browser.css` returns at least 1 match
5. `grep 'file-name' apps/web/src/styles/shared-browser.css` returns at least 1 match
6. Run `cd /home/user/cipher-box && npm run build --workspace=apps/web` to confirm no CSS syntax errors
  </verify>
  <done>
All .file-list-row, .file-list-cell-*, .file-icon, and .file-name classes have CSS definitions scoped under .shared-browser. Shared rows display as 3-column grid (1fr 120px 180px) matching the header. Build passes.
  </done>
</task>

<task type="auto">
  <name>Task 2: Add mobile responsive overrides for shared browser rows</name>
  <files>apps/web/src/styles/responsive.css</files>
  <action>
Add mobile responsive overrides for the shared browser's .file-list-row classes inside the existing `@media (max-width: 768px)` block in responsive.css. Place them right after the existing `.file-list-item` responsive rules (around line 99).

Add these rules inside the existing `@media (max-width: 768px)` block:

1. `.shared-browser .file-list-row` -- collapse to name-only on mobile:
   - `grid-template-columns: 1fr`

2. `.shared-browser .file-list-cell-size`, `.shared-browser .file-list-cell-date` -- hide size and date:
   - `display: none`

3. `.shared-browser .shared-by-cell` -- hide shared-by column on mobile:
   - `display: none`

4. `.shared-browser .file-list-header-shared-by` -- hide shared-by header on mobile:
   - `display: none`

5. Also update `.shared-browser .file-list-header` to use single column on mobile:
   - `grid-template-columns: 1fr`

These mirror the existing pattern where `.file-list-item` gets `grid-template-columns: 1fr auto` and size/date columns are hidden (lines 96-110 of responsive.css).

IMPORTANT: Add these inside the EXISTING `@media (max-width: 768px)` block. Do NOT create a new media query block.
  </action>
  <verify>
1. `grep -A2 'shared-browser.*file-list-row' apps/web/src/styles/responsive.css` shows the mobile override
2. `grep 'shared-by-cell' apps/web/src/styles/responsive.css` returns match for hidden column
3. Run `cd /home/user/cipher-box && npm run build --workspace=apps/web` to confirm no CSS syntax errors
  </verify>
  <done>
On mobile viewports (<768px), shared browser rows collapse to single-column layout. Size, date, and shared-by columns are hidden. Build passes with no errors.
  </done>
</task>

</tasks>

<verification>
1. `npm run build --workspace=apps/web` passes with no errors
2. Every CSS class used in SharedFileBrowser.tsx has a corresponding CSS definition:
   - .file-list-row -> shared-browser.css (scoped under .shared-browser)
   - .file-list-row--parent -> shared-browser.css
   - .file-list-cell -> shared-browser.css
   - .file-list-cell-name -> shared-browser.css
   - .file-list-cell-size -> shared-browser.css
   - .file-list-cell-date -> shared-browser.css
   - .file-icon -> shared-browser.css
   - .file-name -> shared-browser.css
3. Grid template (1fr 120px 180px) on rows matches the header grid template
4. Mobile responsive rules hide secondary columns on small screens
5. Focus-visible styles present on .file-list-row for keyboard accessibility
</verification>

<success_criteria>
- Shared items in list view render as horizontal 3-column rows (NAME | SHARED BY | DATE)
- Items inside shared folders render as horizontal 3-column rows (NAME | SIZE | MODIFIED)
- Parent directory [..] row renders as horizontal 3-column row
- Hover and focus-visible states work on all rows
- Mobile layout collapses to single NAME column
- Web app builds successfully with no CSS errors
</success_criteria>

<output>
After completion, create `.planning/quick/020-fix-shared-items-rendering/020-SUMMARY.md`
</output>
