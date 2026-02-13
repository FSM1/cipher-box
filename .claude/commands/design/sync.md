---
name: design:sync
description: Synchronize Pencil design file with app implementation. Detects UI drift and offers to update design or code.
argument-hint: '[check|PR#]'
allowed-tools:
  - Read
  - Write
  - Edit
  - Bash
  - Glob
  - Grep
  - Task
  - AskUserQuestion
  - mcp__pencil__*
  - mcp__playwright__*
---

<objective>
Detect drift between Pencil design files (`designs/*.pen`) and CSS/TSX implementation. Report discrepancies and offer to fix them — either updating the design to match code or vice versa.

Modes:

- **No args:** Check files changed on current branch vs main. Interactive — asks resolution direction.
- **`check`:** Same scope as no-args but report-only. No modifications.
- **`PR#`:** Check files changed in a specific PR. Report-only.

This skill lives outside `gsd/` to survive GSD updates.
</objective>

<execution_context>
@designs/DESIGN.md
</execution_context>

<context>
Arguments: $ARGUMENTS

@designs/DESIGN.md
</context>

<process>

### Step 1: Pre-flight

Check that design infrastructure exists:

```bash
DESIGN_FILE=$(ls designs/*.pen 2>/dev/null | head -1)
if [ -z "$DESIGN_FILE" ]; then
  echo "No .pen file found in designs/. Nothing to sync."
  exit 0
fi

DESIGN_DOC="designs/DESIGN.md"
if [ ! -f "$DESIGN_DOC" ]; then
  echo "Warning: designs/DESIGN.md not found. Token resolution will be limited."
fi
```

Check Pencil MCP availability by attempting a read:

```typescript
const editorState = await mcp__pencil__get_editor_state({ include_schema: false });
// If this fails, Pencil MCP is unavailable
```

If Pencil MCP is unavailable, report and exit:

```text
Pencil MCP not available. Cannot read design file.
Run this command with the Pencil editor open.
```

---

### Step 2: Identify changed UI files

Parse `$ARGUMENTS` to determine mode and scope:

**No args (default):**

```bash
# Files changed on current branch vs main
CHANGED_CSS=$(git diff --name-only main...HEAD -- '*.css' 2>/dev/null)
CHANGED_TSX=$(git diff --name-only main...HEAD -- '*.tsx' 2>/dev/null)
MODE="interactive"
```

**`check`:**

```bash
CHANGED_CSS=$(git diff --name-only main...HEAD -- '*.css' 2>/dev/null)
CHANGED_TSX=$(git diff --name-only main...HEAD -- '*.tsx' 2>/dev/null)
MODE="report-only"
```

**`PR#` (e.g., `42`):**

```bash
PR_NUM=$(echo "$ARGUMENTS" | grep -oE '[0-9]+')
CHANGED_CSS=$(gh pr diff $PR_NUM --name-only | grep '\.css$')
CHANGED_TSX=$(gh pr diff $PR_NUM --name-only | grep '\.tsx$')
MODE="report-only"
```

Combine and deduplicate:

```bash
CHANGED_UI_FILES=$(echo "$CHANGED_CSS
$CHANGED_TSX" | sort -u | grep -v '^$')
```

If no UI files changed:

```text
No CSS/TSX files changed on this branch. Nothing to sync.
```

Exit cleanly.

Report scope:

```text
## Design Sync

Mode: ${MODE}
Design file: ${DESIGN_FILE}
Changed UI files: ${count}

${list of files}
```

---

### Step 3: Build CSS-to-design-frame mapping

Map each changed file to its corresponding design frame using three-tier resolution:

#### Tier 1: Parse DESIGN.md component hierarchy

Read `designs/DESIGN.md` and extract the component hierarchy section. Match CSS file names (e.g., `FileList.css` -> `fileListContainer`) to frame IDs listed in the hierarchy.

```bash
# Extract frame IDs and names from DESIGN.md
grep -E '^\s*(├──|└──|│)' designs/DESIGN.md
```

Build mapping table from component names to Pencil frame IDs.

#### Tier 2: Pencil name-pattern search

For unmapped files, search by name pattern:

```typescript
// Search for frames matching the component name
const results = await mcp__pencil__batch_get({
  filePath: DESIGN_FILE,
  patterns: [{ name: componentNameRegex }],
  searchDepth: 3,
  readDepth: 1,
});
```

#### Tier 3: TSX import tracing

For still-unmapped CSS files, read the corresponding TSX file to find which component imports the CSS, then match that component name to a design frame.

```bash
# Find which TSX imports this CSS
grep -rl "import.*$(basename $CSS_FILE)" apps/web/src/ --include='*.tsx'
```

Build final mapping:

```text
| CSS File | Component | Design Frame | Frame ID | Status |
|----------|-----------|--------------|----------|--------|
| FileList.css | FileList | fileListContainer | A87rp | mapped |
| SelectionBar.css | SelectionActionBar | ? | ? | unmapped |
```

Report unmapped components — these may need new design frames.

---

### Step 4: Extract implementation values

For each changed CSS file:

1. Read the CSS file content
2. Extract property declarations (color, background, padding, margin, gap, font-size, font-weight, border, etc.)
3. Resolve `var()` references against the root CSS variables:

```bash
# Read root CSS variables
grep -E '--[a-z-]+\s*:' apps/web/src/index.css
```

Build a property map per component:

```json
{
  "FileList": {
    "background": "#000000",
    "color": "#00D084",
    "padding": "10px 24px",
    "border": "1px solid #003322",
    "font-size": "12px"
  }
}
```

Include file:line references for each property.

---

### Step 5: Extract design values

For each mapped design frame:

```typescript
const frameData = await mcp__pencil__batch_get({
  filePath: DESIGN_FILE,
  nodeIds: [frameId],
  readDepth: 2,
  resolveVariables: true,
});
```

Extract equivalent properties from the Pencil node data:

- `fill` -> background-color
- `textColor` / child text nodes -> color
- `padding` -> padding
- `gap` -> gap
- `fontSize`, `fontWeight` -> font-size, font-weight
- `stroke` -> border
- `cornerRadius` -> border-radius
- `layout` -> display/flex-direction

Build a matching property map per component from the design data.

---

### Step 6: Compare with normalization

Compare implementation values against design values with format normalization:

**Color normalization:**

- Convert all colors to lowercase hex: `rgb(0, 208, 132)` -> `#00d084`
- Handle alpha: `rgba(0, 208, 132, 0.4)` -> `#00d08466`
- Normalize shorthand: `#000` -> `#000000`

**Spacing normalization:**

- Expand shorthand: `padding: 10px` -> `10px 10px 10px 10px`
- Pencil `padding` (single number) -> `Npx Npx Npx Npx`
- Pencil `paddingTop/Right/Bottom/Left` -> individual sides

**Layout normalization:**

- Pencil `layout: "vertical"` -> CSS `flex-direction: column`
- Pencil `layout: "horizontal"` -> CSS `flex-direction: row`
- Pencil `gap: N` -> CSS `gap: Npx`

**Border normalization:**

- Pencil `stroke` + `strokeThickness` -> CSS `border: Npx solid color`
- Directional borders (border-left only) vs all-sides

For each property, classify as:

- **Match** — values equivalent after normalization
- **Mismatch** — values differ
- **Code-only** — property exists in CSS but not in design
- **Design-only** — property exists in design but not in CSS

---

### Step 7: Generate discrepancy report

Build a report table:

```markdown
## Discrepancy Report

**Branch:** $(git branch --show-current)
**Design file:** ${DESIGN_FILE}
**Checked:** ${count} components, ${total_props} properties

### Mismatches

| Component | Property | Design Value | Code Value | File:Line       |
| --------- | -------- | ------------ | ---------- | --------------- |
| FileList  | padding  | 12px         | 10px 24px  | FileList.css:15 |
| Header    | color    | #00D084      | #00d084    | Header.css:8    |

### Code-only properties (no design equivalent)

| Component    | Property   | Value                | File:Line           |
| ------------ | ---------- | -------------------- | ------------------- |
| SelectionBar | background | rgba(0,208,132,0.15) | SelectionBar.css:22 |

### Unmapped components

| CSS File         | Reason                         |
| ---------------- | ------------------------------ |
| NewComponent.css | No matching design frame found |

### Summary

- **Matched:** X properties
- **Mismatched:** Y properties
- **Code-only:** Z properties
- **Unmapped:** W components
```

If `MODE == "report-only"` (check or PR#): display report and exit.

If `MODE == "interactive"` and no mismatches: display "All synced!" and exit.

---

### Step 8: Ask resolution direction

Only runs in interactive mode with mismatches found:

```text
AskUserQuestion(
  header: "Resolution",
  question: "Found ${mismatch_count} discrepancies. How should they be resolved?",
  options: [
    { label: "Update design (Recommended)", description: "Update Pencil design frames to match current CSS implementation" },
    { label: "Update code", description: "Update CSS files to match Pencil design values" },
    { label: "Review individually", description: "Go through each mismatch and choose direction" },
    { label: "Skip", description: "Just show the report, don't change anything" }
  ],
  multiSelect: false
)
```

If "Skip": exit with report only.

---

### Step 9: Apply changes

**If "Update design to match code":**

For each mismatch, build `batch_design` operations:

```typescript
// Update design frame properties to match CSS
await mcp__pencil__batch_design({
  filePath: DESIGN_FILE,
  operations: `
U("${frameId}", { fill: "${cssBackgroundColor}" })
U("${frameId}/textNode", { textColor: "${cssColor}" })
`,
});
```

After applying changes, take screenshots to verify:

```typescript
await mcp__pencil__get_screenshot({
  filePath: DESIGN_FILE,
  nodeId: frameId,
});
```

**If "Update code to match design":**

For each mismatch, use Edit tool to update CSS values:

```text
Edit(file_path, old_value, new_value)
```

**If "Review individually":**

For each mismatch, present:

```text
${component}.${property}
  Design: ${designValue}
  Code:   ${codeValue} (${file}:${line})

-> Use design value / Use code value / Skip
```

Apply chosen direction for each.

**After all changes:**

Update `designs/DESIGN.md` if design tokens changed (color values, spacing, etc.).

---

### Step 10: Summary

Display what was changed:

```markdown
## Design Sync Complete

**Direction:** ${direction}
**Updated:** ${count} properties

### Changes Applied

| Component | Property | Old  | New       | Target |
| --------- | -------- | ---- | --------- | ------ |
| FileList  | padding  | 12px | 10px 24px | design |

${if design was modified:}
**Reminder:** Save the Pencil file to persist design changes.
Changes are in-memory only until saved from the Pencil editor.
```

</process>

<edge_cases>

**Missing design frame:**
When a CSS component has no corresponding design frame, offer to create a placeholder:

```text
Component "SelectionActionBar" has no design frame.
-> Create placeholder frame / Skip
```

If creating: insert a labeled frame in the design file with basic properties from CSS.

**Deleted component:**
When a design frame references a component whose CSS/TSX was deleted:

```text
Design frame "oldComponent" (ID: abc123) has no corresponding implementation.
This may be a stale design element.
-> Flag for removal / Skip
```

**CSS variable chains:**
Resolve full chain before comparison:

```css
--color-primary: #00d084;
--btn-bg: var(--color-primary);
.button {
  background: var(--btn-bg);
} /* resolves to #00D084 */
```

**Pencil MCP unavailable:**
Exit gracefully with instructions:

```text
Pencil MCP not available. To run design sync:
1. Open designs/cipher-box-design.pen in Pencil editor
2. Re-run /design:sync
```

**No .pen file:**
Exit immediately -- not an error, just nothing to sync.

</edge_cases>

<ui_keyword_heuristic>

<!-- SYNC: This heuristic appears in 4 locations. Keep all in sync:
  1. .claude/commands/gsd/quick.md:105
  2. .claude/get-shit-done/workflows/discuss-phase.md:505
  3. .claude/commands/design/sync.md (this file, used in post-task hooks)
  4. .claude/get-shit-done/workflows/execute-phase.md (design_sync_check step)
-->

The following regex detects UI-related task descriptions:

```bash
echo "$DESCRIPTION" | grep -iqE "ui|ux|style|restyle|design|layout|component|page|view|screen|display|button|form|modal|dialog|popover|tooltip|toast|dropdown|sidebar|header|footer|nav|menu|card|list|table|grid|icon|badge|avatar|breadcrumb|tab|color|font|typography|spacing|padding|margin|responsive|mobile|css|visual|appearance|interface|frontend|dashboard|browser|drag|drop|dnd|hover|focus|animation|transition|overlay|scroll|carousel|interaction|gesture|click|swipe|resize|collapse|expand|accordion|input|checkbox|radio|select|slider|toggle|switch|picker|upload|panel|drawer|toolbar|statusbar|banner|alert|notification|snackbar|thumbnail|preview|placeholder|skeleton|spinner|progress|loading"
```

</ui_keyword_heuristic>

<success_criteria>

- [ ] Design file exists and Pencil MCP is available
- [ ] Changed UI files identified from git diff
- [ ] CSS files mapped to design frames (3-tier resolution)
- [ ] Implementation values extracted with var() resolution
- [ ] Design values extracted via Pencil MCP
- [ ] Values compared with format normalization
- [ ] Discrepancy report generated with file:line references
- [ ] Resolution direction chosen (interactive mode) or report displayed (check/PR mode)
- [ ] Changes applied correctly to design or code
- [ ] Pencil save reminder displayed if design was modified
      </success_criteria>
