# Pencil Design Workflow

This document describes how to use Pencil MCP for design-first UI development within the GSD framework.

## Overview

Pencil is a design tool that produces `.pen` files (JSON format) containing UI specifications. The GSD framework integrates Pencil designs as the source of truth for UI phases.

**Design-first workflow:**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Design    │───▶│  Research   │───▶│   Execute   │───▶│   Verify    │
│  (Pencil)   │    │  (Extract)  │    │   (Build)   │    │  (Compare)  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      ▲                                                         │
      │                                                         │
      └──────────── (Fix discrepancies) ◀───────────────────────┘
```

## Phase Integration

### Research Phase: Design Extraction

When a phase involves UI work, spawn `ui-design-researcher` instead of or alongside `gsd-phase-researcher`.

**Triggers for UI research:**

- Phase name contains: "UI", "restyle", "design", "layout", "component"
- Phase goal mentions: visual, styling, interface, appearance
- CONTEXT.md references: design file, Pencil, mockups

**What ui-design-researcher does:**

1. Locates `.pen` files in `designs/` directory
2. Parses JSON to extract design tokens
3. Documents component specifications
4. Identifies missing designs (states not covered)
5. Produces design-focused RESEARCH.md

### Planning Phase: Design-Aware Tasks

The planner uses RESEARCH.md design specifications to create precise tasks:

```markdown
### Task 1: Implement header component styling

**Type:** auto

**From design frame:** bi8Au (Desktop File Browser)
**Component:** header (n386r)

**Implementation:**
- Background: var(--color-background) → #000000
- Border-bottom: var(--border-thickness) solid var(--color-border) → 1px #00D084
- Padding: var(--spacing-sm) var(--spacing-lg) → 12px 24px

**Verification:**
- CSS file has correct values
- Computed style matches at runtime (if Playwright available)
```

### Verification Phase: Design Comparison

After execution, spawn `ui-design-verifier` to compare implementation against design.

**What ui-design-verifier does:**

1. Loads design specifications from Pencil file
2. Checks CSS for exact values
3. Uses Playwright MCP (if available) for runtime verification
4. Documents discrepancies with file/line references
5. Produces design-compliance VERIFICATION.md

## Pencil MCP Tools

### If Pencil MCP is Available

```
mcp__pencil__read_design     - Read entire .pen file
mcp__pencil__get_frame       - Get specific frame by ID
mcp__pencil__get_colors      - Extract color palette
mcp__pencil__get_typography  - Extract font specifications
mcp__pencil__get_spacing     - Extract spacing values
mcp__pencil__get_components  - List component definitions
mcp__pencil__create_design   - Create new design element
```

### Fallback: Direct JSON Parsing

If Pencil MCP is not available, parse `.pen` files directly:

```bash
# Read design file
cat designs/app-design.pen | jq '.'

# Extract all frames
cat designs/app-design.pen | jq '.children[] | select(.type=="frame") | {id, name, width, height}'

# Extract colors
cat designs/app-design.pen | jq -r '.. | .fill? // empty' | sort -u | grep "^#"

# Extract typography
cat designs/app-design.pen | jq '.. | select(.type=="text") | {font: .fontFamily, size: .fontSize, weight: .fontWeight}'

# Extract spacing
cat designs/app-design.pen | jq '.. | .padding?, .gap?' | grep -v null | sort -u
```

## Design File Structure

### Pencil .pen Format

```json
{
  "version": "2.6",
  "children": [
    {
      "type": "frame",
      "id": "unique-id",
      "name": "Page Name",
      "width": 1440,
      "height": 900,
      "fill": "#000000",
      "layout": "vertical",
      "gap": 16,
      "padding": [12, 24],
      "children": [
        {
          "type": "text",
          "id": "text-id",
          "content": "Hello",
          "fill": "#00D084",
          "fontFamily": "JetBrains Mono",
          "fontSize": 14,
          "fontWeight": "600"
        },
        {
          "type": "frame",
          "id": "container-id",
          "name": "container",
          "stroke": {
            "align": "inside",
            "thickness": 1,
            "fill": "#00D084"
          },
          "children": [...]
        }
      ]
    }
  ]
}
```

### Key Properties

**Layout:**

- `layout`: "horizontal" | "vertical" | null (free positioning)
- `gap`: Space between children (pixels)
- `padding`: [vertical, horizontal] or [top, right, bottom, left]
- `justifyContent`: "flex_start" | "center" | "flex_end" | "space_between"
- `alignItems`: "flex_start" | "center" | "flex_end" | "stretch"

**Dimensions:**

- `width`: number (pixels) | "fill_container" | "hug_contents"
- `height`: number (pixels) | "fill_container" | "hug_contents"

**Styling:**

- `fill`: Hex color string (e.g., "#00D084")
- `stroke`: { align, thickness, fill }
- `effect`: { type: "shadow", blur, color, ... }
- `cornerRadius`: number (pixels)

**Typography:**

- `fontFamily`: Font name string
- `fontSize`: number (pixels)
- `fontWeight`: "normal" | "600" | "700" | number
- `content`: Text string

## Workflow Commands

### Starting UI-focused phases

```bash
# Research with design extraction
/gsd:research-phase 6.2  # Spawns ui-design-researcher for UI phases

# Plan with design specs
/gsd:plan-phase 6.2  # Creates design-aware tasks

# Execute
/gsd:execute-phase 6.2  # Implements per specifications

# Verify against design
/gsd:verify-work 6.2  # Spawns ui-design-verifier
```

### Manual design extraction

```bash
# Extract design tokens for a phase
jq -r '.children[] | select(.type=="frame")' designs/app-design.pen

# Generate CSS variables from design
cat designs/app-design.pen | jq -r '
  "/* Colors */",
  (.. | .fill? // empty | select(. != null) | select(startswith("#")) | "--color-" + . + ": " + . + ";"),
  "",
  "/* Font sizes */",
  (.. | select(.type=="text") | "--font-size-" + (.fontSize|tostring) + ": " + (.fontSize|tostring) + "px;")
' | sort -u
```

## Missing Design Handling

When designs don't exist for needed states:

### Option 1: Request from User

```markdown
## Missing Designs

The following states need Pencil designs before implementation:

1. **Upload progress modal** - Shows upload progress bar
2. **Error state** - Display when operation fails
3. **Empty folder** - Shown when folder has no contents

**Recommendation:** Create these in Pencil before proceeding.
```

### Option 2: Use Pencil MCP to Create

If Pencil MCP supports design creation:

```typescript
mcp__pencil__create_design({
  type: 'frame',
  name: 'Error Modal',
  width: 400,
  height: 200,
  children: [
    {
      type: 'text',
      content: 'Error',
      fill: '#EF4444',
      fontSize: 16,
      fontWeight: '600',
    },
  ],
});
```

### Option 3: Document Design Direction

Ask user for design direction, implement, then request design review:

```markdown
## Design Direction Needed

**Component:** Error toast notification

**Proposed approach (Claude's discretion):**
- Position: Top-right, fixed
- Background: #1a0000 (dark red tint)
- Border: 1px solid #EF4444
- Text: #EF4444 (red)
- Font: JetBrains Mono 11px

**Awaiting:** User approval or design in Pencil
```

## Verification with Playwright MCP

### Automated Visual Verification

When Playwright MCP is available, automate design comparison:

```typescript
// 1. Navigate to app
await mcp__playwright__navigate({ url: 'http://localhost:5173' });

// 2. Desktop viewport (matches design frame)
await mcp__playwright__set_viewport({ width: 1440, height: 900 });

// 3. Capture screenshot
await mcp__playwright__screenshot({
  fullPage: true,
  name: 'desktop-file-browser',
});

// 4. Extract computed styles
const headerStyles = await mcp__playwright__evaluate({
  script: `
    const header = document.querySelector('.app-header');
    const styles = getComputedStyle(header);
    return {
      backgroundColor: styles.backgroundColor,
      borderBottom: styles.borderBottom,
      padding: styles.padding
    };
  `,
});

// 5. Verify against design
// Design specifies: bg=#000000, border=1px #00D084, padding=12px 24px
console.assert(
  headerStyles.backgroundColor === 'rgb(0, 0, 0)',
  'Header background should be black'
);
console.assert(
  headerStyles.borderBottom.includes('rgb(0, 208, 132)'),
  'Header border should be green'
);
```

### Visual Regression Testing

Compare screenshots against baseline:

```typescript
// Capture current state
await mcp__playwright__screenshot({ name: 'current-header' });

// Compare to baseline (from design export or previous approved version)
const diff = await mcp__playwright__visual_diff({
  baseline: 'baselines/header-desktop.png',
  current: 'screenshots/current-header.png',
  threshold: 0.01, // 1% pixel difference tolerance
});

if (diff.percentage > 0.01) {
  console.log('Visual regression detected:', diff);
}
```

## Best Practices

### 1. Design-First Always

Never implement UI without design reference. If design doesn't exist:

- Request it from user
- Get design direction approval
- Document assumptions for verification

### 2. Extract Before Implement

Always run design extraction before writing CSS:

```bash
# Extract design tokens first
cat designs/app-design.pen | jq '...'

# Then implement with exact values
```

### 3. Verify Exact Values

Don't approximate. Verify:

- `#00D084` not `#00C974` or `green`
- `12px` not `10px` or `0.75rem`
- `600` not `500` or `bold`

### 4. Document Discrepancies

When implementation differs from design:

- Note the difference
- Explain why (intentional or needs fix)
- Update design or code to match

### 5. Use Playwright When Available

Computed styles are the truth. CSS source might say one thing, but cascade/inheritance might produce different result. Verify at runtime.

## Common Issues

### Issue: Design uses non-web fonts

**Problem:** Design specifies font not available for web

**Solution:**

1. Request web-compatible alternative from designer
2. Find closest Google Font match
3. Self-host the font if licensed

### Issue: Design spacing doesn't translate to CSS

**Problem:** Pencil padding array format differs from CSS

**Solution:**

```javascript
// Pencil: padding: [12, 24] means [vertical, horizontal]
// CSS: padding: 12px 24px (top/bottom left/right)

// Pencil: padding: [8, 16, 8, 16] means [top, right, bottom, left]
// CSS: padding: 8px 16px 8px 16px
```

### Issue: Colors look different in browser

**Problem:** Same hex code looks different

**Solution:**

1. Check color profile (sRGB)
2. Verify no color filters applied
3. Check for transparency/overlay effects
4. Test on calibrated monitor

### Issue: Responsive breakpoints not in design

**Problem:** Design only shows desktop/mobile, not tablet

**Solution:**

1. Interpolate between breakpoints
2. Use standard breakpoints (768px, 1024px)
3. Ask designer for intermediate sizes
4. Document assumptions for review

## Related Files

- **Agents:**
  - `.claude/agents/ui-design-researcher.md` - Extracts design specs
  - `.claude/agents/ui-design-verifier.md` - Verifies implementation
- **Design files:**
  - `designs/*.pen` - Pencil design files
- **Research output:**
  - `.planning/phases/*/RESEARCH.md` - Extracted specifications
- **Verification output:**
  - `.planning/phases/*/VERIFICATION.md` - Compliance report
