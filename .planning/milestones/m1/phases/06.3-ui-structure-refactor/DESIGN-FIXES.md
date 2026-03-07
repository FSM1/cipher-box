# Phase 6.3: UI Structure Refactor - Design Fixes

**Researched:** 2026-01-30
**Domain:** UI Implementation, Design System
**Confidence:** HIGH
**Design Source:** `/Users/michael/Code/cipher-box/designs/cipher-box-design.pen`
**Primary Frame:** `nRzxj` (Phase 6.3 - Unified Structure Mockup)

## Summary

This document identifies discrepancies between the implemented UI and the Pencil design specifications for Phase 6.3. The toolbar, breadcrumbs, toolbar buttons, and sidebar navigation items have styling issues that need to be corrected.

Key issues identified:

1. **Toolbar** - Missing dark green background (#001108)
2. **Breadcrumbs** - Should be simple text path format in secondary color (#006644)
3. **Toolbar buttons** - Should use terminal bracket style with proper border colors
4. **Sidebar nav items** - Should use emoji icons, not text-based [DIR]/[CFG] prefixes

**Primary recommendation:** Update CSS variables and component styles to match the extracted design tokens from frame `nRzxj`.

---

## Design Specifications

### Source Frame

| Frame ID | Name                                 | Dimensions | Purpose                                |
| -------- | ------------------------------------ | ---------- | -------------------------------------- |
| `nRzxj`  | Phase 6.3 - Unified Structure Mockup | 1000 x 700 | Primary reference for Phase 6.3 layout |

### Color Palette (Extracted from Frame nRzxj)

| Hex       | Usage                                         | CSS Token                     | Currently Implemented |
| --------- | --------------------------------------------- | ----------------------------- | --------------------- |
| `#000000` | Background, main areas                        | `--color-background`          | YES                   |
| `#00D084` | Primary accent, text, borders                 | `--color-green-primary`       | YES                   |
| `#006644` | Secondary text, breadcrumbs, inactive items   | `--color-green-dim`           | YES                   |
| `#003322` | Dim borders, row separators, inactive buttons | `--color-green-darker`        | YES                   |
| `#001a11` | Active nav item background                    | `--color-nav-active`          | YES                   |
| `#001108` | Toolbar background                            | **MISSING** - needs new token | NO                    |

**New Token Required:**

```css
--color-toolbar-bg: #001108;
```

### Typography Scale (Extracted from Frame nRzxj)

| Size | Weight         | Usage                                   | Element ID Reference      |
| ---- | -------------- | --------------------------------------- | ------------------------- |
| 20px | 700 (bold)     | Logo prompt ">"                         | `9jOaU`                   |
| 14px | 600 (semibold) | App name "CIPHERBOX"                    | `cjDhd`                   |
| 12px | 600 (semibold) | Active nav item text                    | `rr76i`                   |
| 12px | 400 (normal)   | Inactive nav item text                  | `hM3sj`                   |
| 11px | 400 (normal)   | Breadcrumb path, file names, user email | `uUOmU`, `jsVmB`, `5RlUT` |
| 10px | 600 (semibold) | Column headers                          | `aDYxP`                   |
| 10px | 400 (normal)   | Toolbar buttons, file sizes, dates      | `aGan3`, `n8MrG`, `DB1fB` |
| 9px  | 600 (semibold) | Storage label                           | `vWvmF`                   |
| 9px  | 400 (normal)   | Footer links, storage text              | `LedCZ`, `Zcghl`          |
| 8px  | 400 (normal)   | User menu caret                         | `uIfYP`                   |

**Font Family:** JetBrains Mono (monospace)

### Spacing Values (Extracted from Frame nRzxj)

| Value | Usage                                                    | Design Element              |
| ----- | -------------------------------------------------------- | --------------------------- |
| 4px   | User menu vertical padding                               | `CLFih` padding: [4, 8]     |
| 6px   | Button vertical padding, storage bar height              | `8T0F3` padding: [6, 12]    |
| 8px   | User menu gap, nav item vertical padding, sidebar gap    | Various                     |
| 10px  | File row vertical padding                                | `RmYYZ` padding: [10, 0]    |
| 12px  | Toolbar vertical padding, nav item gap, button gap       | `ugnDQ` padding: [12, 20]   |
| 16px  | Sidebar padding, nav gap                                 | `wfywR` padding: 16, gap: 8 |
| 20px  | Toolbar horizontal padding, file list horizontal padding | `ugnDQ`                     |
| 24px  | Header horizontal padding, footer horizontal padding     | `BwljC` padding: [12, 24]   |
| 48px  | Column meta gap                                          | `pdtUr` gap: 48             |

### Border Specifications

| Location           | Thickness | Color     | Direction |
| ------------------ | --------- | --------- | --------- |
| Header             | 1px       | `#00D084` | bottom    |
| Sidebar            | 1px       | `#003322` | right     |
| Footer             | 1px       | `#003322` | top       |
| File list header   | 1px       | `#003322` | bottom    |
| File row           | 1px       | `#003322` | bottom    |
| User menu          | 1px       | `#003322` | all sides |
| Storage bar        | 1px       | `#003322` | all sides |
| Button (primary)   | 1px       | `#00D084` | all sides |
| Button (secondary) | 1px       | `#003322` | all sides |

---

## Component Inventory - Issues Identified

### 1. Toolbar (id: `ugnDQ`)

**Frame Reference:** Line 5572-5656 in design file

**Design Specifications:**

- Background: `#001108` (dark green)
- Padding: 12px vertical, 20px horizontal
- Layout: flex, space-between, center aligned
- Width: fill container

**Current Implementation Issues:**

```css
/* CURRENT (file-browser.css line 52-59) */
.file-browser-toolbar {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-thickness) solid var(--color-border-dim);
  margin-bottom: var(--spacing-md);
  /* MISSING: background-color */
}
```

**Required Fix:**

```css
.file-browser-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between; /* ADD: space-between */
  gap: var(--spacing-md);
  padding: var(--spacing-sm) 20px; /* FIX: 12px 20px */
  background-color: #001108; /* ADD: toolbar background */
  /* REMOVE: border-bottom, margin-bottom (not in design) */
}
```

### 2. Breadcrumb (id: `uUOmU`)

**Frame Reference:** Line 5585-5594 in design file

**Design Specifications:**

- Text color: `#006644` (secondary green)
- Font: JetBrains Mono, 11px, normal weight
- Content format: `~/root/documents/projects` (simple path text)
- No interactive segments, no separators

**Current Implementation Issues:**

The current Breadcrumbs.tsx uses interactive buttons and renders segments separately:

```tsx
// CURRENT (Breadcrumbs.tsx line 145-172)
<nav className="breadcrumb-nav">
  <span className="breadcrumb-prefix">~</span>
  <span className="breadcrumb-separator">/</span>
  {breadcrumbs.map((crumb) => (
    <Fragment key={crumb.id}>
      <button className="breadcrumb-item" ...>
        {crumb.name.toLowerCase()}
      </button>
      {!isLast && <span className="breadcrumb-separator">/</span>}
    </Fragment>
  ))}
</nav>
```

**Design Intent:** Simple text path, not interactive clickable segments in toolbar.

**Required CSS Fix (if keeping interactive):**

```css
.breadcrumb-nav {
  color: #006644; /* Secondary green, not primary */
}

.breadcrumb-item {
  color: #006644; /* Match design */
  background: transparent;
  border: none;
  padding: 0;
}

.breadcrumb-item:hover {
  color: #00d084; /* Primary on hover */
  background: transparent; /* No background change */
}

/* Remove prefix styling complexity */
.breadcrumb-prefix,
.breadcrumb-separator {
  color: #006644;
}
```

**Alternative (match design exactly):** Render as simple `<span>` with full path text.

### 3. Toolbar Buttons (btnNewFolder: `8T0F3`, btnRefresh: `tC3V4`)

**Frame Reference:** Lines 5601-5652 in design file

**Design Specifications - btnNewFolder (Primary):**

- Border: 1px `#00D084` (primary green)
- Padding: 6px vertical, 12px horizontal
- Text: `+folder` in `#00D084`, 10px, normal weight
- No background fill

**Design Specifications - btnRefresh (Secondary):**

- Border: 1px `#003322` (dim green)
- Padding: 6px vertical, 12px horizontal
- Text: `refresh` in `#006644`, 10px, normal weight
- No background fill

**Current Implementation Issues:**

```tsx
// CURRENT (FileBrowser.tsx line 268-291)
<button className="file-browser-new-folder-button">
  <svg ...>
    {/* SVG folder icon */}
  </svg>
  <span>New Folder</span>
</button>
```

**Problems:**

1. Uses SVG icon instead of text-only button
2. Text says "New Folder" instead of "+folder"
3. Different styling than design (rgba colors, border-radius)

**Required Fix:**

```tsx
<button className="toolbar-btn toolbar-btn--primary">
  +folder
</button>
<button className="toolbar-btn toolbar-btn--secondary">
  refresh
</button>
```

```css
.toolbar-btn {
  padding: 6px 12px;
  font-family: var(--font-family-mono);
  font-size: 10px;
  font-weight: 400;
  background: transparent;
  border: 1px solid;
  border-radius: 0;
  cursor: pointer;
}

.toolbar-btn--primary {
  color: #00d084;
  border-color: #00d084;
}

.toolbar-btn--secondary {
  color: #006644;
  border-color: #003322;
}

.toolbar-btn--primary:hover {
  box-shadow: var(--glow-green);
}
```

### 4. Sidebar Navigation Items (navFiles: `kmbsj`, navSettings: `X75Nl`)

**Frame Reference:** Lines 5440-5505 in design file

**Design Specifications - navFiles (Active):**

- Background: `#001a11`
- Gap: 12px
- Padding: 8px vertical, 12px horizontal
- Icon: Folder emoji rendered as text element (no fill specified)
- Text: "Files" in `#00D084`, 12px, weight 600

**Design Specifications - navSettings (Inactive):**

- No background
- Gap: 12px
- Padding: 8px vertical, 12px horizontal
- Icon: Gear emoji in `#006644`, 14px
- Text: "Settings" in `#006644`, 12px, normal weight

**Current Implementation Check Needed:**

The layout.css shows:

```css
.nav-item-icon {
  font-family: var(--font-family-mono);
  font-size: 10px; /* WRONG: should be 14px */
}
```

**Required CSS Fix:**

```css
.nav-item {
  gap: 12px; /* Match design gap */
  padding: 8px 12px;
}

.nav-item-icon {
  font-size: 14px; /* Match design icon size */
}

.nav-item--active {
  background-color: #001a11;
}

.nav-item--active .nav-item-text {
  color: #00d084;
  font-weight: 600;
}

.nav-item:not(.nav-item--active) .nav-item-icon,
.nav-item:not(.nav-item--active) .nav-item-text {
  color: #006644;
}
```

---

## File List Specifications (For Reference)

### Row Structure

**Parent Directory Row (rowParent: `RmYYZ`):**

- Text: `[..] PARENT_DIR` in `#006644`
- Font: 11px, normal
- Padding: 10px 0
- Border bottom: 1px `#003322`
- Size/Date columns: empty (fill `#003322`)

**Directory Row (e.g., row1: `LWrHb`):**

- Name: `[DIR] folder-name/` in `#00D084`
- Size: `--` in `#003322`
- Date: date in `#006644`
- Font: name 11px, meta 10px

**File Row (e.g., row3: `Qk1Dk`):**

- Name: `[FILE] filename.ext` in `#00D084`
- Size: size in `#00D084`
- Date: date in `#00D084`
- Font: name 11px, meta 10px

**Column Header (fileListHeader: `0aYdY`):**

- Name column: `[NAME]` with sort arrow in `#00D084`, 10px, weight 600
- Size column: `[SIZE]` in `#006644`, 10px, normal
- Date column: `[MODIFIED]` in `#006644`, 10px, normal
- Padding: 12px 0
- Border bottom: 1px `#003322`

---

## Missing Designs

The following UI states are not present in the Phase 6.3 design frame and need to be created:

### 1. Empty State Design

**Current:** Uses ASCII art box with "// EMPTY DIRECTORY" text

**Status:** Not in design file - appears to be a custom implementation

**Recommendation:** Keep current implementation or create matching design with:

- Terminal-style ASCII art
- Text in `#006644` (secondary)
- Same font family/sizes as file list

### 2. Upload Zone in Toolbar

**Current:** Uses `--upload` text button in toolbar

**Design:** No upload button visible in toolbar - only `+folder` and `refresh`

**Question:** Should upload be in toolbar or only in empty state?

### 3. Hover/Active States

**Current CSS has hover states but they are not in design:**

Inferred from design patterns:

- Hover on file rows: background `#003322` (darker green)
- Hover on buttons: add glow effect
- Active nav item: background `#001a11`

### 4. Selected Row State

Not explicitly shown in design. Current implementation uses:

- Background: `#003322`
- Left border: 2px `#00D084`

---

## CSS Fixes Summary

### 1. Add New CSS Variable

```css
:root {
  --color-toolbar-bg: #001108;
}
```

### 2. Update file-browser.css

```css
.file-browser-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  background-color: var(--color-toolbar-bg);
  /* Remove border-bottom and margin-bottom */
}
```

### 3. Update breadcrumbs.css

```css
.breadcrumb-nav {
  color: var(--color-text-secondary); /* #006644 */
}

.breadcrumb-item {
  color: var(--color-text-secondary);
  padding: 0;
  background: transparent;
}
```

### 4. Update Toolbar Buttons

Create new button styles or update existing:

```css
.toolbar-btn {
  padding: 6px 12px;
  font-size: 10px;
  background: transparent;
  border: 1px solid;
  border-radius: 0;
}

.toolbar-btn--primary {
  color: var(--color-text-primary);
  border-color: var(--color-text-primary);
}

.toolbar-btn--secondary {
  color: var(--color-text-secondary);
  border-color: var(--color-border-dim);
}
```

### 5. Update layout.css Nav Items

```css
.nav-item-icon {
  font-size: 14px; /* Was 10px */
}

.nav-item {
  gap: 12px; /* Verify this matches */
}
```

---

## Implementation Checklist

- [ ] Add `--color-toolbar-bg: #001108` to index.css
- [ ] Update `.file-browser-toolbar` background and layout
- [ ] Update `.breadcrumb-nav` and `.breadcrumb-item` colors
- [ ] Update FileBrowser.tsx toolbar buttons to terminal style
- [ ] Update `.nav-item-icon` font-size to 14px
- [ ] Verify emoji icons render correctly for nav items
- [ ] Test hover states match design intent
- [ ] Verify mobile responsive behavior

---

## Verification Criteria

| Component      | Verification                                | Frame Reference |
| -------------- | ------------------------------------------- | --------------- |
| Toolbar        | Background #001108, padding 12px 20px       | `ugnDQ`         |
| Breadcrumb     | Text color #006644, 11px font               | `uUOmU`         |
| +folder button | Border #00D084, text #00D084, 10px          | `8T0F3`         |
| refresh button | Border #003322, text #006644, 10px          | `tC3V4`         |
| Files nav      | Icon 14px, text 12px 600 weight, bg #001a11 | `kmbsj`         |
| Settings nav   | Icon/text #006644, 12px normal              | `X75Nl`         |

---

## Sources

### Primary (HIGH confidence)

- Design file: `/Users/michael/Code/cipher-box/designs/cipher-box-design.pen` - authoritative source
- Frame ID: `nRzxj` - Phase 6.3 Unified Structure Mockup

### Secondary

- Current CSS: `/Users/michael/Code/cipher-box/apps/web/src/styles/file-browser.css`
- Current CSS: `/Users/michael/Code/cipher-box/apps/web/src/styles/breadcrumbs.css`
- Current CSS: `/Users/michael/Code/cipher-box/apps/web/src/styles/layout.css`

---

## Metadata

**Confidence breakdown:**

- Design tokens: HIGH - Extracted directly from .pen file
- Component specs: HIGH - Direct measurements from design
- Implementation fixes: HIGH - Clear delta between current and design

**Research date:** 2026-01-30
**Valid until:** Completion of Phase 6.3
