# CipherBox Design System

**Source:** `designs/cipher-box-design.pen`
**Last Updated:** 2026-01-30
**Status:** Active design system reference

This document serves as the persistent design context for UI mockup generation. Load this file before any Pencil MCP interaction to ensure consistent outputs.

## Design Tokens

### Colors

| Hex Code  | Opacity | Usage                    | CSS Variable           |
| --------- | ------- | ------------------------ | ---------------------- |
| `#000000` | 100%    | Background, surfaces     | `--color-background`   |
| `#00D084` | 100%    | Primary accent, borders  | `--color-primary`      |
| `#00D084` | 40%     | Glow effects             | `--color-glow`         |
| `#006644` | 100%    | Secondary text, muted    | `--color-text-muted`   |
| `#003322` | 100%    | Row separators, dividers | `--color-border-muted` |

### Typography

| Size | Weight | Usage                | CSS Variable       |
| ---- | ------ | -------------------- | ------------------ |
| 10px | 600    | Status text, labels  | `--font-size-xs`   |
| 11px | 400    | Body text, metadata  | `--font-size-sm`   |
| 11px | 600    | Button text, headers | `--font-size-sm`   |
| 12px | 400    | File names           | `--font-size-base` |
| 14px | 600    | App name, section    | `--font-size-md`   |
| 18px | 700    | Prompt character     | `--font-size-lg`   |

**Font Family:** `JetBrains Mono`

### Spacing Scale

| Value | Usage                     | CSS Variable    |
| ----- | ------------------------- | --------------- |
| 8px   | Button padding (vertical) | `--spacing-xs`  |
| 10px  | Row padding (vertical)    | `--spacing-sm`  |
| 12px  | Header padding, gaps      | `--spacing-md`  |
| 16px  | Button padding (h), gaps  | `--spacing-lg`  |
| 20px  | Header item gaps          | `--spacing-xl`  |
| 24px  | Content padding           | `--spacing-2xl` |

### Borders & Effects

| Property     | Value                | Usage                    |
| ------------ | -------------------- | ------------------------ |
| Thickness    | 1px                  | All borders              |
| Radius       | 0 (sharp corners)    | Terminal aesthetic       |
| Glow         | `0 0 10px #00D08466` | Status dot, active items |
| Border align | `inside`             | Consistent sizing        |

## App Layout

### Desktop (1440 x 900)

```text
┌─────────────────────────────────────────────────────────────────┐
│  > CIPHERBOX                    ● [CONNECTED] user@matrix.cloud │
├─────────────────────────────────────────────────────────────────┤
│  ~/storage/documents/projects                                   │
│  ┌─────────┐ ┌───────────┐ ┌───────────┐                       │
│  │--upload │ │ --new-dir │ │ --refresh │                       │
│  └─────────┘ └───────────┘ └───────────┘                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ NAME                    SIZE      TYPE       MODIFIED       ││
│  ├─────────────────────────────────────────────────────────────┤│
│  │ [DIR] ..               --        directory  --              ││
│  │ [DIR] backup_archives  4.2 GB    directory  2026-01-15      ││
│  │ [FILE] report.pdf      2.4 MB    document   2026-01-20      ││
│  │ [FILE] data.enc        156 KB    encrypted  2026-01-22      ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Component Hierarchy

```text
frame (root - 1440x900)
├── header (n386r)
│   ├── headerLeft (zNr0C)
│   │   ├── prompt (D7afA) - ">"
│   │   └── appName (iJ5Gn) - "CIPHERBOX"
│   └── headerRight (VA9WI)
│       ├── statusDot (MhpBr) - with glow effect
│       ├── statusText (8u2AP) - "[CONNECTED]"
│       └── userInfo (Mwofn) - email
├── mainContent (zRTYl)
│   ├── breadcrumbBar (HLKjX)
│   ├── controlBar (uMUQZ)
│   │   ├── btnUpload (1nlwl) - primary filled
│   │   ├── btnNewFolder (5usp9) - outline
│   │   └── btnRefresh (aa0ZP) - outline
│   └── fileListContainer (A87rp)
│       ├── fileListHeader (JIRd2)
│       └── rows (7tF1E, MKlFi, ...)
```

## Component Library

### Header

| Property   | Value                             |
| ---------- | --------------------------------- |
| Background | `#000000`                         |
| Border     | 1px bottom `#00D084`              |
| Padding    | 12px 24px                         |
| Layout     | horizontal, space-between, center |

### Button - Primary (Filled)

| Property   | Value               |
| ---------- | ------------------- |
| Background | `#00D084`           |
| Text color | `#000000`           |
| Padding    | 8px 16px            |
| Font       | JetBrains Mono 11px |
| Weight     | 600                 |

### Button - Secondary (Outline)

| Property   | Value               |
| ---------- | ------------------- |
| Background | transparent         |
| Border     | 1px `#00D084`       |
| Text color | `#00D084`           |
| Padding    | 8px 16px            |
| Font       | JetBrains Mono 11px |
| Weight     | 400                 |

### File Row

| Property       | Value                     |
| -------------- | ------------------------- |
| Padding        | 10px 16px                 |
| Border         | 1px bottom `#003322`      |
| Icon color     | `#00D084`                 |
| Name color     | `#00D084`                 |
| Metadata color | `#006644`                 |
| Column widths  | flex, 120px, 120px, 180px |

### Status Indicator

| Property | Value                 |
| -------- | --------------------- |
| Size     | 8px circle            |
| Fill     | `#00D084`             |
| Glow     | 10px blur `#00D08466` |

## Interaction Patterns

### Hover States

- **Buttons:** Subtle brightness increase
- **File rows:** Background highlight (very subtle `#001a11`)
- **Links:** Underline

### Focus States

- **Inputs:** 1px `#00D084` outline
- **Buttons:** Same as hover + focus ring

### Loading States

- **Skeleton:** Pulsing `#003322` blocks
- **Spinner:** Terminal-style cursor blink or `[...]`

### Error States

- **Color:** `#EF4444` (red) for errors
- **Border:** 1px `#EF4444`
- **Text:** `#EF4444` for error messages

## Design Decision Log

Record design decisions made during discuss-phase sessions.

| Date       | Phase | Decision                                  | Rationale                |
| ---------- | ----- | ----------------------------------------- | ------------------------ |
| 2026-01-30 | -     | Initial design system extracted from .pen | Baseline for consistency |

---

## Usage in Agents

### Loading Design Context (Required First Step)

```typescript
// Before ANY Pencil MCP call, load this document
const designContext = await read('designs/DESIGN.md');

// Extract tokens for use in prompts
const tokens = {
  colors: {
    background: '#000000',
    primary: '#00D084',
    glow: '#00D08466',
    textMuted: '#006644',
    borderMuted: '#003322',
  },
  typography: {
    fontFamily: 'JetBrains Mono',
    sizes: { xs: 10, sm: 11, base: 12, md: 14, lg: 18 },
    weights: { normal: 400, semibold: 600, bold: 700 },
  },
  spacing: { xs: 8, sm: 10, md: 12, lg: 16, xl: 20, '2xl': 24 },
  borders: { thickness: 1, radius: 0 },
};
```

### Creating Consistent Designs

Always use tokens from this file when creating new designs:

```typescript
await mcp__pencil__create_design({
  // Use ONLY colors from design system
  fill: tokens.colors.background,
  stroke: { thickness: tokens.borders.thickness, fill: tokens.colors.primary },

  // Use spacing scale
  padding: [tokens.spacing.sm, tokens.spacing.lg],
  gap: tokens.spacing.md,

  // Use typography
  fontFamily: tokens.typography.fontFamily,
  fontSize: tokens.typography.sizes.sm,
});
```

---

_Design system extracted from cipher-box-design.pen_
_Maintained by ui-design-discusser agent_
