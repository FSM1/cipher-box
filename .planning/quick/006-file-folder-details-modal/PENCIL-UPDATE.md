# Pencil Design Update — Details Modal

## Frames to Add

Two new frames needed: **File Details Modal** and **Folder Details Modal**.

---

## File Details Modal

### Layout

- Uses existing `Modal` base (500px max-width, green border, black bg, green glow shadow)
- Header: `FILE DETAILS` (uppercase, 11px, semibold, `--color-text-primary`)
- Close button: `×` in top-right (existing modal pattern)
- Body: Scrollable list of detail rows

### Detail Rows

Each row is a vertical stack: label on top, value below, separated by `--color-border-dim` (#003322) bottom border.

| Label               | Value                                         | Style                                                              |
| ------------------- | --------------------------------------------- | ------------------------------------------------------------------ |
| NAME                | `example-document.pdf`                        | `--color-text-primary`                                             |
| TYPE                | `[FILE]` badge                                | Badge: 1px border `--color-border-dim`, uppercase, xs font         |
| SIZE                | `1.2 MB`                                      | `--color-text-primary`                                             |
| **// encryption**   | _(section header)_                            | `--color-green-dim` (#006644), uppercase, xs, 0.1em letter-spacing |
| CONTENT CID         | `bafkreia...` + `[cp]` button                 | Monospace, word-break, with copy button                            |
| FOLDER METADATA CID | `bafkreib...` + `[cp]` button                 | Same copyable style                                                |
| ENCRYPTION MODE     | `AES-256-GCM`                                 | `--color-text-primary`                                             |
| FILE IV             | `a1b2c3d4...` + `[cp]` button                 | Copyable hex string                                                |
| WRAPPED FILE KEY    | `04a1b2c3d4e5f6g7...h8i9j0k1 (ECIES-wrapped)` | Italic, `--color-text-dim` (#4a5a4e)                               |
| **// timestamps**   | _(section header)_                            | Same as encryption header                                          |
| CREATED             | `Jan 21, 2024`                                | `--color-text-primary`                                             |
| MODIFIED            | `Feb 10, 2026`                                | `--color-text-primary`                                             |

---

## Folder Details Modal

### Layout

Same modal base as file details. Header: `FOLDER DETAILS`.

### Detail Rows

| Label             | Value                                         | Style                                                           |
| ----------------- | --------------------------------------------- | --------------------------------------------------------------- |
| NAME              | `my-documents`                                | `--color-text-primary`                                          |
| TYPE              | `[DIR]` badge                                 | Badge: `--color-green-primary` text                             |
| CONTENTS          | `5 items`                                     | `--color-text-primary`                                          |
| **// ipns**       | _(section header)_                            | `--color-green-dim`, uppercase                                  |
| IPNS NAME         | `k51qzi5u...` + `[cp]` button                 | Copyable, monospace                                             |
| METADATA CID      | `bafkreic...` + `[cp]` button                 | Copyable (or `resolving...` in italic `--color-text-secondary`) |
| SEQUENCE NUMBER   | `42`                                          | `--color-text-primary`                                          |
| **// encryption** | _(section header)_                            | `--color-green-dim`, uppercase                                  |
| FOLDER KEY        | `04a1b2c3d4e5f6g7...h8i9j0k1 (ECIES-wrapped)` | Italic, `--color-text-dim` (redacted)                           |
| IPNS PRIVATE KEY  | `04d8e9f0a1b2c3d4...e5f6g7h8 (ECIES-wrapped)` | Italic, `--color-text-dim` (redacted)                           |
| **// timestamps** | _(section header)_                            | `--color-green-dim`, uppercase                                  |
| CREATED           | `Feb 1, 2026`                                 | `--color-text-primary`                                          |
| MODIFIED          | `Feb 10, 2026`                                | `--color-text-primary`                                          |

---

## Context Menu Update

Add `ⓘ Details` menu item to the existing context menu frame:

- Position: after "Move to...", before the divider/Delete
- Icon: `ⓘ` (info circle, Unicode &#9432;)
- Style: same as other menu items (`--color-text-primary`, hover `--color-green-darker`)

---

## Component Tokens

### Labels

- Font: `--font-family-mono` (JetBrains Mono)
- Size: `--font-size-xs` (10px)
- Weight: `--font-weight-semibold` (600)
- Transform: uppercase
- Letter-spacing: 0.05em
- Color: `--color-text-secondary` (#006644)

### Values

- Font: `--font-family-mono`
- Size: `--font-size-sm` (11px)
- Color: `--color-text-primary` (#00D084)
- Line-height: 1.5
- Word-break: break-all (for long CIDs)

### Section Headers

- Font: `--font-family-mono`
- Size: `--font-size-xs` (10px)
- Weight: `--font-weight-semibold` (600)
- Transform: uppercase
- Letter-spacing: 0.1em
- Color: `--color-green-dim` (#006644)
- Padding: 12px top, 8px bottom
- Border-bottom: 1px solid `--color-border-dim`

### Copy Button

- Padding: 2px 6px
- Font: `--font-family-mono`, `--font-size-xs`
- Color: `--color-text-secondary` → `--color-text-primary` on hover
- Border: 1px solid `--color-border-dim` → `--color-border` on hover
- Background: transparent → `--color-green-darker` on hover
- Copied state: color and border become `--color-green-primary`, text changes `cp` → `ok`

### Redacted Values

- Font-style: italic
- Color: `--color-text-dim` (#4a5a4e)

### Type Badge

- Display: inline-block
- Padding: 1px 6px
- Font: `--font-family-mono`, `--font-size-xs`, `--font-weight-semibold`
- Transform: uppercase
- Border: 1px solid `--color-border-dim`
- `[FILE]` color: `--color-text-primary`
- `[DIR]` color: `--color-green-primary`

---

## Row Spacing

- Row padding: `--spacing-xs` (8px) top and bottom
- Row gap between label and value: 2px
- Row separator: 1px solid `--color-border-dim`
- Section header margin-top: `--spacing-xs` (8px)
