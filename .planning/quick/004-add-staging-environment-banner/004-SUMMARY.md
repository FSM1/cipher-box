# Quick Task 004: Add Staging Environment Banner

**Status:** Complete
**Branch:** `feat/staging-banner`
**Date:** 2026-02-09

## What Was Done

1. **Created `StagingBanner` component** (`apps/web/src/components/StagingBanner.tsx`)
   - Two variants: `login` (fixed overlay) and `compact` (36px flow element)
   - Reads `import.meta.env.VITE_ENVIRONMENT` — returns `null` when not `'staging'`
   - Orange warning color scheme: `#FF6B00` text on `#3d1a00` background
   - JetBrains Mono font via `var(--font-family-mono)`, warning triangle unicode chars
   - `data-testid="staging-banner"` for E2E testability

2. **Integrated into Login page** (`apps/web/src/routes/Login.tsx`)
   - Login variant renders as fixed overlay at top of viewport (z-index 1000)
   - Shows "STAGING ENVIRONMENT" title + disclaimer about data safety

3. **Integrated into AppShell** (`apps/web/src/components/layout/AppShell.tsx`)
   - Compact variant renders above the app grid as a 36px bar
   - Staging path wraps grid in flex column (100vh - 36px for banner)
   - Non-staging code path is completely unchanged (zero production risk)

## Design Specs

| Property   | Login Variant            | Compact Variant          |
| ---------- | ------------------------ | ------------------------ |
| Background | `#3d1a00`                | `#3d1a00`                |
| Text color | `#FF6B00`                | `#FF6B00`                |
| Border     | `1px solid #FF6B00`      | `1px solid #FF6B00`      |
| Font       | JetBrains Mono 13px bold | JetBrains Mono 11px bold |
| Position   | Fixed, top 0             | Flow element             |
| Height     | Auto (~50px)             | 36px                     |

## Commits

- `084638b` — docs(quick-004): plan staging environment banner
- `c7b7184` — feat(quick-004): add StagingBanner component
- `839179e` — feat(quick-004): integrate into Login and AppShell
