---
created: 2026-02-17T22:30
title: Split FileBrowser.tsx god component
area: ui
files:
  - apps/web/src/components/file-browser/FileBrowser.tsx
---

## Problem

FileBrowser.tsx is 1,115 lines with 50 React hook calls (useEffect/useCallback/useMemo), 16 sub-component imports, and handles sync, selection, context menus, drag-drop, all CRUD operations, batch actions, previews, and navigation. It's the largest file in the web app and difficult to reason about.

## Solution

Extract into focused modules:

- `useFileBrowserActions` hook — rename, delete, move, create folder, batch operations (~300 lines)
- `useFileBrowserDialogs` hook — dialog open/close state for ~10 dialogs (~150 lines)
- Keep FileBrowser.tsx as a lean composition root wiring hooks to UI

This is the highest-effort but highest-impact maintainability win.
