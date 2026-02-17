---
created: 2026-02-17T22:30
title: Centralize error handling in FileBrowser
area: ui
files:
  - apps/web/src/components/file-browser/FileBrowser.tsx
---

## Problem

FileBrowser.tsx has 10 `console.error` calls with slightly different patterns for operations like sync, move, download, batch delete, rename, create folder. Each catch block independently logs to console and may or may not set UI error state. No structured error reporting.

## Solution

Create a `useErrorHandler` hook or simple utility that:

- Logs with consistent prefix/format
- Sets a UI-visible error toast/banner state
- Optionally categorizes errors (network, crypto, storage)

Replace the 10 ad-hoc catch blocks with calls to this handler. Could pair well with the FileBrowser split (item 1) since the action handlers would use it.
