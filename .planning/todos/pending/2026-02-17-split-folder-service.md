---
created: 2026-02-17T22:30
title: Split folder.service.ts into focused modules
area: ui
files:
  - apps/web/src/services/folder.service.ts
---

## Problem

folder.service.ts is 937 lines with 18 exported functions spanning tree traversal utilities, IPNS record building, and file/folder CRUD mutations. Functions range from pure utilities (`getDepth`, `isDescendantOf`, `calculateSubtreeDepth`) to complex async operations (`moveFolder`, `deleteFolder`, `replaceFileInFolder`).

## Solution

Split into focused modules:

- `folder-tree.service.ts` — pure tree utilities (getDepth, isDescendantOf, calculateSubtreeDepth)
- `folder-mutations.service.ts` — create, rename, delete, move operations for folders and files
- Keep `folder.service.ts` as a barrel re-export for backward compatibility, or update imports across the codebase
