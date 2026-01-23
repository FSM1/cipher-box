---
created: 2026-01-23T12:15
title: Add simple text file editor modal
area: ui
files:
  - apps/web/src/components/file-browser/ContextMenu.tsx
  - apps/web/src/components/file-browser/FileBrowser.tsx
---

## Problem

Users cannot edit text files directly within CipherBox. To modify a text file, they must:

1. Download the file
2. Edit locally
3. Delete the original file
4. Re-upload the modified version

This is cumbersome for simple edits to notes, configs, or other text files. A built-in text editor would enable quick edits without leaving the app.

Additionally, having an "Edit" option in the context menu would provide a natural way to test the file update/overwrite flow in E2E tests, since it exercises the full cycle of: download → decrypt → modify → encrypt → upload → update metadata.

## Solution

Add an "Edit" option to the context menu (for text files only) that opens a modal dialog with:

- **Header**: File name
- **Body**: `<textarea>` with file contents (decoded from UTF-8)
- **Footer**: Cancel and Save buttons

Flow:

1. User right-clicks text file → "Edit" option appears
2. Click Edit → Download file, decrypt, decode as UTF-8
3. Display content in modal textarea
4. User edits content
5. Click Save → Encrypt new content, upload to IPFS, update folder metadata (replace old CID with new)
6. Modal closes, file list refreshes

Text file detection: Check file extension (.txt, .md, .json, .yaml, .yml, .xml, .csv, .log, etc.)

Consider: Monaco editor or CodeMirror for syntax highlighting (future enhancement, not v1).
