# Quick Task 014: Fix Multiselect Button Visibility

**Date:** 2026-02-13
**Commit:** 33a56c8

## Problem

The download and move buttons in the multi-select action bar were barely visible. The `toolbar-btn--secondary` class used `color: #006644` (dim green) and `border-color: #003322` (darker green) — both nearly invisible against the action bar's `#003322` background.

## Fix

Added CSS overrides for `.selection-action-bar .toolbar-btn--secondary`:

- Text color: `var(--color-green-primary)` (#00D084) — bright green, high contrast
- Border color: `var(--color-green-dim)` (#006644) — visible mid-green border
- Hover glow: `var(--glow-green)` — consistent with primary button hover

## Design Update

Added selection action bar frame to Pencil design (`designs/cipher-box-design.pen`) in the File Browser screen, matching the implemented styles:

- Bar: `#003322` background with `#00D084` top border
- Download/Move buttons: `#00D084` text, `#006644` border
- Delete button: `#EF4444` text and border
- Count text: `#00D084` bold, clear text: `#006644`

## Files Changed

- `apps/web/src/styles/file-browser.css` — Added 8 lines of CSS overrides
- `designs/cipher-box-design.pen` — Added selectionActionBar frame to File Browser screen
