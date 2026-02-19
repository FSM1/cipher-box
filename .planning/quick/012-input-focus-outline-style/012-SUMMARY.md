# Quick Task 012: Summary

## What Changed

Replaced the double-outline focus indicator pattern (border + offset outline) with a single thicker border (2px) on focus for dialog elements.

## Files Modified

- `apps/web/src/styles/dialogs.css` — Input and button focus styles
- `apps/web/src/styles/modal.css` — Modal close button focus style

## Root Cause

The global `:focus-visible` rule in `index.css` applies `outline: 2px solid` with `outline-offset: 2px` to all focused elements. Components that already have their own border (inputs, secondary buttons, close button) showed both the border and the outer outline — a double ring effect.

## Fix

- `.dialog-input:focus`: Added `border-width: 2px` + `outline: none` with padding compensation (`-1px`) to prevent layout shift
- `.dialog-button`: Changed base border from `none` to `1px solid transparent` so focus can thicken it
- `.dialog-button:focus-visible`: Replaced outline with `border-width: 2px` + `outline: none`
- `.modal-close:focus`: Replaced outline with `border-color` + `border-width: 2px` + `outline: none`

## Commit

78ca2fe
