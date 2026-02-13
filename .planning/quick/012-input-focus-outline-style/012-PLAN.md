# Quick Task 012: Replace double-outline focus style with thicker border

## Goal

Remove the double-outline effect on focused inputs, buttons, and modal close buttons in dialogs. Replace with a thicker (2px) single border.

## Tasks

### Task 1: Fix dialog input, button, and modal close focus styles

**Files:** `apps/web/src/styles/dialogs.css`, `apps/web/src/styles/modal.css`

**Changes:**

1. `.dialog-input:focus` — Add `border-width: 2px`, compensate padding by -1px, add `outline: none`
2. `.dialog-button` — Change base `border` from `none` to `1px solid transparent` for consistent sizing
3. `.dialog-button:focus-visible` — Replace outer outline with `border-width: 2px` + `outline: none`
4. `.modal-close:focus` — Replace outer outline with `border-color: green` + `border-width: 2px` + `outline: none`
