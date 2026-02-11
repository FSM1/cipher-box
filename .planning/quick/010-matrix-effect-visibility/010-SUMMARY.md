# Quick Task 010: Matrix Effect Visibility

## Summary

Made the matrix rain background effect visible through the app shell chrome (header, sidebar, footer) and added a dedicated matrix animation to modal backdrop overlays. The app-level animation pauses when a modal is open so only one canvas runs at a time (no performance cost).

## Changes

### MatrixBackground.tsx

- Added `opacity`, `className`, and `paused` props
- Default opacity increased from 0.25 to 0.5
- Animation frame rate increased from ~30fps to ~60fps
- Moved positioning styles from inline to `.matrix-canvas` CSS class
- Pause support: animation loop skips draw calls when `paused=true`

### useModalOpen.ts (new)

- Lightweight global open-modal counter using `useSyncExternalStore`
- `incrementModalCount()` / `decrementModalCount()` called by Modal on mount/unmount
- `useAnyModalOpen()` hook returns true when any modal is open

### AppShell.tsx

- Passes `paused={anyModalOpen}` to MatrixBackground
- App-level animation freezes when modal opens, resumes when it closes

### Modal.tsx

- Renders a dedicated `MatrixBackground` (opacity 0.35) inside the modal backdrop
- Calls `incrementModalCount` on mount, `decrementModalCount` on unmount
- Only one canvas animates at a time

### layout.css

- Added `.matrix-canvas` CSS class (position: fixed, z-index: -1)
- Removed solid `background-color` from `.app-shell` (was blocking the canvas)
- Reduced header/sidebar/footer backgrounds to `rgb(0 0 0 / 50%)`
- Main content area set to `rgb(0 0 0 / 90%)` (stays opaque)
- Converted all `rgba()` to modern `rgb()` notation

### modal.css

- Added `.matrix-canvas--modal` class for absolute positioning inside backdrop
- Reduced backdrop opacity to 40% for more visible matrix effect
- Removed `backdrop-filter: blur` (was obscuring the matrix)
- Added `z-index: 1` to `.modal-container` for proper stacking
- Converted legacy `rgba()` to modern `rgb()` notation

## Verified

- Build compiles without errors
- Matrix rain visible through header, sidebar, and footer
- Main content area remains opaque and readable
- Modal overlay shows dedicated matrix animation
- App-level canvas pauses when modal opens (single canvas performance)
- No console errors on modal open/close
