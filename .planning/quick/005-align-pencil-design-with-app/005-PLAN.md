# Quick Task 005: Align Pencil Design with Staging App

## Goal

Reorganize the Pencil design file to be a clear, structured reference that matches the deployed staging app. Remove exploration artifacts, organize by device/flow, and ensure visual consistency with the actual implementation.

## Tasks

### Task 1: Clean up canvas — remove old exploration frames

- Delete Phase 6.3 exploration frames (Option A, Option B, Toolbar Options, Border Options, Unified Structure Mockup)
- Delete old Empty State Design (keep the improved version)
- Delete Hover States reference frame

### Task 2: Organize canvas into labeled sections

- Create 3 clearly labeled sections: Desktop Screens, Mobile Screens, Component Designs
- Add section headers with JetBrains Mono bold green text
- Add individual screen labels below each section header
- Position all frames in logical grid layout with consistent spacing

### Task 3: Rebuild desktop E2E flow screens

- Update Login (Connected) to match staging: remove logo icon, update text, remove footer, match font sizes
- Update Login (Disconnected) to match staging: same layout, grayed button, red API status
- Rebuild File Browser (Empty State): add sidebar, proper footer, correct border colors
- Create File Browser (With Files): copy empty, add file list with [DIR]/[FILE] rows, 3-column layout
- Create Context Menu overlay: file row highlighted, dropdown with Download/Rename/Move/Delete

### Task 4: Rebuild mobile E2E flow screens

- Update Login Mobile (Connected): remove logo icon, match staging text/button
- Update Login Mobile (Disconnected): same with grayed button
- Rebuild File Browser Mobile (Empty): no sidebar, centered buttons, footer
- Create File Browser Mobile (With Files): 2-column layout (no date column)

### Task 5: Organize Quick Task designs

- Move Empty State, Staging Banner designs into labeled Components section

### Task 6: Visual verification

- Screenshot each screen and compare against staging app
- Verify fonts, colors, layout, and content match
