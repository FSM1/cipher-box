---
created: 2026-02-17T22:30
title: Deduplicate Audio/Video player dialog logic
area: ui
files:
  - apps/web/src/components/file-browser/AudioPlayerDialog.tsx
  - apps/web/src/components/file-browser/VideoPlayerDialog.tsx
---

## Problem

AudioPlayerDialog (481 lines) and VideoPlayerDialog (479 lines) share near-identical logic:

- Verbatim copy of `formatTime()` utility
- Same `getMime()` pattern with extension-to-MIME lookup
- Identical streaming vs blob preview resolution (lines 55-84 structurally identical in both)
- Same playback state management (isPlaying, currentTime, duration, volume, speed)
- Same seek/transport control handlers

## Solution

- Extract shared `formatTime()` to a utility (or shared media helpers file)
- Extract `useMediaPlayback` hook for transport state (play/pause, seek, volume, speed, time tracking)
- Extract streaming/blob preview resolution into a shared `useMediaPreview` that wraps `useStreamingPreview` + `useFilePreview` with the mode-selection logic
- Keep Audio/Video dialogs as thin wrappers for their specific UI (visualizer vs video element)
