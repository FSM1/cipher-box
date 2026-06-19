---
created: 2026-03-28T02:03:43.219Z
title: Add media preview E2E test suite
area: testing
files:
  - apps/web/src/components/file-browser/VideoPlayerDialog.tsx
  - apps/web/src/components/file-browser/AudioPlayerDialog.tsx
  - tests/web-e2e/tests/full-workflow.spec.ts
---

## Problem

PDF viewer, video player, and audio player have no E2E test coverage. These are user-facing features that were manually verified during Phase 12.1 but never automated. The feature matrix lists them under "Features Without E2E Coverage".

## Solution

Create `tests/web-e2e/tests/media-preview.spec.ts` covering:

1. **PDF viewer** — upload a small PDF fixture, click to preview, verify the PDF viewer dialog renders with controls
2. **Video player** — upload a >256KB MP4 fixture, open player, verify playback controls appear and video element loads metadata (duration)
3. **Audio player** — upload a >256KB MP3/audio fixture, open player, verify player controls and playback
4. **Small media fallback** — upload <256KB video, verify GCM blob URL path works (no SW interception)

Test fixtures: create minimal valid media files (small PDF, ~300KB MP4, ~300KB MP3) in `tests/web-e2e/fixtures/`.
