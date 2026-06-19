---
created: 2026-03-28T02:03:43.219Z
title: Add AES-CTR streaming playback E2E tests
area: testing
files:
  - apps/web/src/workers/decrypt-sw.ts
  - apps/web/src/services/streaming-crypto.service.ts
  - apps/web/src/hooks/useStreamingPreview.ts
  - packages/crypto/src/aes/decrypt-ctr.ts
  - packages/crypto/src/aes/encrypt-ctr.ts
---

## Problem

The AES-CTR streaming encryption/decryption system has 35 unit tests in `packages/crypto` but zero E2E coverage. The full pipeline — mode selection, Service Worker interception, range-request decryption, seeking — has never been tested end-to-end. Phase 12.1 left a human verification checklist that was never automated.

Key behaviors untested at E2E level:

- CTR mode selected for media >256KB (vs GCM for smaller/non-media files)
- Service Worker intercepts `/decrypt-stream/*` requests
- HTTP 206 range responses work for video seeking
- Decrypt progress bar tracks 0-100%
- Cache management (max 5 entries in SW)

## Solution

Create `tests/web-e2e/tests/streaming-playback.spec.ts` covering:

1. **CTR mode activation** — upload >256KB video, verify SW intercepts requests (check network for `/decrypt-stream/` URLs via `page.route()` or `page.on('request')`)
2. **Playback from start** — video element fires `loadedmetadata` and `canplay` events
3. **Seeking** — programmatically seek to 50%, verify playback continues (no stall/error)
4. **Progress tracking** — decrypt progress bar visible during initial fetch, reaches 100%
5. **GCM fallback** — upload <256KB video, verify blob URL path (no SW interception)
6. **Download button** — click download in player, verify decrypted file downloads

May need to combine with or depend on the media-preview suite for shared setup logic.
