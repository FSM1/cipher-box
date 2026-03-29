---
created: 2026-03-29T21:10:42.273Z
title: SDK uploadFile hardcodes GCM — wire CTR encryption for media uploads
area: sdk
files:
  - packages/sdk-core/src/upload/index.ts:88
  - packages/sdk-core/src/upload/index.ts:113
  - packages/sdk/src/client.ts:691
  - apps/web/src/services/streaming-crypto.service.ts:53
  - apps/web/src/hooks/useDropUpload.ts
---

## Problem

The SDK's `uploadFile()` in `packages/sdk-core/src/upload/index.ts` hardcodes `encryptAesGcm` (line 88) and sets `encryptionMode: 'GCM'` (line 113). New file uploads through the SDK always use GCM regardless of file size or MIME type.

The `selectEncryptionMode()` function in `apps/web/src/services/streaming-crypto.service.ts` correctly returns `'CTR'` for media files >256KB, but it's only called for the duplicate-file re-encrypt path in `useDropUpload.ts` — never for new uploads through the SDK.

As a result, the CTR streaming playback pipeline (Service Worker interception, range-request decryption) never activates for newly uploaded files. The decrypt SW works correctly (verified), but files are never encrypted with CTR so `isStreaming` is always false and the encrypted badge never appears.

Discovered during E2E test debugging — the streaming-playback CTR badge test correctly caught this bug.

## Solution

1. Add `encryptionMode` parameter to `sdkCore.uploadFile()` params (already accepted by `createFileMetadata`)
2. When mode is `'CTR'`: use `encryptAesCtr` (already exported from `@cipherbox/crypto`) instead of `encryptAesGcm`, generate CTR IV via `generateCtrIv()`
3. Pass `encryptionMode` through `client.uploadFile()` → `sdkCore.uploadFile()` → `createFileMetadata()`
4. Caller determines mode: either SDK client checks MIME type + size internally, or the web app's `useDropUpload` passes the mode explicitly
5. Un-skip the `streaming-playback.spec.ts` CTR badge test after fix
