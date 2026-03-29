## SDK uploadFile always uses GCM — CTR streaming never triggers for new uploads

**Priority:** High
**Discovered:** 2026-03-29

The SDK's `uploadFile()` in `packages/sdk-core/src/upload/index.ts` hardcodes `encryptAesGcm` (line 88) and `encryptionMode: 'GCM'` (line 113). The `selectEncryptionMode()` function in `apps/web/src/services/streaming-crypto.service.ts` is only used for the duplicate-file re-encrypt path — new uploads through the SDK always use GCM regardless of file size or MIME type.

**Fix required:**

1. Add `encryptionMode` parameter to `sdkCore.uploadFile()` and `client.uploadFile()`
2. When mode is CTR: use `encryptAesCtr` instead of `encryptAesGcm`, generate CTR IV, set `encryptionMode: 'CTR'` in metadata
3. Caller determines mode based on MIME type + size (>256KB media → CTR)
4. The `@cipherbox/crypto` package already exports `encryptAesCtr` — just needs wiring

**Impact:** CTR streaming playback badge never appears for newly uploaded files. The decrypt SW pipeline works (verified), but files are never encrypted with CTR so the streaming path is never activated.
