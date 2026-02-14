---
created: 2026-02-07T12:00
title: Offload large file encryption to Web Worker
area: ui
files:
  - apps/web/src/services/file-crypto.service.ts
  - apps/web/src/services/upload.service.ts
---

## Problem

`encryptFile()` in `file-crypto.service.ts` calls `file.arrayBuffer()` and `encryptAesGcm()` on the main thread. For large files (approaching the 100MB limit), this blocks the UI thread and can cause the browser to appear frozen during encryption.

Identified by CodeRabbit review on PR #55.

## Solution

Offload encryption to a Web Worker for files >= 10MB:

1. Create a dedicated encryption worker (`encrypt.worker.ts`)
2. Worker receives `File`/`Blob`, generates file key + IV, runs `encryptAesGcm`, returns ciphertext + wrapped key
3. Main thread stays responsive, upload progress UI remains smooth
4. Files < 10MB continue using main thread (worker overhead not worth it for small files)

**Considerations:**

- Web Crypto API is available in Worker contexts
- Need to handle `Transferable` objects for zero-copy ArrayBuffer passing
- Worker bundling with Vite uses `new Worker(new URL(...), { type: 'module' })` pattern
- Error handling: worker crashes should fall back to main thread encryption
