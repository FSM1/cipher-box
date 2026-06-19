---
created: 2026-02-10T12:00
title: Fix TEE critical integration bugs (C1, C2, H1)
area: api
files:
  - apps/api/src/republish/republish.service.ts:88-94
  - apps/api/src/tee/tee.service.ts:8-19
  - apps/api/src/tee/tee.service.ts:90
  - tee-worker/src/routes/public-key.ts:27
  - tee-worker/src/routes/health.ts:13-17
  - tee-worker/src/routes/republish.ts:29-30
---

## Problem

Three critical integration bugs prevent ALL automatic IPNS republishing from working. Identified by security review (REVIEW-2026-02-07-tee-phase8.md).

**C1: Missing `currentEpoch`/`previousEpoch` in republish batch request**
The API's `RepublishEntry` interface omits `currentEpoch` and `previousEpoch` fields. The TEE worker expects them. `decryptWithFallback()` receives `undefined` for both epochs, deriving a key for `"epoch-undefined"` which never matches. Every republish fails silently; IPNS records expire after 48h.

**C2: Public key encoding mismatch (hex vs base64)**
TEE worker returns public key as hex (`Buffer.from(publicKey).toString('hex')`). API decodes it as base64 (`atob(data.publicKey)`). This produces garbled bytes stored in `tee_key_state`, breaking all subsequent ECIES operations. Clients receive an invalid TEE public key.

**H1: Health endpoint response shape mismatch**
TEE worker health returns `{ status, mode, uptime }`. API expects `{ healthy: boolean, epoch: number }`. `data.healthy` is always `undefined` (falsy), `data.epoch` is `undefined`. TEE initialization stores keys for an undefined epoch.

## Solution

**C1:** Either add `currentEpoch`/`previousEpoch` to the API's `RepublishEntry` and populate from `TeeKeyStateService.getCurrentState()`, or (preferred) have TEE worker resolve its own epoch state internally using `entry.keyEpoch` directly with fallback.

**C2:** Align encoding — use hex consistently since TEE worker already sends hex. Change `tee.service.ts` to decode with `Buffer.from(data.publicKey, 'hex')` instead of `atob()`.

**H1:** Update TEE worker health endpoint to return `{ healthy: true, epoch, mode, uptime }` matching what `tee.service.ts` expects.
