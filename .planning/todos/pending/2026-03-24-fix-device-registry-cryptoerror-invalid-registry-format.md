---
created: 2026-03-24T00:25:28.379Z
title: Fix device registry CryptoError Invalid registry format
area: core
files:
  - packages/core/src/registry/encrypt.ts:360
  - apps/web/src/services/device-registry.service.ts:19
---

## Problem

Device registry sync fails on login with `CryptoError: Invalid registry format` at `validateDeviceEntry` (core/dist/index.mjs:360). Discovered during phase 20 UAT via Playwright browser console.

Error trace:

```text
[DeviceRegistry] Failed to sync registry: CryptoError: Invalid registry format
    at validateDeviceEntry (packages/core/dist/index.mjs:360)
    at validateDeviceRegistry (packages/core/dist/index.mjs:326)
    at decryptRegistry (packages/core/dist/index.mjs:403)
    at initializeOrSyncRegistry (device-registry.service.ts:19)
```

Likely a schema mismatch between the current device registry validation code and what's stored on IPFS from an older version. The registry was written by a previous code version and the current validator rejects it.

## Solution

1. Check what fields `validateDeviceEntry` requires vs what old registries contain
2. Either relax validation for backward compatibility or add a migration path
3. Consider versioning the registry format (similar to vault blob v2)
