---
created: 2026-02-21T12:00
title: 'Phase 14 security review: deferred findings (M1, M5, L1, L4)'
area: shares
files:
  - apps/api/src/shares/entities/share.entity.ts
  - apps/api/src/shares/shares.controller.ts
  - apps/web/src/services/share.service.ts
---

## Problem

Security review (REVIEW-2026-02-21-phase14.md) identified items deferred to future work:

- **M1**: `itemName` stored as plaintext on server. File/folder names in the `shares` table leak content metadata. Fix: encrypt `itemName` with recipient's public key; recipient decrypts for display.
- **M5**: `reWrapForRecipients` silently swallows errors. If key re-wrapping fails for a recipient, it logs a warning but the recipient gets a share with missing keys. Fix: surface a non-blocking notification to the sharer, or implement background retry.
- **L1**: `/shares/lookup` enables public key enumeration (200/404 distinction). Mitigated by requiring authentication and ThrottlerGuard, but an authenticated attacker can enumerate registered public keys. Consider returning 200 with `{ exists: boolean }` always.
- **L4**: No pagination on `getReceivedShares` and `getSentShares` endpoints. A user with many shares could see slow responses. Fix: add `limit`/`offset` query params.

## Solution

- M1: Encrypt `itemName` with recipient's public key (ECIES), decrypt client-side for display. Requires schema change (longer field for ciphertext).
- M5: Add a toast/notification system for background operation failures. Consider a retry queue in the share store.
- L1: Change lookup to always return 200 with `{ exists: boolean }` instead of 404. Update client to check boolean.
- L4: Add pagination with `@Query() limit: number, @Query() offset: number` with sensible defaults (limit=50, offset=0).
