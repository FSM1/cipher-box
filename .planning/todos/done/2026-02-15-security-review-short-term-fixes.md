---
created: 2026-02-15T12:00
title: Security review short-term fixes (H-01, H-06, H-07, M-01, M-04, M-06)
area: auth
files:
  - apps/api/src/auth/auth.service.ts:423-445
  - packages/crypto/src/registry/encrypt.ts:49-62
  - packages/crypto/src/registry/schema.ts:69-84
  - apps/api/src/migrations/1700000000000-FullSchema.ts:66-90
  - apps/api/src/device-approval/device-approval.service.ts:22-33
  - apps/api/src/device-approval/dto/create-approval.dto.ts:13-19
---

## Problem

Security review (REVIEW-2026-02-15-phase-12.2-12.4.md) identified 6 issues for short-term fix:

- **H-01**: unlinkMethod has TOCTOU race — two concurrent unlinks when user has 2 methods can delete both, locking user out. Needs DB transaction with SELECT...FOR UPDATE.
- **H-06**: Decrypted registry plaintext, encrypted JSON buffers, and HKDF-derived seeds never cleared from memory. clearBytes() exists but isn't used in hot paths.
- **H-07**: Registry schema fields (deviceId, publicKey, ipHash) only checked as strings, not for length/format. Compromised device could inject multi-MB strings.
- **M-01**: No UNIQUE constraint on (type, identifier_hash) in auth_methods table. Concurrent linkMethod requests can create duplicates.
- **M-04**: No limit on concurrent pending approval requests per user. Unlimited requests can fill DB and overwhelm approver UI.
- **M-06**: deviceName in create-approval DTO has no @MaxLength or character restriction. User-controlled, displayed in approval modal.

## Solution

- H-01: Wrap unlinkMethod in queryRunner transaction with `SELECT ... FOR UPDATE` lock on auth_methods
- H-06: Add try/finally blocks with clearBytes(plaintext) in encryptRegistry/decryptRegistry
- H-07: Add hex format + length validation for deviceId/publicKey/ipHash, maxLength for name/appVersion/deviceModel
- M-01: New migration adding UNIQUE constraint on (type, identifier_hash)
- M-04: Add check in createRequest: count pending requests for user, reject if >= 5
- M-06: Add @MaxLength(100) and @Matches(/^[\w\s-]+$/) on deviceName DTO
