---
created: 2026-02-15T12:00
title: Security review medium-term fixes (H-08, M-07, M-11)
area: auth
files:
  - apps/web/src/lib/device/identity.ts:86-92
  - apps/web/src/hooks/useAuth.ts:253-258
  - apps/desktop/src-tauri/src/api/types.rs:8-38
---

## Problem

Security review (REVIEW-2026-02-15-phase-12.2-12.4.md) identified 3 higher-effort issues for medium-term fix:

- **H-08**: Device Ed25519 private key stored as plaintext number array in IndexedDB. XSS can exfiltrate it, enabling device impersonation in registry and unauthorized device approval.
- **M-07**: Temporary REQUIRED_SHARE JWT (placeholder `pending-core-kit-{userId}` login) gets full-privilege JWT. Should be scoped to device-approval endpoints only.
- **M-11**: All Rust auth structs derive `Debug`. Any `{:?}` format outputs full tokens to logs. Future log::debug! calls would leak secrets.

## Solution

- H-08: Use non-extractable CryptoKey objects or wrap device key with session-derived key before storing in IndexedDB
- M-07: Add JWT claim for scope (e.g., `scope: 'device-approval'`) and guard device-approval endpoints to accept limited JWTs, while other endpoints reject them
- M-11: Replace `#[derive(Debug)]` with manual Debug impl that redacts sensitive fields (access_token, refresh_token)
