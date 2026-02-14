---
created: 2026-02-14T15:49
title: Migrate auth method identifiers to SHA-256 hashed lookup
area: auth
files:
  - apps/api/src/auth/controllers/identity.controller.ts
  - apps/api/src/auth/auth.service.ts
  - apps/api/src/auth/entities/auth-method.entity.ts
  - apps/api/src/auth/services/google-oauth.service.ts
  - apps/api/src/auth/services/siwe.service.ts
---

## Problem

Google auth methods currently use the user's **email** as the stored identifier. Google emails are mutable (Google now allows users to change their Gmail address), so this creates two risks:

1. **Lost access:** If a user changes their Google email, the identifier no longer matches and they lose their linked Google auth method.
2. **Account confusion:** If the old email is reassigned, it could theoretically match to the wrong CipherBox account.

Google provides a stable, immutable `sub` (subject) claim in their JWT — this should be the lookup identifier, not the email.

Additionally, for privacy preservation consistent with CipherBox's zero-knowledge philosophy, all auth method identifiers should be stored as SHA-256 hashes rather than plaintext. This prevents DB breach enumeration of registered accounts.

Wallet auth methods already use this pattern (`identifier_hash` + `identifier_display`). Google and email methods should follow the same pattern.

### Target uniform pattern

| Auth Type | `identifier_hash`            | `identifier_display` | Lookup key                   |
| --------- | ---------------------------- | -------------------- | ---------------------------- |
| Google    | SHA-256(google_sub)          | <user@gmail.com>     | SHA-256(google_sub)          |
| Wallet    | SHA-256(checksummed_address) | 0xAbCd...1234        | SHA-256(checksummed_address) |
| Email     | SHA-256(normalized_email)    | <user@example.com>   | SHA-256(normalized_email)    |

### Note on email entropy

Email addresses have lower entropy than Google subs or wallet addresses, making dictionary attacks on `identifier_hash` more feasible. However, hashing still raises the bar significantly over storing plaintext and maintains consistency across all auth method types.

## Solution

1. Change Google identity flow to extract and use `sub` instead of `email` for identifier storage
2. Store `SHA-256(sub)` in `identifier_hash` column (already exists from wallet work)
3. Store email in `identifier_display` for UI rendering
4. Migrate email auth methods to use `identifier_hash = SHA-256(normalized_email)`, `identifier_display = email`
5. Update all auth method lookups (`findOrCreateUserByEmail`, `linkMethod`, `unlinkMethod`) to query by `identifier_hash`
6. Ensure `findOrCreateUserByEmail` still works for cross-method email linking (Google + email methods with same email should resolve to same user)
7. Add migration for existing auth_methods rows (hash existing identifiers)
