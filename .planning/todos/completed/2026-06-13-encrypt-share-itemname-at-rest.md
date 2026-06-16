---
created: 2026-06-13T14:00
title: 'Encrypt share itemName at rest (Phase 14 security finding M1)'
area: shares
files:
  - apps/api/src/shares/entities/share.entity.ts
  - apps/api/src/shares/shares.service.ts
  - apps/web/src/services/share.service.ts
---

## Problem

Security finding **M1** from `REVIEW-2026-02-21-phase14.md`, still **open** as of 2026-06-13 (verified against live code). The shares table stores `itemName` (file/folder names) as server-readable plaintext, leaking content metadata for shared items even though the server is otherwise zero-knowledge.

Evidence:

- `apps/api/src/shares/entities/share.entity.ts:45-50` — `itemName` is a plaintext `varchar(255)` (the column comment explicitly notes it is plaintext).
- `apps/api/src/shares/shares.service.ts:96` — server stores the raw `dto.itemName`.
- `apps/web/src/services/share.service.ts:117` — client sends the raw name. Contrast: `encryptedKey` in the same flow IS ECIES-wrapped, so the pattern exists.

This was previously bundled in `.planning/todos/done/2026-02-21-phase14-security-review-deferred.md` (M1, M5, L1, L4). M5, L1, and L4 have since been implemented, so that todo was closed — but M1 was never addressed and fell off the actionable queue. This todo re-surfaces it.

## Solution

Encrypt `itemName` with the recipient's public key (ECIES), mirroring the `encryptedKey` flow, and decrypt client-side for display:

- Add an encrypted column (longer field for ciphertext) on the shares entity; migrate the plaintext column.
- API stores only the ciphertext; no plaintext name is persisted.
- Client encrypts the name with the recipient pubkey on share creation and decrypts on render.

Note: M1 is documented in `REVIEW-2026-02-21-phase14.md` as an accepted trade-off for the share-discovery UX. Confirm whether to implement or formally accept-and-document before scheduling.
