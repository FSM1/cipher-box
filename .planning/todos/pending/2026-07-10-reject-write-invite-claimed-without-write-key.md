---
created: 2026-07-10
title: Reject a write-capable invite claimed without a re-wrapped write key
area: api
files:
  - apps/api/src/shares/share-invite.service.ts
  - apps/api/src/shares/share-invite.service.spec.ts
---

## Problem

In `ShareInviteService.claimInvite`, when the invite grants write
(`invite.encryptedWriteKey !== null`) but the claim body omits `dto.encryptedWriteKey`, the
service silently produces/keeps a READ-ONLY share:
- mint path: `encryptedWriteKey: inviteGrantsWrite && dto.encryptedWriteKey ? ... : null`
- widen path: `if (isWriteUpgrade && dto.encryptedWriteKey) { existingShare.encryptedWriteKey = ... }`

The claimer silently loses the write authority the invite granted (they must supply the
re-wrapped-for-self write key). CodeRabbit suggests rejecting the claim instead (require a
non-empty `dto.encryptedWriteKey` when `inviteGrantsWrite`), on BOTH the mint and widen paths,
before consuming the invite.

Deferred from Phase 71: this is a BEHAVIOR CHANGE to the auth-critical claim flow (not a
Phase 71 regression — the silent-read-only behavior predates this phase's widen-only work).
It needs its own decision: hard-reject vs. allow an intentional read-only claim of a write
invite, and care around the atomic invite-consume ordering.

## Solution

Decide the intended semantics, then (if reject): validate `inviteGrantsWrite → dto.encryptedWriteKey`
is present BEFORE the atomic claim UPDATE, throw 400/422 otherwise, and add the negative unit
test (write invite + read-only claim body → rejected, invite NOT consumed, no read-only Share
persisted) alongside the existing T-66-E1 cases in `share-invite.service.spec.ts`.
