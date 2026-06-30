---
created: 2026-06-30T00:00:00.000Z
title: Restore full unit coverage for the reshaped shares module (descriptor-ref model)
area: testing
severity: medium
files:
  - apps/api/src/shares/shares.service.ts
  - apps/api/src/shares/share-invite.service.ts
  - apps/api/src/shares/shares.controller.ts
  - apps/api/src/shares/invites.controller.ts
  - apps/api/src/shares/share-invites.controller.ts
---

> Deferred from the Phase 66 ship. The cutover (66-03/66-04) deleted all 5 shares
> spec files (they tested the old child-key model) and did not replace them. The
> ship review restored only the security-critical slice — a focused
> `share-invite.service.spec.ts` for the claim path (T-66-E1, self-claim, root
> identity, idempotency). The rest of the module is still unit-uncovered.

## Problem

After the descriptor-ref cutover, these reshaped surfaces have no unit tests:

- `SharesService` — descriptor-ref grant creation, `revokeShare` hard-delete
  (DATA-02 / DATA-04 revoke), received/sent share listing, hidden-by-recipient.
- `SharesController` / `InvitesController` / `ShareInvitesController` — the
  slimmed descriptor-ref request/response surfaces and authz guards.
- `ShareInviteService.createInvite` and the rest of the invite lifecycle beyond
  the claim path (status/expiry transitions, listing, cleanup).

The publish/resolve plane (TEE-04/05/07, WRITE-04, DATA-03) is well covered
(ipns unit specs + sdk-e2e ipns-publish-gate). This gap is isolated to shares.

## Proposed fix

Author unit specs mirroring the deleted ones but against the new model. The
deleted harnesses are recoverable from git for the DI/mock scaffolding:

```
git show <pre-cutover-sha>:apps/api/src/shares/shares.service.spec.ts
git show <pre-cutover-sha>:apps/api/src/shares/shares.controller.spec.ts
git show <pre-cutover-sha>:apps/api/src/shares/invites.controller.spec.ts
git show <pre-cutover-sha>:apps/api/src/shares/share-invites.controller.spec.ts
```

Consider folding this into Phase 68 (which wires the real web share path) so the
specs are written against the finalized, runnable flow rather than mid-milestone
stubs.
