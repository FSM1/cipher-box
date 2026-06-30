---
created: 2026-06-30T00:00:00.000Z
title: Finish ShareInviteService lifecycle unit coverage (createInvite + invite lifecycle)
area: testing
severity: low
files:
  - apps/api/src/shares/share-invite.service.ts
---

> Mostly resolved during the Phase 66 ship. The cutover (66-03/66-04) deleted all
> 5 shares spec files; the CI Test coverage gate forced restoration of the bulk of
> them during the ship review. What's RESTORED (committed on the phase branch):
>
> - `shares.service.spec.ts` — 25 tests (grant creation, revokeShare hard-delete,
>   received/sent listing, hidden-by-recipient, auth/ownership branches).
> - `shares.controller.spec.ts`, `share-invites.controller.spec.ts`,
>   `invites.controller.spec.ts` — full controller surfaces + authz threading.
> - `share-invite.service.spec.ts` — the claim path (T-66-E1, self-claim, root
>   identity, idempotency).
> - `ipns.controller.spec.ts` — all handlers incl. the new tombstone.
>
> Global + per-file jest coverage thresholds now pass.

## Remaining gap (non-blocking)

`ShareInviteService` is at ~48% line coverage: the claim path is tested, but
`createInvite` and the rest of the invite lifecycle (status/expiry transitions,
`getInvitesForItem`/`getInviteStatus` listing, expired-invite cleanup) are still
uncovered. There is no per-file coverage threshold on this file, so it does not
block CI — this is coverage-depth completeness only.

## Proposed fix

Extend `apps/api/src/shares/share-invite.service.spec.ts` with `createInvite`
(token/expiry generation, itemNameEncrypted hex/null, descriptor-ref passthrough)
and the lifecycle/listing helpers. The pre-cutover spec is recoverable from git
for scaffolding:

```
git show <pre-cutover-sha>:apps/api/src/shares/share-invite.service.spec.ts
```

## Also — contract-valid fixtures in shares.controller.spec.ts (CodeRabbit NIT3)

`shares.controller.spec.ts` fixtures (`fullShare`/`minimalShare`, ids,
`rootIpnsName`, `recipientPublicKey` at ~lines 23-55, 88-96, 141-142, 260-286)
use placeholder strings — non-UUID ids like `'share-uuid-1'`, truncated IPNS
stubs like `'k51qzi5uqu5full'`, and short public keys like `'04sharerkey'`.
Because these controller tests mock the service and bypass Nest pipes, invalid
fixtures can mask API-contract drift. Swap them to contract-valid values: real
UUIDs, full `k51qzi5uqu5...` (~62-char) IPNS names, and `0x04` + 128 hex public
keys. The `lookupUser` test in the same file already models a valid key as
`` `0x04${'a'.repeat(128)}` `` — reuse that rigor. Behavior-only; no production
code touched.
