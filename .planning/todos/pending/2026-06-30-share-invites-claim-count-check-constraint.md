---
created: 2026-06-30T00:00:00.000Z
title: Add a DB CHECK so share_invites.claim_count stays within [0, max_claims]
area: data-integrity
severity: low
files:
  - apps/api/src/shares/entities/share-invite.entity.ts
  - apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts
---

> Deferred from the Phase 66 ship (CodeRabbit major finding #11). Defense-in-depth
> only — the claim flow already enforces the bound at the application layer; the
> Phase 66 cutover migration has shipped, so this needs a NEW forward migration
> rather than an in-place edit.

## Problem

`share_invites` has `claim_count` (default 0) and `max_claims` (default 1) with
no DB-level CHECK. Nothing at the schema level prevents `claim_count` from going
negative or exceeding `max_claims`.

Today the invariant holds at the application layer: the atomic claim UPDATE
guards with `AND claim_count < max_claims` and only ever does
`claim_count = claim_count + 1`, so it cannot over-claim or go negative through
the supported path.

## Proposed fix

Add a CHECK constraint via a new forward migration (do NOT edit the shipped
`ApiSchemaCutover` migration in place):

```sql
ALTER TABLE "share_invites"
  ADD CONSTRAINT "CHK_share_invites_claim_count"
  CHECK ("claim_count" >= 0 AND "claim_count" <= "max_claims");
```

Mirror it on the entity with a `@Check(...)` decorator for documentation.
