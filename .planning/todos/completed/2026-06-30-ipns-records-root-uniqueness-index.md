---
created: 2026-06-30T00:00:00.000Z
title: Add a partial unique index on ipns_records(user_id) WHERE is_root for defense-in-depth
area: data-integrity
severity: low
files:
  - apps/api/src/ipns/entities/ipns-record.entity.ts
  - apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts
---

> Deferred from the Phase 66 ship (CodeRabbit major finding F2). Out of the
> phase's publish-gate/cutover domain and requires a data-model invariant
> decision + a migration, so it is not a low-risk in-scope fix.

## Problem

`IpnsRecord` (`@Entity('ipns_records')`) enforces uniqueness only on
`ipnsName` (`@Unique(['ipnsName'])`). It also carries an `is_root` boolean
(`isRoot`). Nothing at the DB level prevents two rows with the same `user_id`
both having `is_root = true`, so a user could in principle accumulate multiple
"root" records and make root lookups ambiguous.

Today the invariant is upheld at the application layer: a user's root IPNS name
is deterministically derived from their root folder key (one root per user), and
the publish/resolve plane keys by `ipnsName` alone — so this is a
defense-in-depth gap, not an observed bug.

## Proposed fix

Add a partial unique index and back it with a migration:

```ts
// entity
@Index('UQ_ipns_records_user_root', ['userId'], {
  unique: true,
  where: '"is_root" = true',
})
```

```sql
-- migration
CREATE UNIQUE INDEX "UQ_ipns_records_user_root"
  ON "ipns_records" ("user_id") WHERE "is_root" = true;
```

## Before doing this

Confirm the one-root-per-user invariant actually holds for every flow that sets
`is_root = true` (vault creation, import/export, any future multi-vault work).
If multi-root per user is ever intended, this constraint must NOT be added.
A fresh forward migration is required — the Phase 66 cutover migration has
already shipped; do not edit it in place.
