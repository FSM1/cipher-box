---
created: 2026-06-30T00:00:00.000Z
title: Bulk-revoke shares with a direct DELETE instead of find + remove
area: performance
severity: low
files:
  - apps/api/src/shares/shares.service.ts
  - apps/api/src/shares/shares.service.spec.ts
---

> Deferred from the Phase 66 ship (CodeRabbit nitpick, Trivial). A perf-only
> improvement on a non-hot path; switching the spec's shared query-builder mock to
> sequence two execute() results is more churn than the gain warrants right now.
> Verified SAFE to do (no behavior change) — see below.

## Problem

`SharesService.revokeForItems` (~line 170) loads full `Share` rows — including the
`bytea` descriptor columns `readDescriptorRef` / `writeDescriptorRef` /
`itemNameEncrypted` — into memory before deleting them:

```ts
const shares = await manager.find(Share, {
  where: { sharerId, rootIpnsName: In(uniqueNames) },
});
if (shares.length > 0) {
  await manager.remove(shares);
}
// ...
return { revokedShares: shares.length, revokedInvites: inviteResult.affected ?? 0 };
```

For a subtree revoke touching many shares this needlessly fetches every blob.

## Proposed fix

Use a direct DELETE and its affected count:

```ts
const shareResult = await manager
  .createQueryBuilder()
  .delete()
  .from(Share)
  .where('sharer_id = :sharerId', { sharerId })
  .andWhere('root_ipns_name IN (:...names)', { names: uniqueNames })
  .execute();
// ...
return { revokedShares: shareResult.affected ?? 0, revokedInvites: inviteResult.affected ?? 0 };
```

## Verified safe

The `Share` entity has NO `@OneToMany`, NO `@BeforeRemove`/`@AfterRemove` hooks,
and NO `EntitySubscriber`; its only relations are owning-side `@ManyToOne` to
`User` with `onDelete: 'CASCADE'` (a DB-level cascade that fires on USER deletion,
not on Share deletion). So `manager.remove()` triggers nothing that a raw DELETE
skips — the change is behavior-preserving. If `In` becomes unused in
`shares.service.ts`, drop it from the typeorm import.

## Spec impact

`shares.service.spec.ts` `revokeForItems` tests currently mock `manager.find` +
`manager.remove` and assert `revokedShares` from `shares.length`. They must switch
to the shared `queryBuilder` mock used for the invite UPDATE, sequencing
`execute` with `mockResolvedValueOnce({ affected: <shares> })` then
`mockResolvedValueOnce({ affected: <invites> })` (the share DELETE runs before the
invite UPDATE).
