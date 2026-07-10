---
created: 2026-06-30T00:00:00.000Z
title: Make IPNS first-publish INSERT race return a clean 409 instead of a unique-violation 500
area: tech-debt
severity: low
files:
  - apps/api/src/ipns/ipns.service.ts
---

> Deferred from the Phase 66 ship (CodeRabbit major finding #13). Real but an
> edge concurrency case; correctness is already guaranteed by the DB unique
> constraint, so only the error shape is suboptimal. Touches the e2e-verified
> publish path and is not covered by the existing publish-gate suite, so it is
> not a low-risk inline fix at ship time.

## Problem

`upsertIpnsRecord` handles the first publish (no existing row) as
`findOne` → `create` → `save` (an INSERT). Two concurrent first-publishes of the
same brand-new `ipnsName` both observe `!existing` and both INSERT. The
`@Unique(['ipnsName'])` constraint guarantees exactly one wins — the loser gets a
Postgres unique-violation, which currently surfaces as a 500 rather than the
clean `409` the TEE-04 contract promises for "concurrent publishes → exactly one
409, zero lost updates."

No data is lost (the constraint is authoritative); only the rejected racer's
HTTP status is wrong. The existing publish-gate suite (Test 16) exercises
concurrent *forward* publishes against an existing row, not concurrent *first*
publishes.

## Proposed fix

Wrap the first-publish `save` and translate the unique violation to a
`ConflictException` (409), mirroring the CAS `affected === 0` path:

```ts
try {
  const saved = await this.ipnsRecordRepository.save(folder);
  ...
} catch (e) {
  if (e instanceof QueryFailedError && /* unique_violation 23505 */) {
    throw new ConflictException({ statusCode: 409, message: 'IPNS record already exists' });
  }
  throw e;
}
```

Add an sdk-e2e case: two concurrent first-publishes of a fresh name → exactly
one 200 + one 409.
