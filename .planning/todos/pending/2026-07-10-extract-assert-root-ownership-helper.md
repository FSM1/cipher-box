---
created: 2026-07-10
title: Extract shared assertRootOwnership helper for the share-plane D-01 gate
area: api
files:
  - apps/api/src/shares/share-invite.service.ts
  - apps/api/src/shares/shares.service.ts
resolves_phase: 77
---

## Problem

Phase 71 (D-01/SC#1) added an identical 7-line root-ownership gate to both
`ShareInviteService.createInvite` and `SharesService.createShare`:

```ts
const owned = await this.ipnsRecordRepo.findOne({
  where: { ipnsName: dto.shareRootIpnsName, userId: sharerId },
});
if (!owned) {
  throw new ForbiddenException('You are not the registered owner of this node');
}
```

The two copies are byte-identical apart from a trailing comment. It was left
duplicated intentionally at ship time — the code is security-critical, unit-tested
(both services assert the 403), and verified, so a pre-ship refactor was judged
higher-risk than the marginal DRY benefit.

## Solution

Extract a small shared helper (e.g. `assertRootOwnership(sharerId, shareRootIpnsName)`
on a shared provider or a `ShareOwnershipService`) that both services inject, so the
gate lives in one place. Keep the ForbiddenException message and the fail-fast ordering
(before recipient lookup in `createShare`). Re-run `pnpm --filter @cipherbox/api test`
(the `shares` suite covers both 403 paths) after the extraction.

Low priority / low risk — pure dedup, no behavior change. Not tied to a specific phase.
