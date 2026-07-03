# Deferred Items — Phase 68.1

Out-of-scope discoveries logged during plan execution (not fixed; scope boundary rule).

## From 68.1-11 (share/invite creation)

- **`apps/web/src/services/share.service.ts`** still throws
  `'deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired'` in
  `createShare`, `updateSharePermission`, `fetchShareKeys`, and `fetchPendingRotations`.
  This file is marked `@deprecated: Use @cipherbox/sdk instead` and was explicitly
  out of 68.1-11's `files_modified` scope (only `key-wrapping.ts`, `ShareDialog.tsx`,
  `invite.service.ts` were touched).
  - `ShareDialog.tsx`'s `handleDowngradeConfirm` (pre-existing, not part of 68.1-11's
    task list) still calls `share.service.ts`'s `updateSharePermission` and will still
    throw at runtime when a user tries to downgrade a write share back to read-only.
    This is a **pre-existing bug**, not a regression introduced by 68.1-11 — the
    upgrade path (`handleUpgrade`, in scope for 68.1-11) now fails gracefully with a
    user-facing error instead of an unconditional throw; downgrade should get the
    same treatment (and ideally a real implementation) in a follow-up.
  - `checkPendingRotation`/`fetchPendingRotations` are unused by any current call
    site found during this plan's grep sweep — left as-is.

- **Write-permission share/invite creation** (SHARE-WRITE-KEY web-wiring gap): see
  the `68.1-11-SUMMARY.md` "Known Gaps" section — a full architecture note, not a
  simple out-of-scope item, so it is documented there rather than duplicated here.

## From 68.1-24 (GAP-6 backfill removal)

- **`apps/api/src/shares/shares.controller.spec.ts` `updateGrant` test** — pre-existing
  failure at HEAD (confirmed via `git show HEAD:...`, unrelated to this plan's changes).
  `SharesController.updateGrant` calls `sharesService.updateGrant(shareId, userId,
  readDescriptorRef, rootGeneration, writeDescriptorRef, clearWriteDescriptor)` (6 args,
  added in 68.1-19), but the test's `toHaveBeenCalledWith` assertion only lists the first
  4 args, so it now fails with two unexpected trailing `undefined`s. Not touched — outside
  this plan's `files_modified` (`updateGrant` describe block, not `updateShareItemName`).
  Needs a follow-up to update the assertion to include `dto.writeDescriptorRef` and
  `dto.clearWriteDescriptor`.

- **`apps/api/src/ipns/ipns-verify-cache.spec.ts` and
  `apps/api/src/metrics/http-metrics.interceptor.spec.ts`** — pre-existing `tsc --noEmit`
  errors on `apps/api`'s own tsconfig (TS2352 unsafe cast, TS2724 missing `HttpArgumentsHost`
  export from `@nestjs/common`). Unrelated to the shares module; not in this plan's file
  scope. `apps/api` typecheck is not part of the root `pnpm typecheck` chain (which only
  covers crypto/core/api-client/sdk-core/sdk/web), so this did not block the plan's
  `pnpm typecheck` acceptance criterion.

- **`pnpm lint:fix` (repo-root)** — fails on pre-existing errors in `landing/.astro/*.d.ts`
  (generated Astro content types: triple-slash-reference, empty-object-type) and warnings
  in `apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts` (`no-explicit-any`). None of
  these files were touched by this plan; `pnpm api:generate`'s `openapi:generate` + `orval
  generate` + `api-client build` steps all succeeded before the trailing `lint:fix` step hit
  these unrelated errors. Scoped `eslint --fix` on this plan's touched files passed clean.

- **`packages/api-client` orval `clean` gap** — `orval.config.ts` has no `output.clean: true`,
  so regenerating after deleting the `UpdateItemNameDto` schema left an orphaned
  `src/models/updateItemNameDto.ts` file and a stale `export * from './updateItemNameDto'`
  barrel line in `src/models/index.ts` that `pnpm api:generate` did not remove on its own.
  Manually deleted both as part of this plan (in scope: `packages/api-client/src/models` is
  in `files_modified`). A future plan could add `output.clean: true` to
  `packages/api-client/orval.config.ts` to make future removals self-cleaning — architectural
  tooling change, not done here.
