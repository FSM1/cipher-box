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
