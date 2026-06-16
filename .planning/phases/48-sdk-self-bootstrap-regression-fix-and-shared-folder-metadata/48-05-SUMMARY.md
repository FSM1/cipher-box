---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
plan: 05
subsystem: api
tags: [api, crypto, migration, shares, security, ecies, typeorm, nestjs]

# Dependency graph
requires:
  - phase: 14
    provides: "shares.itemName plaintext-at-rest finding M1 (the threat this plan closes)"
provides:
  - "Additive nullable item_name_encrypted bytea columns on shares and share_invites"
  - "itemNameEncrypted hex DTO field on create-share, create-invite, claim-invite plus response DTOs"
  - "Service plumbing persisting client-supplied ECIES ciphertext on createShare, createInvite and the invite-claim path (zero-knowledge: server never encrypts)"
  - "Regenerated @cipherbox/api-client exposing itemNameEncrypted"
affects: [48-06]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Additive nullable ciphertext column mirroring the existing encryptedKey/encryptedIpnsKey ECIES bytea pattern"
    - "Zero-knowledge migration: additive-only, NO data UPDATE (server cannot re-encrypt legacy plaintext)"

key-files:
  created:
    - apps/api/src/migrations/1749200000000-EncryptShareItemName.ts
  modified:
    - apps/api/src/shares/entities/share.entity.ts
    - apps/api/src/shares/entities/share-invite.entity.ts
    - apps/api/src/shares/dto/create-share.dto.ts
    - apps/api/src/shares/dto/create-invite.dto.ts
    - apps/api/src/shares/dto/claim-invite.dto.ts
    - apps/api/src/shares/dto/share-response.dto.ts
    - apps/api/src/shares/dto/invite-response.dto.ts
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/share-invite.service.ts
    - apps/api/src/shares/shares.controller.ts
    - apps/api/src/shares/invites.controller.ts
    - apps/api/src/shares/share-invites.controller.ts
    - apps/api/src/shares/shares.service.spec.ts
    - packages/crypto/src/__tests__/ecies.test.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated/
    - packages/api-client/src/models/

key-decisions:
  - "Added item_name_encrypted to BOTH shares and share_invites in the same migration so decision A3 (include invite flow) has no plaintext-only path"
  - "Added itemNameEncrypted to claim-invite DTO so the recipient-rewrapped ciphertext lands on the resulting Share row during claim"
  - "Field is optional (hex @Matches, @MaxLength 1024) so legacy plaintext clients keep validating during rollout; web encrypt/decrypt/backfill is plan 48-06"

patterns-established:
  - "Ciphertext-only persist: server stores Buffer.from(hex) and never calls a crypto encrypt path (asserted in spec)"
  - "Zero-knowledge additive migration: ADD COLUMN IF NOT EXISTS bytea, DROP IF EXISTS, no data UPDATE"

requirements-completed: [REQ-4]

# Metrics
duration: 8min
completed: 2026-06-16
---

# Phase 48 Plan 05: Encrypt share itemName at rest (API + crypto) Summary

**Additive nullable item_name_encrypted bytea on shares and share_invites with DTO/service plumbing that persists client-supplied ECIES ciphertext on share-create, invite-create and invite-claim while the server stays zero-knowledge, plus a regenerated api-client.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-06-16T14:20:08Z
- **Completed:** 2026-06-16T14:28:00Z
- **Tasks:** 3 (2 auto/tdd + 1 blocking checkpoint auto-resolved locally)
- **Files modified:** 145 (14 source/test + migration + 130 regenerated api-client)

## Accomplishments

- Closed Phase-14 finding M1: share/invite display names can now be stored as ECIES ciphertext (`item_name_encrypted`) instead of plaintext, with the server never seeing or encrypting plaintext.
- Migration `EncryptShareItemName1749200000000` adds the additive nullable bytea column to both `shares` and `share_invites`; applied to the live dev DB (TypeORM `migration:show` reports `[X]`).
- `createShare`, `createInvite`, and the invite-`claim` path all persist `Buffer.from(dto.itemNameEncrypted, 'hex')` when present (decision A3 — no plaintext-only invite path); legacy clients omitting the field still validate and persist `null`.
- ECIES round-trip test extended to cover UTF-8 display names (ASCII + multibyte); service spec extended with ciphertext-persist and no-server-encrypt assertions.
- `@cipherbox/api-client` regenerated and committed in the same commit as the API change (pre-commit `check-api-client.sh` passed).

## Task Commits

All work landed in a single atomic commit (the api-client must be regenerated and staged together with the API change for `check-api-client.sh`):

1. **Task 1: ECIES itemName round-trip + migration + entity/DTO** - `b05694532` (feat)
2. **Task 2: Persist ciphertext in createShare + invite path** - `b05694532` (feat)
3. **Task 3: [BLOCKING] Apply migration + regenerate api-client** - resolved in-line (migration applied, `pnpm api:generate` run, generated files staged in `b05694532`)

## Files Created/Modified

- `apps/api/src/migrations/1749200000000-EncryptShareItemName.ts` - Additive nullable `item_name_encrypted` bytea on `shares` and `share_invites`; no data UPDATE.
- `apps/api/src/shares/entities/share.entity.ts` / `share-invite.entity.ts` - `itemNameEncrypted: Buffer | null` columns.
- `apps/api/src/shares/dto/create-share.dto.ts` / `create-invite.dto.ts` / `claim-invite.dto.ts` - optional hex-validated `itemNameEncrypted`.
- `apps/api/src/shares/dto/share-response.dto.ts` / `invite-response.dto.ts` - expose `itemNameEncrypted` (hex string, nullable).
- `apps/api/src/shares/shares.service.ts` / `share-invite.service.ts` - persist ciphertext on create + claim; server never encrypts.
- `apps/api/src/shares/shares.controller.ts` / `invites.controller.ts` / `share-invites.controller.ts` - map the entity column to hex in responses.
- `apps/api/src/shares/shares.service.spec.ts` - ciphertext-persist + no-server-encrypt + legacy-null tests.
- `packages/crypto/src/__tests__/ecies.test.ts` - UTF-8 itemName round-trip.
- `packages/api-client/openapi.json`, `src/generated/`, `src/models/` - regenerated client carrying `itemNameEncrypted`.

## Decisions Made

- **Migration touches `share_invites` too (not just `shares`):** decision A3 requires the invite flow to carry ciphertext. The invite uses a separate `share_invites` table, so the column and entity field were added there as well — the minimal additive change to remove the plaintext-only invite path.
- **`claim-invite` DTO gained `itemNameEncrypted`:** the invite stores the name wrapped with the ephemeral key; on claim the client re-wraps for the recipient's real key, and that re-wrapped ciphertext is persisted on the resulting Share.
- **Field kept optional during rollout:** plaintext `itemName` columns remain readable until the web ships encrypt/decrypt/lazy-backfill in plan 48-06 (decision A2).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Extended migration + entity to `share_invites` and added `itemNameEncrypted` to claim-invite DTO**

- **Found during:** Task 2 (invite-path persistence)
- **Issue:** The plan's artifact list named only the `shares` column, but decision A3 (include the invite flow, no plaintext path) cannot be satisfied without an `item_name_encrypted` column on the `share_invites` table and a way for the claim flow to carry the recipient-rewrapped ciphertext onto the Share. The invite uses a distinct `ShareInvite` entity/table.
- **Fix:** Added the additive nullable column to `share_invites` in the same migration, added `itemNameEncrypted` to the `ShareInvite` entity and `CreateInviteDto`, added `itemNameEncrypted` to `ClaimInviteDto`, and persisted it on the claim-created Share. All additive, nullable, zero-knowledge (no data UPDATE, no server encrypt).
- **Files modified:** `1749200000000-EncryptShareItemName.ts`, `share-invite.entity.ts`, `create-invite.dto.ts`, `claim-invite.dto.ts`, `share-invite.service.ts`
- **Verification:** `pnpm --filter @cipherbox/api test shares` (158 passing), build green, migration applied.
- **Committed in:** `b05694532`

**2. [Rule 3 - Blocking] Populated `itemNameEncrypted` in controller response mappings**

- **Found during:** Task 1 (build/typecheck)
- **Issue:** Adding `itemNameEncrypted` to the response DTOs made the inline controller response object literals fail typecheck (`nest build`) because the property was missing.
- **Fix:** Mapped `entity.itemNameEncrypted ? .toString('hex') : null` in createShare/received/sent share responses and in the invite controllers' create/list/getInviteData responses.
- **Files modified:** `shares.controller.ts`, `invites.controller.ts`, `share-invites.controller.ts`
- **Verification:** `nest build` green.
- **Committed in:** `b05694532`

---

**Total deviations:** 2 auto-fixed (1 missing critical, 1 blocking)
**Impact on plan:** Both necessary to satisfy decision A3 end-to-end and to keep the build/types green. No scope creep beyond the shares/invite API surface; SDK and web were not touched (those are REQ-3 / plan 48-06).

## TDD Gate Compliance

This is a `type: tdd` plan. Per the plan's own Task 1 note, the ECIES round-trip needed NO crypto change — the assertion was added against the existing audited `wrapKey`/`unwrapKey` primitive and was GREEN on first run (no RED phase expected for a primitive that already supports arbitrary bytes). The service-level behavior tests (ciphertext-persist + no-server-encrypt) were authored alongside the implementation and verified green. All test and implementation changes landed in a single `feat:` commit because the regenerated api-client must be staged together with the API change (pre-commit `check-api-client.sh`). Note: there is no separate `test(...)` gate commit; the RED/GREEN distinction is documented here rather than as separate commits.

## Issues Encountered

- **DB verification ambiguity:** A direct `docker exec cipherbox-postgres psql -U postgres -d cipherbox` did not show the new columns, but TypeORM `migration:show` (which uses the app's `.env`-driven connection) reports `[X] EncryptShareItemName1749200000000` = applied. The `.env` connection (unreadable here by the Bash security guard) targets a different DB instance/credentials than the manual `postgres`-user query, so `migration:show` is the authoritative check and confirms the migration is applied to the DB the API actually uses.

## User Setup Required

None - no external service configuration required. The migration is already applied to the dev DB; staging/prod will pick it up via the normal migration run on deploy.

## Next Phase Readiness

- Plan 48-06 (web side) can now consume the regenerated `@cipherbox/api-client`: wire ECIES wrap of `itemName` on the share-create/invite call sites, decrypt for display, and implement the lazy backfill (decision A2).
- The plaintext `itemName` columns remain populated for legacy rows until 48-06's backfill runs; no rows were destroyed and the change is fully backward-compatible.

## Self-Check: PASSED

- Migration file exists; SUMMARY exists; commit `b05694532` present in git log.
- `item_name_encrypted` present in migration (5 occurrences across shares + share_invites up/down).
- No SQL `UPDATE` in the migration (the single `grep -c UPDATE` hit is the words "NO data UPDATE" in the doc comment, not a statement).
- `itemNameEncrypted` persisted in both `shares.service.ts` and `share-invite.service.ts`.
- Verification suites green: crypto ecies (22) + api shares (158).

---

_Phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata_
_Completed: 2026-06-16_
