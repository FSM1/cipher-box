---
phase: 57-api-cid-and-provider-hardening-and-module-dedup
plan: 01
subsystem: api
tags: [cid-validation, ipfs, class-validator, nestjs, url-encoding, openapi]

requires:
  - phase: 50-api-hardening
    provides: UnpinDto with CID_REGEX and MaxLength(255) as the reference pattern
provides:
  - Shared CID_REGEX constant in cid.constants.ts (single source of truth for CIDv0+CIDv1 regex)
  - RegisterCidDto aligned with UnpinDto (exact CIDv0 branch, MaxLength 255)
  - LocalProvider pin/rm and cat URLs percent-encode the CID via URLSearchParams
  - openapi.json RegisterCidDto.cid carries maxLength:255; regenerated api-client built and staged
affects:
  - 57-02 (module-dedup tasks that touch ipfs.module / vault.module / pending-unpin.module)

tech-stack:
  added: []
  patterns:
    - Extract shared regex constants to a dedicated constants file imported by multiple DTOs
    - URLSearchParams for constructing Kubo query strings (percent-encoding defense-in-depth)

key-files:
  created:
    - apps/api/src/ipfs/dto/cid.constants.ts
    - apps/api/src/ipfs/dto/register-cid.dto.spec.ts
  modified:
    - apps/api/src/ipfs/dto/register-cid.dto.ts
    - apps/api/src/ipfs/dto/unpin.dto.ts
    - apps/api/src/ipfs/providers/local.provider.ts
    - apps/api/src/ipfs/providers/local.provider.spec.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated/ (all files)
    - packages/api-client/src/models/ (all files)

key-decisions:
  - 'Keep regex approach (not multiformats/@IsCid) per D-03 — avoids a new runtime dependency'
  - 'CIDv0 branch tightened to exact {44} chars; CIDv1 b[a-z2-7]{58,} branch kept open-ended (capped by @MaxLength)'
  - 'URLSearchParams chosen over manual encodeURIComponent for Kubo query strings — idiomatic and covers all reserved chars'
  - 'api:generate required building @cipherbox/crypto first (dist was missing in worktree); deviation documented'

patterns-established:
  - 'CID regex lives in cid.constants.ts; DTOs import it — never declare inline'
  - 'Kubo URL query strings always use URLSearchParams; never raw template interpolation'

requirements-completed: [HARD-08]

duration: 35min
completed: 2026-06-22
---

# Phase 57 Plan 01: API CID and Provider Hardening Summary

**Shared CID_REGEX constant extracted to cid.constants.ts; RegisterCidDto tightened to reject CIDv0 overflow and oversized strings; LocalProvider Kubo URLs percent-encode CID via URLSearchParams; openapi.json gains maxLength:255 and regenerated api-client is committed.**

## Performance

- **Duration:** 35 min
- **Started:** 2026-06-22T00:00:00Z
- **Completed:** 2026-06-22T00:35:00Z
- **Tasks:** 4 (with TDD RED+GREEN commits for tasks 1-3)
- **Files modified:** 9 source files + 131 regenerated api-client files

## Accomplishments

- Single shared `CID_REGEX` in `cid.constants.ts` — both `unpin.dto.ts` and `register-cid.dto.ts` import it; no inline regex remains in either DTO
- `RegisterCidDto.cid` now rejects CIDv0 strings with extra chars (the `{44,}` overflow) and any string over 255 chars — matching `UnpinDto` exactly
- `LocalProvider.unpinFile` and `getFile` build Kubo query strings via `URLSearchParams` — percent-encoding is now guaranteed regardless of what upstream writers stored in the DB
- `openapi.json` carries `"maxLength": 255` on `RegisterCidDto.cid`; regenerated `@cipherbox/api-client` is built and committed; `check-api-client.sh` passes

## Task Commits

Each task was committed atomically:

1. **Task 1 RED: shared CID_REGEX scaffold + failing spec** - `cb9b8a30a` (test)
2. **Task 2 GREEN: align RegisterCidDto + share CID_REGEX** - `509c80172` (feat)
3. **Task 3 RED: failing LocalProvider encoding tests** - `7bf20cc06` (test)
4. **Task 3 GREEN: URLSearchParams in pin/rm + cat** - `3aace0e9a` (feat)
5. **Task 4: regenerate api-client** - `88e35a62e` (chore)

## Files Created/Modified

- `apps/api/src/ipfs/dto/cid.constants.ts` - New file; exports `CID_REGEX` (verbatim from unpin.dto.ts) with IN-02 comment
- `apps/api/src/ipfs/dto/register-cid.dto.spec.ts` - New Jest spec; 4 tests covering CIDv1 accept, CIDv0 overflow reject, 255+ char reject, canonical CIDv0 accept
- `apps/api/src/ipfs/dto/register-cid.dto.ts` - Added `MaxLength` import, `CID_REGEX` import from cid.constants, `@MaxLength(255)`, fixed `{44,}` to `{44}`, updated `@ApiProperty` with pattern + maxLength
- `apps/api/src/ipfs/dto/unpin.dto.ts` - Removed inline `const CID_REGEX` declaration; added `import { CID_REGEX } from './cid.constants'`
- `apps/api/src/ipfs/providers/local.provider.ts` - `unpinFile` and `getFile` now use `new URLSearchParams({ arg: cid })` for Kubo query strings; pin/add unchanged
- `apps/api/src/ipfs/providers/local.provider.spec.ts` - Added 2 encoding tests (one for pin/rm, one for cat) that assert reserved chars are percent-encoded

## Decisions Made

- Kept the regex approach (not `multiformats/@IsCid`) per D-03 — no new runtime dependency needed
- CIDv0 branch tightened to exact `{44}` chars; CIDv1 `b[a-z2-7]{58,}` branch retained open-ended (bounded by `@MaxLength(255)`)
- `URLSearchParams` over manual `encodeURIComponent` — idiomatic, covers all RFC 3986 reserved chars, produces identical output for clean CIDs (no regressions in existing toBe assertions)
- `api:generate` required building `@cipherbox/crypto` first because the worktree was missing the dist; built it as a one-time prerequisite

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Built @cipherbox/crypto before api:generate**

- **Found during:** Task 4 (api:generate)
- **Issue:** `pnpm api:generate` failed because `@cipherbox/crypto` dist was absent in the worktree; the generate-openapi.ts script imports `IpnsService` which transitively requires it at runtime
- **Fix:** Ran `pnpm --filter @cipherbox/crypto build` to produce the dist; then re-ran `pnpm api:generate` (exit 0)
- **Files modified:** packages/crypto/dist/ (build artifact, not committed)
- **Verification:** `pnpm api:generate` completed with exit 0; maxLength:255 confirmed in openapi.json
- **Committed in:** 88e35a62e (Task 4 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking — missing build artifact)
**Impact on plan:** One-line prerequisite build; no scope creep, no plan changes required.

## Issues Encountered

- Pre-existing `tsc --noEmit` errors in `apps/api` exist for unrelated modules (`@cipherbox/crypto` missing type declarations, `incomingParsed` null checks in ipns.service.ts, missing properties in share entities). These are out-of-scope pre-existing issues; the ipfs/dto changes are clean.

## TDD Gate Compliance

| Gate     | Commit      | Status |
| -------- | ----------- | ------ |
| RED (Task 1)  | `cb9b8a30a` (test) | Pass |
| GREEN (Task 2) | `509c80172` (feat) | Pass |
| RED (Task 3)  | `7bf20cc06` (test) | Pass |
| GREEN (Task 3) | `3aace0e9a` (feat) | Pass |

## Known Stubs

None - all wired and functional.

## Threat Surface Scan

No new network endpoints, auth paths, or trust boundaries introduced. Changes harden an existing path (CID input → Kubo URL). No new threat flags.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 57-01 deliverables are complete; the module-dedup tasks (57-02 if planned) can import `IpfsProviderModule` from the providers barrel once that module is created
- All 899 apps/api tests pass

---

Phase: 57-api-cid-and-provider-hardening-and-module-dedup
Completed: 2026-06-22
