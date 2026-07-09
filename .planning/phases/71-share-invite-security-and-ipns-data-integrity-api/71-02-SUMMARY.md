---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 02
subsystem: api
tags: [typescript, sdk-core, sdk, web, sdk-e2e, share-plane-rename, vitest]

# Dependency graph
requires:
  - phase: 71-01
    provides: "Regenerated @cipherbox/api-client exposing encryptedReadKey/encryptedWriteKey/shareRootIpnsName"
provides:
  - "sdk-core/sdk/web/sdk-e2e share-domain code renamed to encryptedReadKey/encryptedWriteKey/shareRootIpnsName"
  - "Renamed share methods: resolveShareEncryptedWriteKey/clearEncryptedWriteKey/dispatchEncryptedWriteKeyStale/claimerEncryptedReadKey"
  - "Surgical rootIpnsName->shareRootIpnsName rename confined to share/invite/grant-domain call sites"
affects: [71-03, 71-04, 71-05, 71-06, 71-07, 71-08, 71-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Compiler-guided mechanical rename driven by pnpm typecheck red lines"
    - "Surgical field rename confined to share/invite/grant-domain call sites, vault/folder-tree fields left untouched"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/share/grant.ts
    - packages/sdk-core/src/share/navigate.ts
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/rotation/scope.ts
    - packages/sdk-core/src/__tests__/share/grant.test.ts
    - packages/sdk-core/src/__tests__/share/navigate.test.ts
    - packages/sdk-core/src/__tests__/rotation/scope.test.ts
    - packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts
    - packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/types.ts
    - packages/sdk/src/share/owner-reconcile.ts
    - packages/sdk/src/__tests__/client-rotation.test.ts
    - packages/sdk/src/__tests__/download-shared-file.test.ts
    - packages/sdk/src/__tests__/resolve-share-root.test.ts
    - packages/sdk/src/__tests__/client-write-descriptor.test.ts
    - packages/sdk/src/__tests__/owner-reconcile.test.ts
    - packages/sdk/src/__tests__/update-shared-single-file.test.ts
    - apps/web/src/components/file-browser/ShareDialog.tsx
    - apps/web/src/hooks/useSharedNavigationActions.ts
    - apps/web/src/hooks/useMutationFailureUx.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/lib/crypto/key-wrapping.ts
    - apps/web/src/services/invite.service.ts
    - apps/web/src/services/owner-reconcile.service.ts
    - apps/web/src/services/rotation-driver.service.ts
    - apps/web/src/services/share.service.ts
    - apps/web/src/stores/share.store.ts
    - tests/sdk-e2e/src/suites/share-operations.test.ts
    - tests/sdk-e2e/src/suites/invite-link.test.ts
    - tests/sdk-e2e/src/suites/read-chain-navigation.test.ts
    - tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts
    - tests/sdk-e2e/src/suites/write-chain-rotation.test.ts

key-decisions:
  - "Applied D-10 field/method rename map verbatim: readDescriptorRef->encryptedReadKey, writeDescriptorRef->encryptedWriteKey, resolveShareWriteDescriptor->resolveShareEncryptedWriteKey, clearWriteDescriptor->clearEncryptedWriteKey, dispatchWriteDescriptorStale->dispatchEncryptedWriteKeyStale, claimerReadDescriptorRef->claimerEncryptedReadKey; no dedicated *DescriptorRef TS type aliases existed (all were field/param names), so the 'type rename' bullet collapsed into the field renames"
  - "Extended the surgical rootIpnsName->shareRootIpnsName rename beyond the plan's explicit example list to every internal share/grant-domain function signature the compiler could not catch on its own: issueReadGrant/claimInviteReadKey/claimInvite (ReadGrantPayload), navigateReadChain, client.downloadSharedFile/resolveShareRoot, LocalGrantRecord (types.ts) and rotation/scope.ts's CoverageParams.localGrantRecord -- these carry the grant/share root ipnsName and are structurally identical to the plan's named ShareDialog/invite.service/useSharedNavigationActions targets, but are internal TS signatures never checked against an api-client type so pnpm typecheck could not flag them"
  - "rotation/engine.ts's RotationParams.rootNodeIpnsName / verifySubtreeClean's rootIpnsName / rotateWriteFromNode's rootIpnsName were left UNCHANGED -- these name the root of the ROTATED subtree (any scope-exit target, not necessarily a share root); grant re-minting is only conditionally invoked via innerGrants/grantCallbacks, so this is rotation-domain, not share-domain, and renaming it would violate the surgical boundary"
  - "enumerateMoveDescendants's rootIpnsName (client.ts) and CipherBoxClientConfig.rootIpnsName (types.ts, the vault config) were left unchanged -- confirmed vault/general-move domain, not share domain"
  - "Fixed 3 raw-HTTP sdk-e2e test files (share-operations.test.ts, invite-link.test.ts) that POST/assert against the live API's CreateShareDto/CreateInviteDto/InviteDataResponseDto wire contract -- these are NOT flagged by pnpm typecheck (untyped JSON.stringify bodies) but would have sent the stale rootIpnsName/encryptedKey field names to the already-renamed 71-01 API, silently breaking at runtime; fixed as part of the same compiler-adjacent sweep"
  - "Did not rename the generic per-item ShareKeyEntry.encryptedKey field (client.ts createShareKey, shared-write.ts, context.ts, key-cache.ts, useSharedWriteOps.ts, useSharedNavigationActions.ts's getShareKeys) -- this is a structurally distinct concept (per-item key wrapping in the legacy shared-write fan-out), not the invite/grant top-level encryptedReadKey the D-10 map targets"
  - "Left client-write-descriptor.test.ts's filename unchanged (4 other test files reference it by name in doc comments) -- the plan's acceptance criterion is a content grep, not a filename grep; renaming would touch ~5 more files for a cosmetic-only gain"

patterns-established:
  - "Descriptor-ref terminology purged from apps/web + packages/sdk-core/sdk + tests/sdk-e2e comments/identifiers in favor of encrypted-key wording; residual 'content descriptor' (file-version, unrelated to share domain) documented and left untouched"

requirements-completed: [D-10]

coverage:
  - id: D1
    description: "sdk-core/sdk/web/sdk-e2e share-domain fields renamed to encryptedReadKey/encryptedWriteKey/shareRootIpnsName; share methods renamed (resolveShareEncryptedWriteKey/clearEncryptedWriteKey/dispatchEncryptedWriteKeyStale/claimerEncryptedReadKey)"
    requirement: D-10
    verification:
      - kind: unit
        ref: "pnpm typecheck (full monorepo: crypto/core/api-client/sdk-core/sdk build + web tsc -b + scripts) -- exit 0"
        status: pass
      - kind: other
        ref: "grep -rn DescriptorRef packages/sdk-core/src packages/sdk/src apps/web/src tests/sdk-e2e/src (zero hits)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Surgical rootIpnsName->shareRootIpnsName rename held: vault/folder-tree rootIpnsName intact"
    requirement: D-10
    verification:
      - kind: other
        ref: "grep -n rootIpnsName apps/web/src/stores/vault.store.ts apps/web/src/hooks/useFolderNavigation.ts (returns hits, unchanged)"
        status: pass
    human_judgment: false
  - id: D3
    description: "sdk-core and sdk unit suites pass under the renamed share vocabulary"
    requirement: D-10
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test (31 files, 363 passed, 12 skipped pre-existing)"
        status: pass
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (40 files, 362 passed, 49 skipped pre-existing)"
        status: pass
    human_judgment: false
  - id: D4
    description: "'descriptor' term purged from share-domain code; only genuinely unrelated file-version 'content descriptor' residuals remain (documented)"
    requirement: D-10
    verification:
      - kind: other
        ref: "grep -rin descriptor packages/sdk-core/src packages/sdk/src apps/web/src tests/sdk-e2e/src (residual hits are file/index.ts, client.ts:4017, version-transforms.ts, read-chain-navigation.test.ts content-descriptor comments, and 4 cross-references to the client-write-descriptor.test.ts filename)"
        status: pass
    human_judgment: false

duration: 95min
completed: 2026-07-09
status: complete
---

# Phase 71 Plan 02: Share-Plane Encrypted-Key Rename (TS Consumers) Summary

**Compiler-guided rename of sdk-core/sdk/web/sdk-e2e share-domain TS consumers to the new encryptedReadKey/encryptedWriteKey/shareRootIpnsName vocabulary the 71-01 api-client regeneration exposed, including three raw-HTTP sdk-e2e test files whose live-API JSON bodies would otherwise have silently broken against the renamed wire contract.**

## Performance

- **Duration:** 95 min
- **Started:** 2026-07-09T20:23:00Z
- **Completed:** 2026-07-09T21:58:34Z
- **Tasks:** 2
- **Files modified:** 33

## Accomplishments
- Renamed `readDescriptorRef`/`writeDescriptorRef` -> `encryptedReadKey`/`encryptedWriteKey` and the invite `encryptedKey` -> `encryptedReadKey` across `packages/sdk-core/src`, `packages/sdk/src`, `apps/web/src`, `tests/sdk-e2e/src`
- Renamed methods: `resolveShareWriteDescriptor` -> `resolveShareEncryptedWriteKey`, `clearWriteDescriptor` -> `clearEncryptedWriteKey`, `dispatchWriteDescriptorStale` -> `dispatchEncryptedWriteKeyStale`, `claimerReadDescriptorRef` -> `claimerEncryptedReadKey`
- Extended the surgical `rootIpnsName` -> `shareRootIpnsName` rename to every internal share/grant-domain function signature (`issueReadGrant`, `claimInvite`, `navigateReadChain`, `client.downloadSharedFile`/`resolveShareRoot`, `LocalGrantRecord`, `hasCoveringGrant`'s `localGrantRecord`, `owner-reconcile.service.ts`) beyond the plan's example call sites, since these are internal TS types the compiler cannot cross-check against the api-client
- Fixed 3 raw-HTTP `tests/sdk-e2e` suites (`share-operations.test.ts`, `invite-link.test.ts`) whose `JSON.stringify` request bodies and response-shape assertions still used the pre-71-01 wire field names -- these are invisible to `pnpm typecheck` but would break at runtime against the live (already-renamed) API
- Held the surgical boundary: `vault.store.ts`/`useFolderNavigation.ts` `rootIpnsName`, `client.ts`'s `enumerateMoveDescendants`/vault `config.rootIpnsName`, and `rotation/engine.ts`'s rotated-subtree `rootIpnsName`/`rootNodeIpnsName` (rotation-domain, not share-domain) all left unchanged
- Purged "descriptor" terminology from share-domain comments/identifiers/test fixtures; residual "content descriptor" (file-versioning, unrelated) and `client-write-descriptor.test.ts` filename cross-references documented as intentionally out of scope
- Full monorepo `pnpm typecheck` green; `pnpm --filter @cipherbox/sdk-core test` (363 passed) and `pnpm --filter @cipherbox/sdk test` (362 passed) both green

## Task Commits

Each task was committed atomically:

1. **Task 1: Rename descriptor fields + share method/type names across sdk-core/sdk/web/sdk-e2e** - `f06e56fea` (feat)
2. **Task 2: Verify sdk-core / sdk unit suites under the new names** - folded into Task 1's commit (see Deviations)

**Plan metadata:** commit pending (this SUMMARY)

## Files Created/Modified

**sdk-core (share/grant/rotation crypto primitives):**
- `packages/sdk-core/src/share/grant.ts` - `ReadGrantPayload`/`issueReadGrant`/`claimInviteReadKey`/`claimInvite` renamed to `encryptedReadKey`/`shareRootIpnsName`; descriptor prose purged
- `packages/sdk-core/src/share/navigate.ts` - `navigateReadChain`'s `rootIpnsName` param -> `shareRootIpnsName`
- `packages/sdk-core/src/rotation/engine.ts` - `reMintGrantsRootedAt`'s `readDescriptorRef`/`writeDescriptorRef` local vars renamed; descriptor prose purged (rotation-domain `rootIpnsName` params left unchanged)
- `packages/sdk-core/src/rotation/scope.ts` - `CoverageParams.localGrantRecord.rootIpnsName` -> `shareRootIpnsName`
- `packages/sdk-core/src/__tests__/share/grant.test.ts`, `navigate.test.ts`, `rotation/scope.test.ts`, `rotation/grant-remint.test.ts`, `rotation/write-revocation.test.ts` - fixture/assertion renames

**sdk (client facade):**
- `packages/sdk/src/client.ts` - `downloadSharedFile`/`resolveShareRoot` params renamed to `shareRootIpnsName`; descriptor prose purged
- `packages/sdk/src/types.ts` - `LocalGrantRecord.rootIpnsName` -> `shareRootIpnsName`
- `packages/sdk/src/share/owner-reconcile.ts` - descriptor prose purged
- `packages/sdk/src/__tests__/client-rotation.test.ts`, `download-shared-file.test.ts`, `resolve-share-root.test.ts`, `client-write-descriptor.test.ts`, `owner-reconcile.test.ts`, `update-shared-single-file.test.ts` - fixture/assertion renames

**web (consumer wiring):**
- `apps/web/src/components/file-browser/ShareDialog.tsx` - `SentShareResponseDto`/`CreateShareDto` `rootIpnsName` -> `shareRootIpnsName`
- `apps/web/src/hooks/useSharedNavigationActions.ts` - `resolveShareRoot`/`downloadSharedFile` call sites renamed
- `apps/web/src/hooks/useMutationFailureUx.ts`, `useAuth.ts` - descriptor prose purged
- `apps/web/src/lib/crypto/key-wrapping.ts` - descriptor prose purged
- `apps/web/src/services/invite.service.ts` - `CreateInviteDto`/`InviteDataResponseDto`/`InviteResponseDto`/`ShareInvitesControllerListInvitesParams` field renames
- `apps/web/src/services/owner-reconcile.service.ts` - `DecodedSentGrant.rootIpnsName` -> `shareRootIpnsName` throughout
- `apps/web/src/services/rotation-driver.service.ts` - `getLocalGrantRecord` return value field rename
- `apps/web/src/services/share.service.ts` - `ReceivedShareResponseDto`/`SentShareResponseDto` field renames
- `apps/web/src/stores/share.store.ts` - descriptor prose purged

**sdk-e2e (raw API test suites):**
- `tests/sdk-e2e/src/suites/share-operations.test.ts`, `invite-link.test.ts` - raw `testFetch` JSON bodies + response assertions renamed to the wire contract
- `tests/sdk-e2e/src/suites/read-chain-navigation.test.ts`, `rotation-crash-safety.test.ts` - `issueReadGrant`/`navigateReadChain` call-site `rootIpnsName` -> `shareRootIpnsName`
- `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` - descriptor prose purged

## Decisions Made
- Extended the plan's example call-site list to cover every internal share/grant TS signature carrying a share root ipnsName, since only the api-client-typed boundary is compiler-checked; the internal sdk-core/sdk signatures are structurally identical share-domain concepts and needed the same rename to satisfy the plan's `must_haves.truths` (full share-domain code uses the new vocabulary)
- Left `rotation/engine.ts`'s rotated-subtree `rootIpnsName`/`rootNodeIpnsName` unchanged -- confirmed via code reading this names the general scope-exit rotation target (any node, share or not), not specifically a share/grant root; grant re-minting there is conditional (`innerGrants`/`grantCallbacks`), so this is rotation-domain
- Did not rename the generic per-item `ShareKeyEntry.encryptedKey` (the legacy shared-write per-item key fan-out used by `client.ts`'s `createShareKey`, `shared-write.ts`, `context.ts`, `key-cache.ts`, `useSharedWriteOps.ts`) -- structurally distinct from the invite/grant top-level `encryptedReadKey` the D-10 map targets
- Left the `client-write-descriptor.test.ts` filename unchanged despite containing "descriptor" -- the plan's acceptance criterion is a content grep (`grep -rin descriptor <dirs>`), which does not match filenames; renaming would ripple into 4 other files' doc-comment cross-references for a purely cosmetic gain

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed 3 raw-HTTP sdk-e2e wire-contract mismatches**
- **Found during:** Task 1 verification sweep (post-typecheck, scanning `tests/sdk-e2e` for residual `rootIpnsName`/`descriptor`)
- **Issue:** `share-operations.test.ts` and `invite-link.test.ts` POST/assert directly against the live API via `testFetch` with hand-built `JSON.stringify` bodies (`CreateShareDto`, `CreateInviteDto`, `InviteDataResponseDto`). These bypass the api-client's generated types entirely, so `pnpm typecheck` cannot see the mismatch -- but the 71-01-renamed API would reject/silently drop the stale `rootIpnsName`/`encryptedKey` field names, breaking these tests at runtime (NestJS DTO whitelist strips unknown properties, or the assertion reads `undefined`).
- **Fix:** Renamed the request-body keys and response-assertion property accesses to `shareRootIpnsName`/`encryptedReadKey` to match the regenerated DTO wire contract; left `alice.rootIpnsName` (the test-harness vault-fixture field, a genuinely different value) untouched.
- **Files modified:** `tests/sdk-e2e/src/suites/share-operations.test.ts`, `tests/sdk-e2e/src/suites/invite-link.test.ts`
- **Verification:** `npx tsc -p tests/sdk-e2e/tsconfig.json --noEmit` shows zero new errors (only pre-existing unrelated `bin-operations.test.ts` errors remain); these suites require a live API/Postgres stack to actually execute and were not run end-to-end in this worktree (no docker stack available), but the wire-contract field alignment is a straightforward compiler-adjacent correctness fix matching 71-01's already-shipped DTO rename.
- **Committed in:** `f06e56fea` (Task 1 commit)

**2. [Rule 3 - Blocking] Rebuilt sdk-core/sdk dist before re-checking web typecheck**
- **Found during:** Task 1, after renaming `resolveShareWriteDescriptor` -> `resolveShareEncryptedWriteKey` in `client.ts`
- **Issue:** `pnpm --filter @cipherbox/web exec tsc -b` initially still reported `Property 'resolveShareEncryptedWriteKey' does not exist on type 'CipherBoxClient'` because the fresh worktree's `packages/sdk/dist` was stale relative to the source edit (cross-package dist-staleness, a known project gotcha).
- **Fix:** Ran `pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build` before re-running the web typecheck.
- **Files modified:** none (build artifacts only, gitignored)
- **Verification:** Subsequent `pnpm --filter @cipherbox/web exec tsc -b` passed with zero errors.
- **Committed in:** n/a (no source change; documented for reproducibility)

**3. [Rule 1 - Bug] Fixed a broken unquoted apostrophe introduced by my own prose edit**
- **Found during:** Task 2 (running `pnpm --filter @cipherbox/sdk test`)
- **Issue:** While purging "descriptor" from `update-shared-single-file.test.ts`'s test name, the replacement text `it('resolves the file keys from the grant's encrypted keys...` broke the single-quoted string literal, causing an esbuild transform failure (`Expected ")" but found "s"`) and a failed test file.
- **Fix:** Switched the string literal to double quotes.
- **Files modified:** `packages/sdk/src/__tests__/update-shared-single-file.test.ts`
- **Verification:** `pnpm --filter @cipherbox/sdk test` -- all 40 files pass (0 failed).
- **Committed in:** `f06e56fea` (Task 1 commit, since Task 2 produced no separate diff)

---

**Total deviations:** 3 auto-fixed (1 bug/wire-contract, 1 blocking/dist-staleness, 1 bug/self-introduced typo)
**Impact on plan:** All three were required to reach the plan's stated `pnpm typecheck` green + unit-suite-passing acceptance criteria. No scope creep beyond the plan's `files_modified` boundary (`apps/api` and Rust crates untouched, confirmed via `git status`).

## Issues Encountered

**Task 2 had no separate diff to commit.** The plan structures this as two tasks (Task 1: rename; Task 2: run+fix sdk-core/sdk unit suites), but the compiler-guided workflow interleaved them -- fixing a `pnpm typecheck` red line in a `*.test.ts` fixture IS the Task-2 fixture-fix work, and it happened inline while driving Task 1 to green. Task 2 was executed as a pure verification step (`pnpm --filter @cipherbox/sdk-core test` / `pnpm --filter @cipherbox/sdk test`, both green) with zero additional file changes, so no second commit was created. This is documented here rather than force-creating an empty commit.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The share plane's TS surface (sdk-core, sdk, web, sdk-e2e non-live-API code) now uses `encryptedReadKey`/`encryptedWriteKey`/`shareRootIpnsName` end-to-end, matching the 71-01 api-client contract.
- `pnpm typecheck` (full monorepo) is green; `pnpm --filter @cipherbox/sdk-core test` and `pnpm --filter @cipherbox/sdk test` both pass.
- `tests/sdk-e2e`'s share/invite suites (`share-operations.test.ts`, `invite-link.test.ts`, `read-chain-navigation.test.ts`, `rotation-crash-safety.test.ts`, `write-chain-rotation.test.ts`) were updated for the new wire contract and typecheck cleanly, but were NOT executed end-to-end against a live API/Postgres/Redis stack in this worktree (no docker stack available in the sandboxed environment) -- a live sdk-e2e run is recommended before merge to confirm runtime behavior, per the project's "SDK E2E is the only cross-package publish gate" convention.
- No blockers for downstream plans in this phase's wave; `apps/api` and Rust crates (other plans' scope) were not touched.

---
*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Completed: 2026-07-09*

## Self-Check: PASSED

- FOUND: packages/sdk-core/src/share/grant.ts
- FOUND: packages/sdk/src/client.ts
- FOUND: .planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-02-SUMMARY.md
- FOUND commit: f06e56fea (Task 1)
- FOUND commit: 3b9095b43 (docs: summary)
