---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 08
subsystem: sdk
tags: [typescript, refactor, aead, write-chain, zeroization]

# Dependency graph
requires:
  - phase: 72-07
    provides: moveInSharedFolder's legacy dead branch removed (clean baseline before consolidating the reachable branch's write-chain walk)
  - phase: 72-02
    provides: getWriteBodyParams fail-closed groundwork the write-chain walk sites already build on
provides:
  - Single walkChildWriteKey(mode) primitive replacing 7 divergent inline unsealChildWriteKey call sites in packages/sdk/src/client.ts
  - Single hasRealWriteKey predicate replacing ~6 inline writeKey-validity spellings
affects: [sdk-write-plane, sc7-and-later-write-chain-work]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "walkChildWriteKey(mode: 'require' | 'skip' | 'nullable') string-literal-union primitive for write-chain hop walks (never a TS enum, per project convention)"
    - "hasRealWriteKey(wk) single predicate for non-null/32-byte/non-zero writeKey checks"

key-files:
  created: []
  modified:
    - packages/sdk/src/client.ts

key-decisions:
  - "hasRealWriteKey and walkChildWriteKey defined as module-private (non-exported) functions in client.ts, not class methods -- matches the existing sharedFileBase64ToBytes/base64ToBytes module-function convention in the same file"
  - "walkChildWriteKey's mode controls ONLY the missing-WriteChildRef behavior; a cryptographic (AEAD) unseal failure is NEVER swallowed by any mode -- deviates from RESEARCH.md's literal table description for the 'nullable' mode (see Deviations)"
  - "Site 5 (updateSharedFile inline walk) left as a documented, NOT-folded exception -- confirmed its getFileIpnsKeyFn fallback is LIVE via apps/web/src/hooks/useSharedWriteOps.ts's resolveFileIpnsKey"
  - "'require'-mode call sites (3, 4, 6) add a defensive post-call null guard purely to satisfy TypeScript control-flow narrowing (walkChildWriteKey's return type is uniformly Uint8Array | null across all 3 modes) -- these guards are unreachable at runtime since 'require' mode always throws instead of returning null"

patterns-established:
  - "Write-chain hop-walk primitive: walkChildWriteKey(params) with an explicit mode string-literal param, matching each caller's original fail-open/fail-closed contract 1:1"
  - "D-09 zeroize idiom inside a shared primitive: null-before-return (ownership transfer) + fill-in-finally-on-throw-only, so callers become the terminal owner of the returned key exactly as before the extraction"

requirements-completed: [SC#6]

coverage:
  - id: D1
    description: "hasRealWriteKey single predicate replaces all inline writeKey-validity spellings (~6 sites + 2 local closures) in packages/sdk/src/client.ts"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (full 389-test suite, no behavior change)"
        status: pass
    human_judgment: false
  - id: D2
    description: "walkChildWriteKey(mode) primitive replaces 7 of the 8 divergent inline unsealChildWriteKey call sites (dfsFindFolder, moveItem, resolveFileWriteChainKeys, resolveShareEncryptedWriteKey, moveInSharedFolder, enumerateSharedSubtree, resolveSharedSubfolderWriteKey), each re-pointed with its RESEARCH-table-assigned mode, D-09 zeroization preserved"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk test (full 389-test suite, no behavior change; resolve-shared-subfolder-write-key.test.ts's 2 explicit throw-on-AEAD-failure cases specifically gate the fail-closed guarantee)"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 08: Write-Chain Hop-Walk & writeKey-Validity Consolidation Summary

**Single `walkChildWriteKey(mode: 'require' | 'skip' | 'nullable')` primitive and single `hasRealWriteKey` predicate replace 8 divergent inline write-chain-walk/validity spellings in `packages/sdk/src/client.ts`, preserving every site's exact fail-open/fail-closed behavior (verified by the full 389-test SDK suite staying green).**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-10T16:59:33Z (after 72-07 completion)
- **Completed:** 2026-07-10T17:13:00Z
- **Tasks:** 2
- **Files modified:** 1 (`packages/sdk/src/client.ts`)

## Accomplishments

- Extracted `hasRealWriteKey(wk)` — a single, module-level, pure-read predicate (`non-null && length===32 && not-all-zero`) replacing ~6 inline spellings of the same check plus 2 duplicated local closures (`enumerateSharedSubtree`, `resolveSharedSubfolderWriteKey`)
- Extracted `walkChildWriteKey(params)` — a single module-level primitive with an explicit `mode: 'require' | 'skip' | 'nullable'` string-literal union (never a TS enum, per project CLAUDE.md convention), encoding the missing-`WriteChildRef` fail-open/fail-closed contract for each of the 7 folded call sites
- Re-pointed all 7 in-scope call sites (`dfsFindFolder`, `moveItem`, `resolveFileWriteChainKeys`, `resolveShareEncryptedWriteKey`, `moveInSharedFolder`'s reachable branch, `enumerateSharedSubtree`, `resolveSharedSubfolderWriteKey`) at the primitive, each with the mode matching its RESEARCH-table row (`require`: 3, 4, 6; `skip`: 1, 2, 7; `nullable`: 8)
- Left site 5 (`updateSharedFile`'s inline walk) as a documented, deliberately-not-folded exception with an inline comment explaining why (fallback-to-legacy-key-lookup shape fits none of the 3 modes) and confirming its `getFileIpnsKeyFn` fallback is LIVE (not dead code) via `apps/web/src/hooks/useSharedWriteOps.ts`
- Preserved the D-09 null-before-return / fill-in-finally zeroization idiom inside the primitive; every re-pointed call site's own post-call zeroing behavior is unchanged
- Full `pnpm --filter @cipherbox/sdk test` suite (389 tests, 46 files) stays green after both tasks; `pnpm --filter @cipherbox/sdk run build` succeeds; `eslint`/`tsc --noEmit` clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract the single hasRealWriteKey predicate** - `b00849615` (refactor)
2. **Task 2: Extract walkChildWriteKey (3-mode) and re-point the write-chain-walk sites** - `5b053a98a` (refactor)

**Plan metadata:** (this commit)

## Files Created/Modified

- `packages/sdk/src/client.ts` — added `hasRealWriteKey` predicate and `walkChildWriteKey` primitive (module-private functions, near the top of the file after imports); re-pointed 7 call sites; removed 2 duplicated local `hasRealWriteKey` closures; added a documented-exception comment at site 5

## Decisions Made

- **`hasRealWriteKey`/`walkChildWriteKey` are module-private functions, not class methods** — matches the file's existing convention (`sharedFileBase64ToBytes`, `base64ToBytesForFile`-style helpers already live at module scope in this file).
- **`walkChildWriteKey`'s `mode` controls ONLY the missing-`WriteChildRef` lookup, never the AEAD-unseal-failure path** — see Deviations below for the full rationale; this was necessary to keep `resolveSharedSubfolderWriteKey`'s own regression tests (which explicitly assert a throw on a tampered `writeKeySealed`) passing.
- **Site 5 (`updateSharedFile`) intentionally NOT folded** — grepped `getFileIpnsKeyFn` callers; `apps/web/src/hooks/useSharedWriteOps.ts:173` wires a real `resolveFileIpnsKey` implementation (fetches `share_keys` via `fetchShareKeys` and ECIES-unwraps a `file-ipns` entry) — the fallback is live production code, not dead weight, so folding it into any of the 3 modes would silently drop functionality live callers depend on. This matches the plan's explicit instruction: "if live, leave site 5 as a documented exception."
- **`'require'`-mode call sites (3, 4, 6) carry a defensive post-call `if (!x) throw ...` guard** — purely to satisfy TypeScript's control-flow narrowing, since `walkChildWriteKey`'s return type (`Uint8Array | null`) is uniform across all 3 modes for a single, simpler function signature (rather than 3 differently-typed overloads). These guards are unreachable at runtime: `'require'` mode always throws instead of returning `null`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug avoidance] `walkChildWriteKey`'s `'nullable'` mode does NOT swallow AEAD unseal failures, despite RESEARCH.md's table literally describing site 8 as "validation returns null too"**

- **Found during:** Task 2 (designing the 3-mode primitive for `resolveSharedSubfolderWriteKey`, site 8)
- **Issue:** RESEARCH.md's "Write-Chain Hop Walk" table classifies site 8's `'nullable'` mode as "missing-ref-returns-null + validation-returns-null." A literal reading would mean `walkChildWriteKey` should catch `unsealChildWriteKey`'s own AEAD auth failure and return `null` for `'nullable'` mode. Inspecting the actual code at all 8 original sites showed **none of them** ever catch `unsealChildWriteKey`'s own throw — it always propagates uncaught in every site, including site 8. `resolveSharedSubfolderWriteKey`'s own docstring ("A tampered `writeKeySealed` or wrong parent writeKey throws (AEAD auth failure) rather than being swallowed") and its regression test `resolve-shared-subfolder-write-key.test.ts` ("throws on a tampered writeKeySealed (fail-closed AEAD, not swallowed)", "throws when the recovered writeKey does not unseal the child own write-body") both explicitly assert a **throw**, not a `null` return, for exactly this scenario. RESEARCH's "validation returns null" language actually refers to a SEPARATE, downstream `unsealNode`/`!childNode.writeBody` structural check the call site keeps for itself (per this task's own instruction to "preserve the validate-before-trust step where the original site had it") — not to the primitive's own unseal step.
- **Fix:** Implemented `walkChildWriteKey` so `mode` controls ONLY the missing-`WriteChildRef` lookup (all 3 modes: `'require'` throws, `'skip'`/`'nullable'` return `null`); an AEAD unseal failure is NEVER caught by the primitive in ANY mode — it always propagates. This makes `'skip'` and `'nullable'` behaviorally identical inside the primitive's own scope (both return `null` on missing ref, both propagate on unseal failure); the distinction between them is purely documentary (matching each site's RESEARCH-table classification and each mode's intended future semantics), not a runtime behavior difference today.
- **Why this was the correct call, not a plan violation:** Following RESEARCH's literal table description would have converted a security-critical AEAD tamper-detection throw into a silent `null` return for `resolveSharedSubfolderWriteKey` — a genuine fail-open regression on a write-key validation path, and it would have broken 2 of that function's own existing regression tests. The plan's own overriding acceptance criterion ("preserve each site's ORIGINAL fail-open/fail-closed behavior... no behavior change" + "full SDK unit suite stays green") takes precedence over RESEARCH's summarized table wording when the two conflict; RESEARCH itself is a design INPUT, not the literal spec, and this is exactly the kind of design-first judgment call the plan's objective calls for ("DESIGN-FIRST, not a mechanical extract").
- **Files modified:** `packages/sdk/src/client.ts` (the `walkChildWriteKey` primitive definition and its JSDoc, which documents this finding explicitly with a citation to the test file)
- **Verification:** `pnpm --filter @cipherbox/sdk test` — all 389 tests pass, including both of `resolve-shared-subfolder-write-key.test.ts`'s throw-assertion cases
- **Committed in:** `5b053a98a` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 Rule 1 — bug avoidance / correctness preservation)
**Impact on plan:** The deviation is a documentation/design-fidelity correction, not a scope change — it kept the primitive's actual behavior aligned with the plan's own top-priority "no behavior change" constraint where RESEARCH.md's shorthand table wording would otherwise have introduced a real security regression. No new files, no new call sites, no scope creep.

## Issues Encountered

- Site 6 (`moveInSharedFolder`) and site 3 (`resolveFileWriteChainKeys`) both combine the missing-`WriteChildRef` check with an additional condition (`!destReadRef` / `!writeBodyParams.writeKey`) in a single guard clause, which the primitive alone can't fully replicate (it only knows about the `writeChildren` array, not sibling conditions). Resolved by keeping each site's original combined pre-check untouched and calling `walkChildWriteKey` in `'require'` mode afterward — the primitive's own missing-ref throw path is technically unreachable at those two sites (the ref is already known present by construction) but is kept for consistency with the RESEARCH-table mode classification and to guard future callers if the pre-check is ever refactored away.
- `walkChildWriteKey`'s uniform `Uint8Array | null` return type (needed so one function signature serves all 3 modes) breaks TypeScript's control-flow narrowing at `'require'`-mode call sites where the result feeds directly into a non-nullable parameter (`unsealNode`'s `writeKey?: Uint8Array`, `wrapKey`'s `key: Uint8Array`). Resolved with small, unreachable defensive `if (!x) throw` guards immediately after each `'require'`-mode call — confirmed via `tsc --noEmit` (clean) and `pnpm --filter @cipherbox/sdk run build` (clean).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC#6's core consolidation is complete: one write-chain hop-walk primitive, one writeKey-validity predicate, both documented and gated by the existing regression suite.
- Any future write-chain call site (e.g. a hypothetical SC#7+ addition) should use `walkChildWriteKey`/`hasRealWriteKey` directly rather than re-inlining the pattern — both are already exercised by 389 passing unit tests across the affected call sites.
- Per the plan's own `<verification>` note, a full web-e2e run is recommended before phase-level verify (high-blast-radius refactor touching 7 write-plane call sites) — not run as part of this plan (out of this plan's own scope; deferred to phase-level verification).

---
*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*

## Self-Check: PASSED

- FOUND: `.planning/phases/72-sdk-write-plane-durability-and-correctness/72-08-SUMMARY.md`
- FOUND: `b00849615` (Task 1 commit)
- FOUND: `5b053a98a` (Task 2 commit)
- FOUND: `ea3ebe4fa` (SUMMARY commit)
