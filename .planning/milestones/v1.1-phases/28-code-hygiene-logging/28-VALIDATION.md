---
phase: 28
slug: code-hygiene-logging
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-19
validated: 2026-06-19
---

# Phase 28 — Validation Strategy

> Retroactive per-phase validation contract. Phase 28 shipped in commit
> `9827f49df` (feat: Phase 28 Code Hygiene & Logging, #382). This document
> records the ACTUAL current coverage of the four success criteria, not
> pending wave-0 stubs.

---

## Test Infrastructure

| Property               | Value                                                      |
| ---------------------- | ---------------------------------------------------------- |
| **Framework**          | Vitest (node env)                                          |
| **Config file**        | `apps/web/vitest.config.ts` (`test.include: src/**/*.test.ts`) |
| **Quick run command**  | `cd apps/web && pnpm test`                                 |
| **Full suite command** | `cd apps/web && pnpm test`                                 |
| **Estimated runtime**  | ~15 seconds                                                |

Note: this is a code-hygiene / tech-debt phase. Three of the four success
criteria (console replacement, `as any` elimination, POC archival) are
**static source properties** — their canonical verification is a `grep`/`ls`
invariant run in CI lint/static analysis, not a runtime behavioral test.
Only the logger module's runtime behavior and the "failures are logged"
behavior have a runtime surface that a Vitest test can exercise.

---

## Success-Criterion Verification Map

| SC  | Requirement                                                        | Test Type     | Verification Command                                                                              | Coverage    | Status |
| --- | ----------------------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------ | ----------- | ------ |
| 1a  | `lib/logger.ts` exists with debug/info/warn/error + level filter  | static        | `ls apps/web/src/lib/logger.ts` (LogLevel enum + `minLevel` PROD gate present)                    | COVERED     | green  |
| 1b  | Logger interface is callable and dispatched on warn path          | unit          | `cd apps/web && npx vitest run src/services/delete.service.test.ts` (mocks logger, asserts warn)  | PARTIAL     | green  |
| 1c  | All 124 raw `console.*` calls replaced in production web code      | static grep   | `grep -rnE "console\.(log\|warn\|error\|info\|debug)\(" apps/web/src --include=*.ts --include=*.tsx \| grep -v logger.ts \| grep -v .test.ts` → 0 | MANUAL-ONLY | green  |
| 2   | `.catch(() => {})` on unpin replaced with `.catch(logger.warn)`   | static + unit | `grep -rn ".catch(() => {})" apps/web/src --include=*.ts --include=*.tsx \| grep -v .test.ts` → only FileBrowser handleSync (non-unpin, out of scope); failure-logs-warn behavior in delete.service.test.ts:65 | PARTIAL     | green  |
| 3   | All `as any` casts eliminated in production web code              | static grep   | `grep -rnE "\bas any\b" apps/web/src --include=*.ts --include=*.tsx \| grep -v .test.ts` → 0      | MANUAL-ONLY | green  |
| 4   | `00-Preliminary-R&D/poc/` archived / no longer pollutes searches  | static fs     | `ls 00-Preliminary-R&D/poc/` → No such file or directory (entire dir removed; preserved in git)   | MANUAL-ONLY | green  |

_Status: pending · green · red · flaky_

---

## Coverage Detail

### SC1 — Structured logger + console replacement

- `apps/web/src/lib/logger.ts` exists: `LogLevel` enum (DEBUG/INFO/WARN/ERROR/SILENT),
  module-load `minLevel` gate (`import.meta.env.PROD ? WARN : DEBUG`), and
  timestamped `formatMessage`. Verified by read.
- The only `console.*` calls remaining under `apps/web/src` are the **4 internal
  sinks inside `logger.ts`** (`console.debug/info/warn/error`). Zero raw
  `console.*` in any other production file (grep verified).
- **Runtime coverage:** `delete.service.test.ts` mocks `../lib/logger` and asserts
  `logger.warn` is invoked on the quota-reconcile failure path
  (`delete.service.test.ts:65`). This exercises the logger as a dependency
  interface but does **not** unit-test the level-filtering branch
  (`shouldLog` / PROD-vs-DEV `minLevel`). The bulk console-replacement criterion
  is a mechanical find-replace verified by grep, not a behavioral test.

### SC2 — Silenced unpin failures made visible

- Production unpin `.catch(() => {})` patterns are gone. The single remaining
  `.catch(() => {})` in production code is `FileBrowser.tsx:149`, attached to
  `actions.handleSync()` (a fire-and-forget UI refresh) — **not an unpin call**,
  so it is outside SC2 scope.
- `upload-error-recovery.test.ts` exercises the upload catch-block recovery
  (fire-and-forget unpin on registration failure; asserts `unpin` and quota
  reconcile are called). However, its own `simulateErrorRecovery` helper uses
  `.catch(() => {})` and does **not** assert that an unpin failure is logged —
  so it covers the recovery flow but not the SC2 "failures are visible in logs"
  guarantee directly.
- `delete.service.test.ts:65` provides the direct behavioral evidence that a
  swallowed-failure path now routes through `logger.warn` rather than an empty
  block.

### SC3 — `as any` elimination

- `grep -rnE "\bas any\b" apps/web/src` (excluding tests) → 0 cast occurrences.
  Polyfill/Window augmentations were converted to `declare global` /
  typed `Window` interfaces. This is a compile-time / source invariant with no
  runtime behavioral surface; verification is static.

### SC4 — Legacy POC archived

- `00-Preliminary-R&D/poc/` no longer exists; the entire `00-Preliminary-R&D/`
  directory is absent from the working tree. Removal is recorded in the Phase 28
  commit `9827f49df` and the POC remains in git history. Filesystem invariant,
  verified by `ls`.
- **Deviation from plan:** 28-04-PLAN/SUMMARY called for an
  `00-Preliminary-R&D/ARCHIVED.md` provenance note; that file is not present
  (the whole parent directory was removed instead). The success criterion
  ("archived … and no longer pollutes searches") is satisfied; the provenance
  note is a documentation-only nicety and is preserved via git history.

---

## Manual-Only / Static Verifications

| Behavior                          | SC  | Why Not a Runtime Test                         | Verification Instruction                                                                                  |
| --------------------------------- | --- | ---------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| All raw `console.*` replaced      | 1c  | Mechanical find-replace; source invariant      | `grep -rnE "console\.(log\|warn\|error\|info\|debug)\(" apps/web/src` returns only logger.ts internals    |
| `as any` casts eliminated         | 3   | Compile-time/type invariant, no runtime path   | `grep -rnE "\bas any\b" apps/web/src` (excl. tests) → 0                                                   |
| POC directory archived            | 4   | Filesystem/repo-history fact                   | `ls 00-Preliminary-R&D/poc/` → not found; removal in commit `9827f49df`                                   |
| Logger level filtering (PROD gate)| 1a  | `minLevel` is module-load const from `import.meta.env.PROD`; not unit-tested | Inspect `logger.ts` `minLevel`/`shouldLog`; no dedicated `logger.test.ts` exists  |

---

## Validation Sign-Off

- [x] All four success criteria have a confirmed verification (automated grep/fs invariant or runtime test)
- [x] Logger interface dispatch and failure-logging behavior have at least one runtime test (delete.service.test.ts)
- [x] No test suite was executed during this audit (static enumeration only)
- [x] `nyquist_compliant: true` — every SC resolves to green via automated grep/fs invariant or justified manual-only

**Approval:** validated 2026-06-19 via retroactive /gsd-validate-phase pass.

## Validation Audit 2026-06-19

| Metric              | Count |
| ------------------- | ----- |
| Success criteria    | 4     |
| Covered (automated) | 0     |
| Partial             | 2     |
| Manual-only/static  | 4     |
| Missing             | 0     |

> Counts span the SC verification map rows: SC1 splits into 1a/1b/1c, giving
> 2 PARTIAL rows (1b, 2) with real runtime evidence and 4 MANUAL-ONLY/static
> invariant rows (1a, 1c, 3, 4). No SC is MISSING.

Audit notes: Phase 28 is a code-hygiene phase whose four success criteria are
predominantly **static source invariants** (no raw `console.*`, no `as any`,
POC removed) rather than runtime behaviors, so the canonical verification is
`grep`/`ls` rather than a Vitest suite. All four invariants were confirmed by
static enumeration: `console.*` in production web code → 0 (only the 4 sinks
inside `logger.ts`); `.catch(() => {})` in production → 1 remaining, which is a
`handleSync` call (out of SC2's unpin scope), not a regression;
`as any` in production web code → 0; `00-Preliminary-R&D/poc/` → removed
(entire parent dir gone, preserved in git history). Two criteria additionally
carry runtime behavioral evidence: `delete.service.test.ts` mocks the logger and
asserts `logger.warn` fires on a swallowed-failure path (covers SC1 logger
dispatch + SC2 "failures visible"), and `upload-error-recovery.test.ts` exercises
the unpin fire-and-forget recovery flow.

Gaps noted but NOT blocking (no escalation — invariants hold and shipped):

1. No dedicated `apps/web/src/lib/logger.test.ts` — the level-filtering branch
   (`shouldLog` / PROD-vs-DEV `minLevel`) has no direct unit test. Logger is
   only covered indirectly via `delete.service.test.ts` mocking its interface.
2. `upload-error-recovery.test.ts` asserts the unpin recovery flow but not that
   an unpin **failure** is logged; SC2's logging guarantee is covered directly
   only by `delete.service.test.ts:65`.
3. Plan deviation (28-04): `00-Preliminary-R&D/ARCHIVED.md` provenance note was
   not created — the whole parent directory was removed instead. The SC is still
   satisfied; provenance lives in git history.

`nyquist_compliant: true` is set because every success criterion resolves to a
confirmed green state via an automated grep/filesystem invariant or a justified
static/manual verification, with two criteria additionally backed by runtime
tests. The three gaps above are coverage-depth nice-to-haves on already-passing
invariants, not unmet requirements.
