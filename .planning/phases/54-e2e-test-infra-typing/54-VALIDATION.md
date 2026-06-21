---
phase: 54
slug: e2e-test-infra-typing
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-19
---

# Phase 54 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                               |
| ---------------------- | --------------------------------------------------- |
| **Framework**          | tsc 5.9.x + eslint 9.x (type-aware) + tsx 4.x (run) |
| **Config file**        | `tsconfig.scripts.json` (new — Wave 1 / plan 01 creates) |
| **Quick run command**  | `pnpm exec tsc -p tsconfig.scripts.json --noEmit`   |
| **Full suite command** | `pnpm typecheck && pnpm lint`                       |
| **Estimated runtime**  | ~120 seconds (includes dep dist build)              |

---

## Sampling Rate

- **After every task commit:** Run `pnpm exec tsc -p tsconfig.scripts.json --noEmit`
- **After every plan wave:** Run `pnpm typecheck && pnpm lint`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 120 seconds

---

## Per-Task Verification Map

> Final task IDs from the four plans. Each migrated `.ts` script typechecks under `tsconfig.scripts.json`
> (catches D-02 entrypoint drift) and passes eslint; behavior is preserved (D-07) and verified by the
> desktop/web E2E suites (manual, live stack). The .mjs originals stay until Wave 3 (plan 04) so runners
> keep working; the runner switch + .mjs deletion is gated on the full `pnpm typecheck && pnpm lint`.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
| ------- | ---- | ---- | ----------- | ---------- | --------------- | --------- | ----------------- | ----------- | ------ |
| 54-01-T1 | 01 | 1 | HARD-05 | T-54-02 | tsconfig paths→dist (no external resolution) | structural | `node -e` include/paths/typecheck-ordering assertions | ❌ W1 creates | ⬜ pending |
| 54-01-T2 | 01 | 1 | HARD-05 | T-54-01 | no secret/privateKeyHex logging; no-`--secret`-on-CLI guard | grep + typecheck | `grep` exports/entrypoints + `tsc -p tsconfig.scripts.json --noEmit` | ❌ W1 creates | ⬜ pending |
| 54-01-T3 | 01 | 1 | HARD-05 | — | N/A | typecheck + lint | `pnpm exec tsc -p tsconfig.scripts.json --noEmit && pnpm exec eslint tests/e2e-helpers/*.ts` | ❌ W1 creates | ⬜ pending |
| 54-02-T1 | 02 | 2 | HARD-05 | T-54-03 | clearBytes preserved; no key logging | typecheck + lint | `tsc -p tsconfig.scripts.json --noEmit && eslint edit/rename.ts` | ❌ W2 creates | ⬜ pending |
| 54-02-T2 | 02 | 2 | HARD-05 | T-54-03 | identical stdout/exit (spawned child) | typecheck + lint | `tsc -p tsconfig.scripts.json --noEmit && eslint verify-filepointer.ts` | ❌ W2 creates | ⬜ pending |
| 54-03-T1 | 03 | 2 | HARD-05 | T-54-05 | TEST_SECRET in spawn env only; tsx interpreter | typecheck + lint | `tsc -p tsconfig.scripts.json --noEmit && eslint bump/test-move.ts` | ❌ W2 creates | ⬜ pending |
| 54-03-T2 | 03 | 2 | HARD-05 | T-54-06, T-54-07 | @cipherbox/core IPNS import; declared @noble devDep | typecheck + lint | `tsc -p tsconfig.scripts.json --noEmit && eslint staging/gen-vectors.ts` | ❌ W2 creates | ⬜ pending |
| 54-04-T1 | 04 | 3 | HARD-05 | T-54-08 | .sh/.ps1 lockstep; intentional divergence preserved | grep gate | runner node-mjs==0 + tsx-ts>=9 + cross-client.ps1 no-rename gate | ✅ existing | ⬜ pending |
| 54-04-T2 | 04 | 3 | HARD-05 | T-54-09 | no dangling .mjs ref before delete | typecheck + lint | `git ls-files *.mjs==0 + no dangling ref && pnpm typecheck && pnpm lint` | ✅ existing | ⬜ pending |
| MANUAL | 02/03/04 | 2-3 | HARD-05 | — | behavior-preserving flows (D-07) | e2e (manual) | `bash tests/desktop-e2e/scripts/run-all.sh` (live stack); web-e2e on next `main` push | ✅ existing | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 / Wave 1 Requirements

> This phase has no Wave 0 test-scaffold step; the foundation (plan 01, Wave 1) creates the gate.

- [ ] `tsconfig.scripts.json` — dedicated scripts tsconfig covering all 7 helper-script locations + tests/e2e-helpers (D-03) — plan 01 T1
- [ ] Root `typecheck` script appends `tsc -p tsconfig.scripts.json --noEmit` after dependency `build` steps (D-02 ordering) — plan 01 T1
- [ ] `tests/e2e-helpers/auth.ts` + `types.ts` — shared typed helper (D-04) — plan 01 T2
- [ ] Root eslint flat config confirmed to cover the scripts via the global `**/*.ts` glob (D-03 — expected: no change needed) — plan 01 T3

_This phase has no runtime test framework to install — validation is tsc + eslint + tsx-run smoke._

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |
| Desktop + web E2E suites still drive identical flows post-migration | HARD-05 | web-e2e runs only on `main` push (not PRs); full desktop FUSE E2E needs a live local stack + macFUSE mount | Run desktop E2E `run-all.sh` against a local stack; confirm each migrated script exits 0 with unchanged behavior. Web-e2e validated on next `main` push. |
| generate-test-vectors emitted hex vectors unchanged | HARD-05 | Rust crypto-parity consumers depend on the exact vectors; entrypoint-import fix must not alter output | Run `pnpm exec tsx apps/desktop/src-tauri/generate-test-vectors.ts` and diff stdout against pre-migration `.mjs` output |

_Remaining behaviors (typecheck, lint, tsx-run smoke) have automated verification._

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 1 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 1 covers all MISSING references (tsconfig.scripts.json, tests/e2e-helpers)
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** planner-filled 2026-06-19
