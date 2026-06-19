---
phase: 54
slug: e2e-test-infra-typing
status: draft
nyquist_compliant: false
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
| **Config file**        | `tsconfig.scripts.json` (new — Wave 0 creates)      |
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

> Planner fills this from final task IDs. Behavioral guarantees to validate (from RESEARCH.md Validation Architecture):
>
> - Each of the 7 migrated `.ts` scripts typechecks under `tsconfig.scripts.json` (catches D-02 entrypoint drift).
> - All scripts pass type-aware eslint under the root flat config.
> - Each migrated script still runs under `tsx` with an identical CLI/arg/env contract (D-07 behavior-preserving).
> - Both `run-all.sh` and `run-all.ps1` (plus all 6 sub-script runners) updated in lockstep (`node *.mjs` → `tsx *.ts`).
> - CI typecheck builds dependency `dist` BEFORE typechecking the helpers (D-02 companion ordering).

| Task ID   | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ---------- | --------------- | --------- | ----------------- | ----------- | ---------- |
| TBD       | TBD  | TBD  | HARD-05     | —          | N/A             | typecheck | `pnpm exec tsc -p tsconfig.scripts.json --noEmit` | ❌ W0 | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `tsconfig.scripts.json` — dedicated scripts tsconfig covering all 7 helper-script locations (D-03)
- [ ] Root `typecheck` script appends `tsc -p tsconfig.scripts.json --noEmit` after dependency `build` steps (D-02 ordering)
- [ ] Root eslint flat config includes the scripts tsconfig in its type-aware project scope (D-03)

_This phase has no runtime test framework to install — validation is tsc + eslint + tsx-run smoke._

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |
| Desktop + web E2E suites still drive identical flows post-migration | HARD-05 | web-e2e runs only on `main` push (not PRs); full desktop FUSE E2E needs a live local stack + macFUSE mount | Run desktop E2E `run-all.sh` against a local stack; confirm each migrated script exits 0 with unchanged behavior. Web-e2e validated on next `main` push. |

_Remaining behaviors (typecheck, lint, tsx-run smoke) have automated verification._

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
