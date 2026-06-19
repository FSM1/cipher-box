---
phase: 53
slug: release-supply-chain-engineering
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-19
---

# Phase 53 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> This phase is pure CI/release-process hardening (no app-runtime code). The "test suite" is the supply-chain tooling itself — `pinact`, `zizmor`, and CI guards — not a unit-test framework.

---

## Test Infrastructure

| Property               | Value                                                                        |
| ---------------------- | ---------------------------------------------------------------------------- |
| **Framework**          | None (no app unit tests — supply-chain tooling is the verification surface)  |
| **Config file**        | N/A — no test framework config                                               |
| **Quick run command**  | `pinact run --check && zizmor --offline .github/workflows/`                  |
| **Full suite command** | `GH_TOKEN=$TOKEN zizmor .github/workflows/ && git diff --exit-code Cargo.lock` |
| **Estimated runtime**  | ~15 seconds (offline checks)                                                 |

---

## Sampling Rate

- **After every task commit:** Run `pinact run --check && zizmor --offline .github/workflows/` (both fast, offline, no GitHub API)
- **After every plan wave:** Run `GH_TOKEN=$TOKEN zizmor .github/workflows/` (full audit) plus the stale-`release-as` comparison script
- **Before `/gsd-verify-work`:** Full suite green — all CI jobs pass on the phase PR, zero zizmor findings, Cargo.lock guard clean
- **Max feedback latency:** ~15 seconds

---

## Per-Task Verification Map

> Task IDs are placeholders aligned to the plan structure (one row per verifiable behavior). Plans assign final IDs; the checker maps each behavior to an automated command below.

| Task ID   | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                            | Test Type    | Automated Command                                              | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ---------- | ---------------------------------------------------------- | ------------ | ------------------------------------------------------------- | ----------- | ---------- |
| 53-01-01  | 01   | 1    | HARD-04     | T-53-01    | No third-party `uses:` ref is tag-pinned (all SHA-pinned)  | static-check | `pinact run --check` (exits non-zero if any tag ref remains)  | ✅          | ⬜ pending |
| 53-01-02  | 01   | 1    | HARD-04     | T-53-01    | Every pinned ref carries a `# vX.Y.Z` version comment      | static-check | `pinact run --verify` / comment-presence grep                 | ✅          | ⬜ pending |
| 53-02-01  | 02   | 2    | HARD-04     | T-53-01    | zizmor `unpinned-uses` passes (hard gate, CLI plain mode)  | static-check | `zizmor --offline .github/workflows/` exits 0                 | ✅          | ⬜ pending |
| 53-02-02  | 02   | 2    | HARD-04     | T-53-02    | No `excessive-permissions` finding (least-privilege jobs)  | static-check | `zizmor --offline .github/workflows/` (no excessive-perms)    | ✅          | ⬜ pending |
| 53-03-01  | 03   | 1    | HARD-04     | T-53-03    | Cargo.lock stale-after-bump is detected by CI guard        | CI/manual    | `git diff --exit-code Cargo.lock` after `cargo update --precise` | ✅       | ⬜ pending |
| 53-04-01  | 04   | 1    | HARD-04     | T-53-04    | No `release-as` entry equals its manifest version          | static-check | `node .github/scripts/check-stale-release-as.js` exits 0      | ❌ W0       | ⬜ pending |
| 53-04-02  | 04   | 2    | HARD-04     | T-53-05    | Preview bot self-heals after force-push (`cancel-in-progress: false`) | manual | Open test PR, push fixup, both preview runs complete + bot commit present | ✅ | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `.github/scripts/check-stale-release-as.js` — comparison of `release-please-config.json` `release-as` values vs `.release-please-manifest.json`; exits non-zero on any entry equal-or-below its manifest version (covers HARD-04 stale-pin guard, task 53-04-01)

_All other phase behaviors are verified by existing/added supply-chain tooling (`pinact`, `zizmor`, `git diff --exit-code`) — no test framework install required._

---

## Manual-Only Verifications

| Behavior                                            | Requirement | Why Manual                                                    | Test Instructions                                                                                                  |
| --------------------------------------------------- | ----------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Pinned SHAs resolve to the same action versions     | HARD-04     | Behavior-equivalence is observable only by running CI         | Open a no-op PR; confirm all 14 workflows' jobs pass exactly as before pinning (SHA → same version, no behavior change) |
| Release PR carries an updated Cargo.lock diff        | HARD-04     | Requires a real release-please PR cycle                       | On the next release PR, confirm `cargo update --precise` step committed a Cargo.lock version-line diff for bumped first-party crates |
| Preview recompute survives force-push / rebase       | HARD-04     | Requires a live PR with a force-push race against the bot      | Open a PR, let the bot push `chore(release): set release targets`, push a fixup, confirm the recompute completes (no cancellation) and the final config is correct |
| Fetch+rebase discipline codified (CLAUDE.md / MEMORY) | HARD-04   | Convention/documentation enforcement, not executable          | Confirm CLAUDE.md (and/or agent instructions) documents "never force-push over the bot's `chore(release)` commit; fetch+rebase instead" |

---

## Validation Sign-Off

- [ ] All tasks have an automated verify command or a Wave 0 dependency (manual-only items are explicitly listed and justified above)
- [ ] Sampling continuity: no 3 consecutive tasks without an automated check (pinact/zizmor cover the static surface)
- [ ] Wave 0 covers all MISSING references (`check-stale-release-as.js`)
- [ ] No watch-mode flags (all checks are one-shot CLI/CI)
- [ ] Feedback latency < 15s for the quick command
- [x] `nyquist_compliant: true` set in frontmatter (plans align — confirmed by plan-checker)

**Approval:** approved 2026-06-19
