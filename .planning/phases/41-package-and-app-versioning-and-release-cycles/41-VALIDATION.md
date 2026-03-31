---
phase: 41
slug: package-and-app-versioning-and-release-cycles
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-31
---

# Phase 41 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                       |
| ---------------------- | ----------------------------------------------------------- |
| **Framework**          | GitHub Actions (workflow syntax validation) + shell scripts |
| **Config file**        | `.github/workflows/*.yml`                                   |
| **Quick run command**  | `node .github/scripts/release-preview.mjs --dry-run --pr 0` |
| **Full suite command** | `act -j pr-release-preview --dryrun` or manual PR test      |
| **Estimated runtime**  | ~5 seconds (dry-run), ~30s (act)                            |

---

## Sampling Rate

- **After every task commit:** Run `node .github/scripts/release-preview.mjs --dry-run --pr 0`
- **After every plan wave:** Validate workflow YAML syntax + dry-run all scripts
- **Before `/gsd:verify-work`:** Full integration test with real PR
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type | Automated Command                                                             | File Exists | Status     |
| -------- | ---- | ---- | ----------- | --------- | ----------------------------------------------------------------------------- | ----------- | ---------- |
| 41-01-01 | 01   | 1    | D-04/D-10   | config    | `node -e "JSON.parse(fs.readFileSync('release-please-config.json'))"`         | ✅          | ⬜ pending |
| 41-01-02 | 01   | 1    | D-05        | config    | `grep '"release-as"' release-please-config.json` (should not exist pre-merge) | ✅          | ⬜ pending |
| 41-02-01 | 02   | 2    | D-15/D-16   | script    | `node .github/scripts/release-preview.mjs --dry-run`                          | ❌ W0       | ⬜ pending |
| 41-02-02 | 02   | 2    | D-21/D-22   | script    | `node .github/scripts/release-preview.mjs --dry-run --test-cascade`           | ❌ W0       | ⬜ pending |
| 41-03-01 | 03   | 3    | D-25/D-27   | script    | `node .github/scripts/post-merge-release.mjs --dry-run`                       | ❌ W0       | ⬜ pending |
| 41-04-01 | 04   | 3    | D-35        | config    | `grep 'staging-' .github/workflows/deploy-staging.yml`                        | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `.github/scripts/release-preview.mjs` — PR commit analysis script with --dry-run mode
- [ ] `.github/scripts/post-merge-release.mjs` — release-as injection script with --dry-run mode

_Scripts created during Wave 2/3 execution, but dry-run mode is the validation mechanism._

---

## Manual-Only Verifications

| Behavior                    | Requirement | Why Manual                       | Test Instructions                         |
| --------------------------- | ----------- | -------------------------------- | ----------------------------------------- |
| Labels appear on real PR    | D-16        | Requires GitHub API interaction  | Open test PR, verify labels auto-applied  |
| RP creates correct release  | D-31        | Requires full RP run             | Merge test PR, verify release PR versions |
| Tauri updater resolves      | D-33        | Requires desktop build + release | Check `/releases/latest` has updater JSON |
| Staging deploy with new tag | D-35        | Requires VPS deploy              | Push staging tag, verify services come up |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
