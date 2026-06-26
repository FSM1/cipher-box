# Phase 53: Release & Supply-Chain Engineering - Research

**Researched:** 2026-06-19
**Domain:** CI/release-process hardening — GitHub Actions supply chain, Cargo.lock sync, release-please pin automation
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01 (pinning):** SHA-pin all ~111 third-party `uses:` refs across 14 workflow files to a full 40-char commit SHA with trailing version comment. Internal reusable-workflow refs (`./github/workflows/*.yml`) excluded. Bulk-convert with `pinact` or `ratchet` — do not hand-edit 111 refs.
- **D-02 (rollout):** All-at-once in one PR.
- **D-03 (Dependabot):** Add/extend `.github/dependabot.yml` with `package-ecosystem: "github-actions"`. Without this, pinning freezes CI on stale SHAs — MANDATORY.
- **D-04 (zizmor + permissions):** Add a zizmor CI gate that fails newly-introduced unpinned `uses:` refs (`unpinned-uses`), AND fix the `excessive-permissions` finding by adding least-privilege job-level `permissions:` blocks.
- **D-05 (lock sync):** Prefer native release-please cargo-aware Cargo.lock updater. Fallback: auto-update lock on release PR via `cargo update -p <crate> --precise <new-version>` per bumped first-party crate + CI guard. Either path keeps lock update on the release PR so `main` is never stale post-merge.
- **D-06 (architecture):** Root cause is force-push/rebase clobbering the bot's `chore(release): set release targets` commit, compounded by `concurrency: cancel-in-progress: true`. Primary fix: fetch+rebase discipline (never force-push over the bot commit), codified in tooling + agent instructions. Optional lightweight safety-net: re-run preview on final state before merge and/or revisit cancel-in-progress — do NOT over-build.
- **D-07 (secondary hygiene):** Reconcile path attribution between `pr-release-preview.js` `packageBumps` (~line 298) and release-please. One-time cleanup of existing `release-as` entries equal to manifest version.

### Claude's Discretion

- Which tool to use for SHA pinning: `pinact` vs `ratchet` — planner picks with rationale.
- Whether to implement the optional safety-net for #16 and which form it takes.

### Deferred Ideas (OUT OF SCOPE)

- Full re-architecture of release-target computation (remove committed `release-as` config, let release-please own versioning natively).

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                        | Research Support                                            |
| ------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| HARD-04 | Release & supply-chain engineering — pin GitHub Actions, Cargo.lock sync, release-please hardening | All three sub-tasks researched below with concrete implementation paths |

</phase_requirements>

## Summary

Phase 53 is pure CI/release-config hardening with no app runtime code. Three bounded work items: (1) SHA-pin 111 third-party GitHub Action `uses:` refs across 14 workflows using `pinact`, keep them current via the Dependabot github-actions block that already exists in `.github/dependabot.yml`, and add a zizmor CI gate; (2) keep Cargo.lock in sync with release-please crate bumps — the native `cargo-workspace` plugin is unreliable (open bug #2517 as of March 2025), so the fallback path applies: `cargo update -p <crate> --precise <new-version>` committed onto the release PR; (3) harden the release-please pin automation against force-push/rebase clobber via fetch+rebase discipline codified in docs and an optional minimal safety-net (re-run preview before merge).

All three work items are `type: execute` (CI config, workflow YAML, script patches) except the optional Node.js guard script for Cargo.lock staleness detection, which is testable. The biggest judgment call is D-05 (native vs fallback cargo lock path) — research conclusively points to the fallback path due to the cargo-workspace plugin bug.

**Primary recommendation:** Use `pinact` (not `ratchet`) for SHA pinning because it has a native GitHub Action wrapper (`suzuki-shunsuke/pinact-action`) that makes it easy to run in CI as a check, and it is actively maintained with version-comment verification support. Use the fallback Cargo.lock path (script in release-please.yml). Implement the D-06 primary fix as CLAUDE.md + MEMORY.md documentation plus a one-line `git push --force-with-lease` guard in the pr-release-preview workflow commit step.

## Architectural Responsibility Map

| Capability                      | Primary Tier     | Secondary Tier        | Rationale                                                |
| ------------------------------- | ---------------- | --------------------- | -------------------------------------------------------- |
| GitHub Actions SHA pinning      | CI / Workflow    | —                     | Pure workflow YAML changes; no app code                  |
| Dependabot github-actions block | CI / Config      | —                     | `.github/dependabot.yml` config entry                    |
| zizmor CI gate                  | CI / Workflow    | —                     | New CI job in existing or new workflow file              |
| Job-level `permissions:` blocks | CI / Workflow    | —                     | Inline job config in existing workflow files             |
| Cargo.lock sync                 | CI / Workflow    | Release PR automation | Script step added to `release-please.yml`                |
| pr-release-preview resilience   | CI / Scripts     | Docs / Agent Memory   | Primary: docs + MEMORY.md; optional: workflow change     |
| release-as cleanup              | Config           | —                     | One-time edit of `release-please-config.json`            |

## Standard Stack

### Core

| Tool / Library | Version     | Purpose                               | Why Standard                                    |
| -------------- | ----------- | ------------------------------------- | ----------------------------------------------- |
| pinact         | latest      | Bulk-convert tag refs to SHA+comment  | Native GitHub Action, version-comment aware, idempotent `pinact run` |
| zizmor         | latest      | CI gate for unpinned-uses + excessive-permissions | Official SAST for GitHub Actions; exits non-zero on findings |
| Dependabot     | built-in    | Keep pinned SHAs current weekly       | Already partially configured; just needs github-actions block |
| cargo update   | bundled     | Regenerate Cargo.lock precisely       | `--precise` flag updates only specified crate version — no dep re-resolution |

### Alternatives Considered

| Instead of       | Could Use               | Tradeoff                                                                                   |
| ---------------- | ----------------------- | ------------------------------------------------------------------------------------------ |
| pinact           | ratchet (sethvargo)     | ratchet has no native GH Action wrapper; both pin to SHA+comment but ratchet is Docker-based |
| zizmor plain run | zizmor-action (SARIF)   | SARIF mode exits 0 always — not suitable as a blocking CI gate; plain mode exits 11-14 on findings |
| cargo-workspace plugin | CI script step  | cargo-workspace plugin has open bug #2517 (March 2025) that skips Cargo.lock member updates |

## Package Legitimacy Audit

No new npm/PyPI/crates packages installed. `pinact` and `zizmor` are dev/CI tools installed in the CI runner environment, not added to package.json. This phase is pure CI config.

**Packages removed due to SLOP verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```
Developer pushes to PR branch
        |
        v
[pr-release-preview.yml] -> pr-release-preview.js
  (concurrency: cancel-in-progress: true)
        |
        v
  bot commits "chore(release): set release targets for PR #N"
  to PR branch (commits SHA into release-please-config.json)
        |
  [VULNERABILITY: force-push clobbers bot commit;
   cancel-in-progress aborts re-run → stale config]
        |
  PR merges to main
        |
        v
[release-please.yml] reads release-please-config.json release-as pins
  -> creates/updates release PR with version bumps in Cargo.toml
  [GAP: Cargo.lock NOT updated — stale after merge]
        |
        v
  release PR merges → version tags created
  → Cargo.lock has stale [[package]] version entries
    until someone runs `cargo` out-of-band
```

**After Phase 53 fixes:**

```
Developer push → git fetch + rebase (never force-push over bot commit)
  [D-06 discipline: codified in CLAUDE.md + MEMORY.md + --force-with-lease guard]
        |
pr-release-preview.yml computes correct release targets → bot commits
        |
Release PR: Cargo.lock updated via `cargo update -p <crate> --precise <ver>`
  CI guard: `git diff --exit-code Cargo.lock` fails if stale
        |
zizmor CI gate: `zizmor .github/workflows/` exits non-zero on unpinned-uses
All 111 third-party uses: refs → SHA@40char # vX.Y.Z
Dependabot weekly bumps pinned SHAs + version comments
```

### Recommended Project Structure

No new directories. Changes are within:
```
.github/
├── workflows/
│   ├── ci.yml                    # job-level permissions: blocks
│   ├── *.yml                     # SHA-pinned uses: refs (all 14 files)
│   └── zizmor.yml (new)          # zizmor CI gate workflow
├── dependabot.yml                # already has github-actions block — verified OK
└── scripts/
    └── pr-release-preview.js     # D-06/D-07 patches
```

## #6 — SHA Pinning: Detailed Research

### Tool Choice: pinact (recommended over ratchet)

**Decision: Use `pinact`.**

Rationale:
- `pinact run` processes all `.github/workflows/*.yml` files in one invocation, resolves every tag to a commit SHA, and writes `uses: action/name@<sha> # vX.Y.Z` version comments idempotently. [CITED: github.com/suzuki-shunsuke/pinact]
- `suzuki-shunsuke/pinact-action` is a first-class GitHub Action wrapper making it trivial to add as a CI check (`pinact run -check`). [CITED: github.com/suzuki-shunsuke/pinact]
- `ratchet` is also viable but uses Docker container execution (`docker://ghcr.io/sethvargo/ratchet:latest`), has no official GH Action wrapper, and is less actively maintained per recent release history. [ASSUMED]
- `pinact run -verify-comment` also validates that existing version comments match pinned SHAs — useful as the ongoing gate after Dependabot bumps. [CITED: github.com/suzuki-shunsuke/pinact]

**Invocation for bulk conversion (one-time, run locally or in a bot job):**

```bash
# Requires GITHUB_TOKEN for API access
GITHUB_TOKEN=<token> pinact run
```

This rewrites all `.github/workflows/*.yml` files in-place. [CITED: github.com/suzuki-shunsuke/pinact]

**Invocation for CI check (ongoing gate):**

```bash
pinact run -check
```

Exits non-zero if any action is not SHA-pinned with a correct version comment.

### Inventory: 111 Third-Party refs, 14 Workflow Files

Verified by `grep -h "uses:" .github/workflows/*.yml | grep -v "\./.github/workflows/" | wc -l` = **111 refs**. [VERIFIED: codebase grep]

Internal refs (excluded, 5 total): `./.github/workflows/deploy-staging.yml`, `./.github/workflows/desktop-e2e.yml` (×2), `./.github/workflows/web-e2e.yml` (×2). [VERIFIED: codebase grep]

**Distribution by action (verified from codebase):** [VERIFIED: codebase grep]

| Action                                 | Count | Risk Level |
| -------------------------------------- | ----- | ---------- |
| `actions/checkout@v6`                  | 33    | Low (GitHub-owned) |
| `actions/setup-node@v6`               | 20    | Low (GitHub-owned) |
| `pnpm/action-setup@v6`                | 18    | Medium (pnpm org) |
| `actions/cache@v5`                    | 9     | Low (GitHub-owned) |
| `tauri-apps/tauri-action@v0`          | 6     | HIGH (third-party, `@v0` is very mutable) |
| `actions/upload-artifact@v7`          | 5     | Low (GitHub-owned) |
| `codecov/codecov-action@v7`           | 4     | Medium (Codecov) |
| `appleboy/ssh-action@v1.2.5`          | 3     | HIGH (low-profile publisher) |
| `appleboy/scp-action@v1.0.0`          | 3     | HIGH (low-profile publisher) |
| `dorny/paths-filter@v4`               | 2     | Medium |
| `docker/login-action@v4`              | 2     | Low (Docker-owned) |
| `docker/build-push-action@v7`         | 2     | Low (Docker-owned) |
| `ikalnytskyi/action-setup-postgres@v8`| 1     | HIGH (low-profile publisher) |
| `googleapis/release-please-action@v5` | 1     | Medium (Google-owned) |
| `actions/download-artifact@v8`        | 1     | Low (GitHub-owned) |
| `actions/create-github-app-token@v3`  | 1     | Low (GitHub-owned) |

**Per-file count (for planner task breakdown):** [VERIFIED: codebase grep]

| Workflow File                     | Third-party refs |
| --------------------------------- | ---------------- |
| ci.yml                            | 36               |
| deploy-staging.yml                | 31               |
| desktop-staging-release.yml       | 15               |
| desktop-e2e.yml                   | 6                |
| web-e2e.yml                       | 4                |
| ci-e2e.yml                        | 4                |
| load-test.yml                     | 4                |
| deploy-landing.yml                | 4                |
| tag-staging.yml                   | 5 (includes one internal) → 4 third-party |
| pr-release-preview.yml            | 2                |
| release-please.yml                | 2                |
| release-gate.yml                  | 1                |
| codecov-base.yml                  | 2                |
| pr-title.yml                      | 0 (no `uses:` at all) |

### Dependabot: Already Configured — No Change Needed

`.github/dependabot.yml` already contains a `package-ecosystem: "github-actions"` block with correct settings (weekly Monday cadence, `chore(ci)` commit prefix, `dependencies` + `ci` labels). [VERIFIED: codebase grep]

```yaml
version: 2
updates:
  - package-ecosystem: 'github-actions'
    directory: '/'
    schedule:
      interval: 'weekly'
      day: 'monday'
    labels:
      - 'dependencies'
      - 'ci'
    commit-message:
      prefix: 'chore(ci)'
```

Dependabot will update SHA-pinned actions' commit hashes AND update the `# vX.Y.Z` version comment when a new release tag is available. [CITED: github.blog/changelog/2022-10-31-dependabot-now-updates-comments-in-github-actions-workflows-referencing-action-versions]

**D-03 is already satisfied.** The planner does NOT need to add a new Dependabot entry.

### zizmor CI Gate

**Tool:** `zizmor` (CLI, not the SARIF-based `zizmorcore/zizmor-action`). [CITED: docs.zizmor.sh/usage]

**Why not the GH Action (SARIF mode):** The `zizmorcore/zizmor-action` emits SARIF, which causes zizmor to exit 0 always — a SARIF consumer doesn't use exit codes for findings. The plain CLI mode exits 11–14 based on finding severity, which is what makes it a hard CI gate. [CITED: docs.zizmor.sh/usage]

**Install in CI:**

```bash
pip install zizmor  # or: cargo install zizmor
```

**CI gate job pattern:**

```yaml
jobs:
  zizmor:
    name: GitHub Actions Security Gate
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<sha> # v4+
      - name: Install zizmor
        run: pip install zizmor
      - name: Run zizmor
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: zizmor .github/workflows/
```

With no `--min-severity` flag, zizmor runs all audits including `unpinned-uses` and `excessive-permissions`. After all actions are SHA-pinned, `unpinned-uses` will no longer fire. The gate then prevents future regressions (any new `uses: action@vX` fails the build). [CITED: docs.zizmor.sh/audits, docs.zizmor.sh/usage]

**Suppressing specific findings inline** (for legitimate exceptions):

```yaml
- uses: some/action@sha # zizmor: ignore[excessive-permissions]
```

**Configuration file** (`.github/zizmor.yml`) for persistent ignore rules:

```yaml
rules:
  excessive-permissions:
    ignore:
      - workflow.yml:10
```

### Permissions Audit: Jobs Lacking `permissions:` Blocks

**Current state (verified):** [VERIFIED: codebase grep]

Workflows with **top-level** `permissions:` block (all jobs inherit):
- `codecov-base.yml` — `actions: read` + `contents: read` (fine)
- `desktop-staging-release.yml` — `contents: write` (too broad — should be job-level)
- `pr-release-preview.yml` — `contents: write`, `pull-requests: write` (fine — only one job, these are the minimum needed)
- `release-please.yml` — `contents: write`, `pull-requests: write` (fine — one job)

Workflows with **no permissions block at all** (inherit default write on all tokens — excessive):
- `desktop-e2e.yml` — `desktop-e2e` job
- `web-e2e.yml` — `web-e2e` job
- `load-test.yml` — `load-test` job
- `release-gate.yml` — `detect-changes` + `verify-e2e` jobs
- `tag-staging.yml` — `resolve-main` job (others have job-level perms)
- `ci-e2e.yml` — `detect-changes` + `web-e2e` + `desktop-e2e` jobs (only `retrigger-release-gate` has perms)

Workflows with **some jobs missing** `permissions:` (only `changes` job has it):
- `ci.yml` — `changes` job has `pull-requests: read`; jobs `lint`, `typecheck`, `api-spec`, `migration-check`, `test`, `sdk-e2e`, `build`, `cargo-windows`, `cargo-macos`, `cargo-linux`, `vector-parity` have NO job-level permissions (zizmor's `excessive-permissions` finding: specifically flagged `cargo-linux` in CodeRabbit scan on PR #487)

**Specific `cargo-linux` finding from PR #487:** The `cargo-linux` job in `ci.yml` (lines 609–680) has no `permissions:` block and runs with the inherited default write token while uploading Codecov coverage. Least-privilege for this job is `contents: read`. [ASSUMED from todo text — original zizmor finding]

**Standard least-privilege pattern for read-only CI jobs:**

```yaml
jobs:
  my-job:
    permissions:
      contents: read
    steps: ...
```

Jobs that write to PRs (comment, label) need `pull-requests: write`. Jobs that create releases need `contents: write`. Jobs with no external writes need only `contents: read`.

**Recommended: also add top-level `permissions: {}` to all workflows lacking it**, then add minimal job-level blocks. This is the zizmor-recommended pattern. [CITED: zizmor docs - excessive-permissions]

## #13 — Cargo.lock Sync: D-05 Path Decision

### Verdict: FALLBACK PATH applies

**Research finding (conclusive):** The `cargo-workspace` plugin for release-please has a known open bug filed March 27, 2025 (googleapis/release-please#2517) that causes it to skip Cargo.lock member version updates AND `.release-please-manifest.json` updates when `"plugins": ["cargo-workspace"]` is added to config. [CITED: github.com/googleapis/release-please/issues/2517]

The fix PR (#1260, merged February 2022) added `postProcessCandidates` to update the root `Cargo.lock`, but the more recent issue #2517 (March 2025) shows this still does not work reliably in manifest/monorepo mode — which is exactly how this repo uses release-please (all crates declared in `release-please-config.json` packages, driven by `.release-please-manifest.json`). [CITED: github.com/googleapis/release-please/issues/2517, github.com/googleapis/release-please/pull/1260]

**Additionally:** `release-please-config.json` does NOT currently have a `"plugins"` key. Adding `cargo-workspace` carries known regression risk (manifest.json updates skipped). [VERIFIED: codebase grep]

**D-05 path: Fallback — `cargo update --precise` in the release-please workflow.**

### Fallback Implementation

The release-please workflow (`release-please.yml`) runs on push to `main`. After release-please creates/updates the release PR, a subsequent step (or a separate workflow triggered by the release PR's push event) must regenerate Cargo.lock.

**Mechanism:** After release-please bumps Cargo.toml version strings for the bumped first-party crates, a step committed onto the release PR runs:

```bash
cargo update -p cipherbox-core --precise <new-version>
cargo update -p cipherbox-fuse --precise <new-version>
# ... for each bumped crate
```

The `--precise` flag only updates that one crate's `[[package]] version` line in Cargo.lock — no transitive dependency re-resolution. [CITED: doc.rust-lang.org/cargo/commands/cargo-update.html]

**Alternative simpler approach:** `cargo generate-lockfile` regenerates the entire Cargo.lock from scratch. This is safe for first-party version-only bumps (no dep changes), but touches more lines. Use `cargo update -p <crate> --precise <ver>` to minimize diff.

**CI guard (fail release PR if lock is stale):**

```bash
git diff --exit-code Cargo.lock
```

Run this after the update step. If Cargo.lock was already correct, exits 0. If stale (missed a crate), exits non-zero and blocks the release PR. This is the "never merge stale" guarantee.

**Alternative guard:** `cargo update --locked --dry-run` — exits non-zero if the lockfile is inconsistent with Cargo.toml. [CITED: doc.rust-lang.org/cargo/commands/cargo-update.html]

### Current Cargo.lock State

Cargo.lock is currently **in sync** with all crate Cargo.toml versions: [VERIFIED: codebase grep]

```
cipherbox-api-client 0.35.0  (matches crates/api-client/Cargo.toml: 0.35.0)
cipherbox-core       0.5.1   (matches crates/core/Cargo.toml: 0.5.1)
cipherbox-crypto     0.5.0   (matches crates/crypto/Cargo.toml: 0.5.0)
cipherbox-desktop    0.35.0  (matches apps/desktop/src-tauri/Cargo.toml: 0.35.0)
cipherbox-fuse       0.6.1   (matches crates/fuse/Cargo.toml: 0.6.1)
cipherbox-sdk        0.6.0   (matches crates/sdk/Cargo.toml: 0.6.0)
```

The out-of-band sync performed 2026-06-18 (mentioned in todo #13) is already committed. The fix prevents future drift.

### Where to Add the Cargo.lock Update Step

The `release-please.yml` workflow creates the release PR via `googleapis/release-please-action@v5`. The step to update Cargo.lock needs to run AFTER release-please has pushed the version-bumped Cargo.toml files to the release PR branch.

Two viable approaches:
1. **Post-release action in `release-please.yml`:** After the release-please step, if `outputs.releases_created == 'true'` (i.e., a release just merged, not just a PR update), run `cargo update --precise` and commit. This fixes Cargo.lock on `main` after the fact — acceptable but adds a commit to `main` after merge.
2. **PR workflow step on the release PR:** Add a separate workflow triggered by the `chore: release` PR branch push that updates Cargo.lock and commits to the release branch. This keeps the lock update ON the release PR (per D-05 preference).

**Recommended approach 2** (CI guard on the release PR itself). The release-please release PR is identified by its title matching `chore: release v*` (from `release-please-config.json` `pull-request-title-pattern`). A workflow triggered by `pull_request` where the branch starts with `release-please--` can detect this and run the Cargo.lock update.

## #16 — Pin Automation Resilience: Detailed Research

### Failure Mechanism (Verified Against Actual Code)

**Step 1 — Bot commits release targets:** `pr-release-preview.yml` triggers on PR open/sync/reopen/label. It runs `pr-release-preview.js` which computes release targets and writes `release-as` pins into `release-please-config.json`, then the "Commit release-as targets" step commits as:

```
git commit -m "chore(release): set release targets for PR #${PR_NUMBER}"
git push
```

[VERIFIED: codebase read — pr-release-preview.yml lines 42-57]

**Step 2 — Force-push clobber:** If the developer subsequently force-pushes (rebase, amend, `git push --force`) to the same PR branch, the bot's commit is clobbered — it is no longer an ancestor of the branch head. The merge of this PR then never includes the release-target commit.

**Step 3 — cancel-in-progress prevents self-correction:** `pr-release-preview.yml` has:

```yaml
concurrency:
  group: release-preview-${{ github.event.pull_request.number }}
  cancel-in-progress: true
```

[VERIFIED: codebase read — pr-release-preview.yml lines 8-10]

Each new push to the PR branch triggers the workflow. If a developer pushes rapidly (e.g., `git push --force` then a fixup), the previous preview run is cancelled before it can re-commit the release targets. With `cancel-in-progress: true`, only the LAST push's run completes — but if that last push was the force-push that clobbered the bot commit, the workflow never had a chance to fix the clobber.

**Step 4 — Stale satisfied pins (secondary):** The clear logic at `pr-release-preview.js` lines 644-652 only clears a `release-as` that THIS PR added AND was not inherited from `main` (`!packageBumps.has(pkgPath) && !baseReleaseAs[pkgPath]`). Inherited, already-consumed pins persist. [VERIFIED: codebase read — pr-release-preview.js ~644-652]

**NOT adopting:** The auto-clearing of satisfied pins (pins where `release-as <= manifest version`) as the primary fix. Per D-06: this is treating the symptom, not the cause.

### Primary Fix: Fetch+Rebase Discipline

The bot commit (`chore(release): set release targets for PR #N`) must be preserved on the PR branch through any subsequent pushes. This mirrors the existing known pattern documented in project memory: "PR-create triggers a bot release commit; fetch + rebase, never force-push over it."

**Codify in:**
1. **CLAUDE.md** — add a rule under "API Development Workflow" or new section "Release Automation Rules": "When pushing updates to an open PR, always `git fetch && git rebase origin/<branch>` rather than `git push --force`. Force-push WILL clobber the bot's `chore(release): set release targets` commit, causing release targets to be dropped."
2. **Project MEMORY.md** — add a memory entry for this specific pattern (matches the format of the existing "PR-create triggers a bot release commit" entry).
3. **Optional: `--force-with-lease` in workflow git push:** Rename the bot commit step to use `git push --force-with-lease` (already `git push` without force; the push in the preview script is a non-force push of the bot commit itself — this is fine as written).

### Optional Lightweight Safety-Net (Planner Evaluates)

Per D-06: do NOT over-build. Two options:

**Option A — Remove `cancel-in-progress: true`:**

```yaml
concurrency:
  group: release-preview-${{ github.event.pull_request.number }}
  cancel-in-progress: false
```

Effect: when multiple pushes happen in sequence, all runs complete (queued). The final run after a force-push will always re-commit the correct targets. Downside: on a PR with rapid pushes, preview runs queue up and consume runner minutes. For this codebase (infrequent rapid pushes), this is minimal cost. This is the safer option because it self-heals without any discipline requirement.

**Option B — Re-run preview on final pre-merge state:**

Add a `push` trigger on the `release-please--` branch in pr-release-preview.yml (already triggered on `pull_request synchronize`) — this is already covered by the current trigger. No change needed.

**Recommendation to planner:** Implement Option A (`cancel-in-progress: false`) as the minimal safety-net. It's a one-line change, eliminates the failure mode without requiring developer discipline, and has negligible cost. Do not add any pin-clearing logic.

### D-07: Secondary Hygiene

**Path attribution at ~line 298 (`packageBumps`):** The `fileToPackage` function in `pr-release-preview.js` maps changed files to package paths via longest-prefix matching against `release-please-config.json` package keys. Release-please itself does the same path-based attribution independently. These two mechanisms are effectively in sync as long as package paths in `release-please-config.json` are accurate. The current config paths match the actual directory structure. [VERIFIED: codebase read — pr-release-preview.js, release-please-config.json]

No code change is needed for path attribution reconciliation — the implementations are already aligned by design.

**Stale release-as cleanup:** Current state as of research date: [VERIFIED: codebase computation]

| Package          | manifest | release-as | Status         |
| ---------------- | -------- | ---------- | -------------- |
| packages/core    | 0.31.0   | 0.31.0     | STALE (= manifest) |
| packages/crypto  | 0.33.0   | 0.33.0     | STALE (= manifest) |
| crates/core      | 0.5.1    | 0.5.1      | STALE (= manifest) |

All other `release-as` entries are > their manifest version (actively pinned to next target) — these are correct and must NOT be removed.

The 3 stale entries (`packages/core`, `packages/crypto`, `crates/core`) should be deleted from `release-please-config.json`. This is a one-time cleanup. (The todo originally estimated ~8-9 stale entries; several have been consumed by release PRs since the todo was filed.)

## Don't Hand-Roll

| Problem                         | Don't Build                            | Use Instead                                            | Why                                                                        |
| ------------------------------- | -------------------------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------- |
| SHA-pin 111 action refs         | sed/awk scripts or manual editing      | `pinact run`                                           | Requires GitHub API to resolve tag→SHA; hand-editing 111 refs is error-prone |
| Keep pinned SHAs current        | Cron job or manual refresh             | Dependabot github-actions (already configured)          | Dependabot is idiomatic, updates SHA + version comment atomically           |
| Detect unpinned actions in CI   | grep-based lint script                 | `zizmor`                                               | zizmor understands workflow structure; grep misses inline/step-level refs  |
| Cargo.lock crate version update | sed on Cargo.lock                      | `cargo update -p <crate> --precise <ver>`              | cargo's tooling handles lock format correctly; sed can corrupt the lockfile |

## Common Pitfalls

### Pitfall 1: SARIF Mode Makes zizmor Exit 0

**What goes wrong:** Using `zizmorcore/zizmor-action` (the GitHub Action wrapper) emits SARIF. In SARIF mode, zizmor exits 0 even with critical findings.
**Why it happens:** SARIF consumers don't use exit codes; findings go to GitHub Code Scanning tab instead.
**How to avoid:** Use `pip install zizmor && zizmor .github/workflows/` directly in a `run:` step. This uses plain output mode and exits 11-14 on findings.
**Warning signs:** CI job passes despite unpinned actions being present.

### Pitfall 2: pinact Needs GITHUB_TOKEN

**What goes wrong:** `pinact run` silently skips actions it can't resolve, or fails with API errors.
**Why it happens:** pinact queries the GitHub API to resolve tags to SHAs; without a token it hits rate limits immediately.
**How to avoid:** Set `GITHUB_TOKEN` env var when running pinact locally; in CI, it's available automatically.
**Warning signs:** Version comments left as `# <unknown>` or some refs remain as tags.

### Pitfall 3: Dependabot Already Configured — Don't Duplicate

**What goes wrong:** Adding a second `github-actions` block to dependabot.yml causes Dependabot to error or produce duplicate PRs.
**Why it happens:** `.github/dependabot.yml` already has a complete `github-actions` ecosystem entry.
**How to avoid:** Read dependabot.yml first. D-03 is already satisfied. No change needed.
**Warning signs:** Two separate dependabot PRs for the same action on the same day.

### Pitfall 4: cargo-workspace Plugin Breaks Manifest

**What goes wrong:** Adding `"plugins": ["cargo-workspace"]` to `release-please-config.json` causes manifest.json version updates to be skipped.
**Why it happens:** Known bug #2517 in release-please (open as of March 2025).
**How to avoid:** Do NOT add the cargo-workspace plugin. Use the fallback CI-script approach for Cargo.lock updates.
**Warning signs:** After adding the plugin, release PRs no longer update `.release-please-manifest.json` correctly.

### Pitfall 5: Force-Push Over Bot Commit

**What goes wrong:** After `pr-release-preview.yml` commits `chore(release): set release targets`, a force-push drops that commit. The PR merges without release targets, causing release-please to miss the bump.
**Why it happens:** `cancel-in-progress: true` prevents the workflow from self-correcting.
**How to avoid:** Always `git fetch + git rebase origin/<branch>` before pushing. With the optional fix (`cancel-in-progress: false`), the workflow self-heals.
**Warning signs:** The latest commit on a PR branch is NOT the bot's `chore(release):` commit; `release-please-config.json` does not have `release-as` entries for packages that were modified.

### Pitfall 6: Stale release-as Equals Manifest (Latent Trap)

**What goes wrong:** A `release-as` entry exactly equal to the manifest version causes release-please to "release" an already-shipped version → self-comparing changelog (`vX...vX`).
**Why it happens:** Pin was satisfied by a release PR merge but was never cleared (the clear logic only removes pins added by THIS PR, not inherited ones).
**How to avoid:** D-07 one-time cleanup removes the 3 current stale entries. With the clear logic unchanged (not adopting the expanded clearing), this can recur when the next release PR merges without clearing inherited pins. Low risk since the preview bot advances pins to next-release-version on every PR push.
**Warning signs:** release-please changelog has `compare/pkg-vX.Y.Z...pkg-vX.Y.Z` self-link.

## Code Examples

### pinact: Bulk Pin All Actions

```bash
# Run locally or in a one-time CI job; requires GITHUB_TOKEN
GITHUB_TOKEN=$GITHUB_TOKEN pinact run
```

Expected output format per action ref:

```yaml
# Before:
- uses: actions/checkout@v6

# After:
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v6.2.0
```

[CITED: github.com/suzuki-shunsuke/pinact]

### zizmor: Plain CI Gate

```bash
# Install
pip install zizmor

# Run (exits 0 on no findings; exits 11-14 on findings)
GH_TOKEN=$GITHUB_TOKEN zizmor .github/workflows/

# Run without online API (syntactic only, no SHA verification)
zizmor --offline .github/workflows/
```

[CITED: docs.zizmor.sh/usage]

### cargo update: Precise Crate Version

```bash
# After release-please bumps crates/core/Cargo.toml to 0.6.0:
cargo update -p cipherbox-core --precise 0.6.0

# Guard: fails if lockfile is still stale
git diff --exit-code Cargo.lock
```

[CITED: doc.rust-lang.org/cargo/commands/cargo-update.html]

### pr-release-preview.yml: concurrency Safety-Net

```yaml
# Change from:
concurrency:
  group: release-preview-${{ github.event.pull_request.number }}
  cancel-in-progress: true

# Change to (Option A safety-net):
concurrency:
  group: release-preview-${{ github.event.pull_request.number }}
  cancel-in-progress: false
```

[VERIFIED: codebase read — pr-release-preview.yml]

### release-please-config.json: Remove Stale Pins

```json
// Remove these three release-as entries (they equal their manifest version):
// "packages/core": { "release-as": "0.31.0" }  <- manifest is 0.31.0
// "packages/crypto": { "release-as": "0.33.0" }  <- manifest is 0.33.0
// "crates/core": { "release-as": "0.5.1" }  <- manifest is 0.5.1
```

[VERIFIED: codebase computation]

## TDD Applicability

| Work Item                                              | Type    | Rationale                                                              |
| ------------------------------------------------------ | ------- | ---------------------------------------------------------------------- |
| pinact run (bulk SHA pin)                              | execute | Config/YAML change; verified by re-running CI                          |
| job-level `permissions:` blocks                        | execute | Config/YAML; verified by zizmor passing                                |
| zizmor CI gate workflow                                | execute | CI YAML; verified by zizmor running and failing on synthetic unpinned ref |
| Dependabot — already configured                        | execute | No change needed                                                       |
| Cargo.lock update step in release-please.yml           | execute | CI YAML + shell commands; verified by CI guard diff check               |
| CI guard `git diff --exit-code Cargo.lock`             | tdd     | Could write a Node.js test script that synthesizes a stale Cargo.lock and verifies the guard detects it; low value — simpler to verify in integration |
| `cancel-in-progress: false` in pr-release-preview.yml | execute | One-line YAML change                                                   |
| Stale release-as cleanup                               | execute | One-time JSON edit of release-please-config.json                       |
| CLAUDE.md / MEMORY.md discipline documentation         | execute | Docs edit; no test                                                     |

**Summary:** All items are `type: execute` (CI config, YAML, JSON, docs). No logic-heavy code changes that would benefit from TDD in this phase.

## Validation Architecture

> `workflow.nyquist_validation: true` in `.planning/config.json` — this section is required.

### Test Framework

| Property           | Value                                                |
| ------------------ | ---------------------------------------------------- |
| Framework          | None (no app unit tests — pure CI/config changes)    |
| Config file        | N/A — no test framework config                       |
| Quick run command  | `zizmor --offline .github/workflows/`                |
| Full suite command | `GH_TOKEN=$TOKEN zizmor .github/workflows/`          |

### Phase Requirements → Test Map

| Req ID  | Behavior                                       | Test Type    | Automated Command                                         | File Exists? |
| ------- | ---------------------------------------------- | ------------ | --------------------------------------------------------- | ------------ |
| HARD-04 | No third-party action is tag-pinned            | static-check | `pinact run -check` (exits non-zero if any tag ref found) | N/A          |
| HARD-04 | zizmor unpinned-uses passes                    | static-check | `zizmor --offline .github/workflows/`                     | N/A          |
| HARD-04 | Cargo.lock matches Cargo.toml post-release     | manual/CI    | `git diff --exit-code Cargo.lock` in release-please.yml   | N/A          |
| HARD-04 | No stale release-as == manifest                | manual       | `node -e "..."` script to compare config vs manifest      | ❌ Wave 0   |

### Per-Item Verification Strategy

**#6 SHA Pinning:**
- After `pinact run`: run `pinact run -check` — must exit 0.
- After zizmor gate added: run `zizmor --offline .github/workflows/` — must exit 0 for `unpinned-uses`; `excessive-permissions` also addressed.
- Smoke check: push a dummy PR; verify all CI jobs still pass (SHA resolves to same version — behavior unchanged).

**#13 Cargo.lock Sync:**
- After adding CI step to release PR workflow: artificially bump a crate version in Cargo.toml on a test branch and verify the CI guard detects the stale lock.
- After the full fix: verify that the next actual release PR includes an updated Cargo.lock diff.

**#16 Pin Automation:**
- After `cancel-in-progress: false`: open a test PR, push a fixup commit immediately after, verify both preview runs complete and the final bot commit is present.
- After CLAUDE.md/MEMORY.md updates: no automated test — convention enforcement.
- After stale pin cleanup: run the comparison script to confirm no release-as entries equal their manifest version.

### Sampling Rate

- **Per task commit:** `pinact run -check && zizmor --offline .github/workflows/` (both fast, offline, no API)
- **Per wave merge:** Full `GH_TOKEN=$TOKEN zizmor .github/workflows/` + `pinact run -verify-comment`
- **Phase gate:** All CI jobs pass on the phase PR; no zizmor findings; Cargo.lock verified clean

### Wave 0 Gaps

- [ ] `.planning/scripts/check-stale-release-as.js` — one-line comparison of release-please-config.json vs manifest for stale pins (covers HARD-04 manual check)

_(The primary test infrastructure is the CI itself — zizmor and pinact are the "test suite" for this phase)_

## State of the Art

| Old Approach                               | Current Approach               | When Changed  | Impact                                           |
| ------------------------------------------ | ------------------------------ | ------------- | ------------------------------------------------ |
| Mutable action tags (`@v6`, `@v0`)         | SHA-pinned with version comment| Phase 53      | Eliminates tag-hijacking supply-chain risk       |
| No Cargo.lock update in release workflow   | `cargo update --precise` on release PR | Phase 53 | `main` is always clean-on-first-cargo post-release |
| `cancel-in-progress: true` (fragile)       | `cancel-in-progress: false`    | Phase 53      | Preview bot self-heals after force-push          |
| Stale `release-as` = manifest pins in config | Cleaned up                   | Phase 53      | Eliminates self-compare changelog loop           |

**Deprecated/outdated:**

- `cargo-workspace` plugin for Cargo.lock sync: do NOT enable — has open bug #2517 (March 2025) causing manifest.json skips.
- `zizmorcore/zizmor-action` (SARIF mode): not suitable as a hard CI gate; use CLI plain mode.

## Assumptions Log

| #   | Claim                                                                                            | Section              | Risk if Wrong                                             |
| --- | ------------------------------------------------------------------------------------------------ | -------------------- | --------------------------------------------------------- |
| A1  | `ratchet` has no first-class GH Action wrapper and is less actively maintained than pinact       | Standard Stack       | Could use ratchet instead — no material difference in outcome |
| A2  | `cargo-linux` job's specific zizmor finding was `excessive-permissions` per CodeRabbit on #487  | Permissions Audit    | Other jobs may also be flagged; zizmor must be run to get exact list |
| A3  | zizmor's default run (no flags) catches both `unpinned-uses` and `excessive-permissions`        | zizmor CI Gate       | May need `--filter` flags if other findings cause noise   |
| A4  | `cancel-in-progress: false` has negligible cost for this codebase's PR cadence                  | #16 Safety-Net       | High PR cadence could queue many preview runs; monitor    |

**If this table is empty:** All claims were verified. It is not empty — A1 and A2 are assumed.

## Open Questions (RESOLVED)

All open questions are resolved for planning purposes.

1. **D-05: Which Cargo.lock path applies?**
   - **RESOLVED:** Fallback path. The cargo-workspace plugin has an open bug (#2517, March 2025) that causes it to skip Cargo.lock and manifest updates in monorepo mode. Use `cargo update -p <crate> --precise <ver>` committed onto the release PR, plus `git diff --exit-code Cargo.lock` CI guard.

2. **How many stale release-as entries need cleanup (D-07)?**
   - **RESOLVED:** 3 entries — `packages/core`, `packages/crypto`, `crates/core`. All others are actively pinned above manifest (correct). The original todo estimated ~8-9 but several release PRs have merged since.

3. **Is .github/dependabot.yml github-actions block already present?**
   - **RESOLVED:** YES. `.github/dependabot.yml` already has a complete `github-actions` entry with correct settings. D-03 requires no change.

4. **Which zizmor jobs lack `permissions:` blocks?**
   - **RESOLVED:** Workflows with NO permissions at all: `desktop-e2e.yml`, `web-e2e.yml`, `load-test.yml`, `release-gate.yml`, `tag-staging.yml` (partial), `ci-e2e.yml` (partial). In `ci.yml`, only `changes` job has permissions; 11 other jobs do not.

5. **Is the optional safety-net (cancel-in-progress: false) worth implementing?**
   - **RESOLVED:** Yes — it is a one-line change that eliminates the primary failure mode without requiring developer discipline. Recommend implementing as part of the phase.

## Environment Availability

| Dependency        | Required By              | Available | Version    | Fallback                    |
| ----------------- | ------------------------ | --------- | ---------- | --------------------------- |
| pinact CLI        | SHA pinning (D-01)       | ✗ local   | —          | Install via Homebrew/go or run in CI |
| zizmor CLI        | CI gate (D-04)           | ✗ local   | —          | Install via `pip install zizmor` or `cargo install zizmor` |
| cargo             | Cargo.lock guard (D-05)  | ✓ in CI   | bundled    | —                           |
| GitHub Actions    | All workflow changes      | ✓         | —          | —                           |

**Notes:** `pinact` and `zizmor` do not need to be installed locally — they run in GitHub Actions CI. The bulk pinning (`pinact run`) is a one-time operation that can be run in a CI job or locally with the right GitHub token.

## Security Domain

### Applicable ASVS Categories

| ASVS Category         | Applies | Standard Control                                         |
| --------------------- | ------- | -------------------------------------------------------- |
| V2 Authentication     | no      | N/A — CI config change                                   |
| V3 Session Management | no      | N/A                                                      |
| V4 Access Control     | yes     | Least-privilege `permissions:` blocks per job — no job runs with default write token |
| V5 Input Validation   | no      | N/A                                                      |
| V6 Cryptography       | no      | N/A                                                      |
| V10 Malicious Code    | yes     | SHA-pinned actions prevent supply-chain injection; zizmor gate prevents regression |

### Known Threat Patterns for GitHub Actions Supply Chain

| Pattern                                | STRIDE        | Standard Mitigation                                                   |
| -------------------------------------- | ------------- | --------------------------------------------------------------------- |
| Mutable tag hijacking (actions)         | Tampering     | SHA-pin all third-party actions; Dependabot keeps SHAs current        |
| Excessive CI token permissions          | Elevation     | Job-level `permissions:` with `contents: read` minimum               |
| Force-push clobbering bot commit       | Tampering     | fetch+rebase discipline + `cancel-in-progress: false` self-healing    |
| Stale release-as loop                  | Tampering     | D-07 cleanup + D-06 primary fix prevents re-accumulation              |

## Project Constraints (from CLAUDE.md)

- Implementation commits use `chore(ci):` NOT `feat`/`fix` for this phase. [VERIFIED: CLAUDE.md]
- All `chore(ci):` commits must follow Conventional Commits format — no parenthesized text in subject line. [VERIFIED: CLAUDE.md]
- Branch naming: `feat/release-supply-chain-engineering` per git branching strategy. [VERIFIED: CLAUDE.md]
- Pre-commit hook runs markdownlint on `.md` files; `.planning/` is excluded. [VERIFIED: project MEMORY.md]
- `pnpm api:generate` MUST NOT be run — this is a planning-only/CI phase with no app code changes. [VERIFIED: CLAUDE.md — only required when API endpoints/DTOs/controllers change]
- All TypeScript should use string literals over enums (N/A — no TS changes in this phase). [VERIFIED: global CLAUDE.md]

## Sources

### Primary (HIGH confidence)

- [VERIFIED: codebase grep] — `.github/workflows/*.yml` files: action inventory, permissions audit, concurrency blocks
- [VERIFIED: codebase grep] — `.github/dependabot.yml`: github-actions block already present
- [VERIFIED: codebase grep] — `release-please-config.json`, `.release-please-manifest.json`: stale pin analysis, package structure
- [VERIFIED: codebase grep] — `.github/scripts/pr-release-preview.js`: clear logic lines 644-652, packageBumps line 298, fileToPackage

### Secondary (MEDIUM confidence)

- [CITED: github.com/suzuki-shunsuke/pinact] — pinact CLI, `pinact run` invocation, version comment support
- [CITED: docs.zizmor.sh/audits, docs.zizmor.sh/usage, docs.zizmor.sh/integrations] — zizmor audit rules, exit codes, CLI usage
- [CITED: github.com/googleapis/release-please/issues/2517] — cargo-workspace plugin bug (open March 2025)
- [CITED: github.com/googleapis/release-please/pull/1260] — original Cargo.lock fix (Feb 2022, insufficient for monorepo mode)
- [CITED: doc.rust-lang.org/cargo/commands/cargo-update.html] — `cargo update --precise` behavior
- [CITED: github.blog/changelog/2022-10-31-dependabot-now-updates-comments-in-github-actions-workflows-referencing-action-versions] — Dependabot updates SHA + version comment

### Tertiary (LOW confidence / ASSUMED)

- [ASSUMED] — ratchet has no first-class GH Action wrapper and is less maintained than pinact
- [ASSUMED] — specific zizmor finding description from PR #487 CodeRabbit scan (cargo-linux excessive-permissions)

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — pinact/zizmor are well-documented; cargo update --precise is official cargo behavior
- Architecture: HIGH — all verified against actual codebase code
- Pitfalls: HIGH — pitfall 4 (cargo-workspace bug) is confirmed by open GitHub issue; others from codebase reading

**Research date:** 2026-06-19
**Valid until:** 2026-07-19 (stable tooling; cargo-workspace bug status may change on googleapis/release-please)
