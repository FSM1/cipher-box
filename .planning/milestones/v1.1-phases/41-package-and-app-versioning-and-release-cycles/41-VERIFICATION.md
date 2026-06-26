---
phase: 41-package-and-app-versioning-and-release-cycles
verified: 2026-03-31T22:15:00Z
status: passed
score: 13/13 must-haves verified
re_verification: false
---

# Phase 41: Package and App Versioning and Release Cycles — Verification Report

**Phase Goal:** All monorepo components (apps, JS packages, Rust crates) version independently via conventional commit analysis at PR time, with Release Please consuming label-derived version targets for precise per-package releases.

**Verified:** 2026-03-31T22:15:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| #   | Truth                                                                                           | Status   | Evidence                                                                                                                                                                                                                             |
| --- | ----------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | All 15 components have entries in release-please-config.json                                    | VERIFIED | Node check: 15 package entries confirmed. All 4 apps (api, web, desktop, tee-worker) added alongside existing 11 entries.                                                                                                            |
| 2   | Root package no longer cascades version to other packages via extra-files                       | VERIFIED | `cfg.packages['.'].hasOwnProperty('extra-files')` returns `false`. Extra-files removed.                                                                                                                                              |
| 3   | API lock group (apps/api, packages/api-client, crates/api-client) handled as unit               | VERIFIED | Both `pr-release-preview.js` and `post-merge-release.js` contain `LOCK_GROUP` / `LABEL_TO_PATHS.api = ['apps/api', 'packages/api-client', 'crates/api-client']`.                                                                     |
| 4   | 61 pre-created release labels script exists and produces correct count                          | VERIFIED | `.github/scripts/create-release-labels.sh --dry-run` outputs "Summary: 61 created, 0 updated, 0 failed / Total expected: 61 labels".                                                                                                 |
| 5   | PR with conventional commits auto-gets release labels via analysis script                       | VERIFIED | `.github/scripts/pr-release-preview.js` (692 lines, valid JS) reads release-please-config.json, parses conventional commits, maps files to packages, applies `release:{component}:{type}` labels.                                    |
| 6   | PR cascade detection auto-labels dependents                                                     | VERIFIED | Script contains `JS_DEPS` and `RUST_DEPS` hardcoded dependency graphs with iterative cascade propagation (described at line 400 of script).                                                                                          |
| 7   | Docs/config/test-only changes are auto-exempted                                                 | VERIFIED | Script maps `build, test, docs, style, chore, ci, revert` commit types to no bump; `release:none` label acts as escape hatch.                                                                                                        |
| 8   | After PR merge, release-as written to release-please-config.json                                | VERIFIED | `.github/scripts/post-merge-release.js` has `config.packages[pkgPath]['release-as'] = targetVersion` (line 302) and `writeFileSync` call.                                                                                            |
| 9   | Multiple concurrent PRs: highest bump wins per package                                          | VERIFIED | `versionDelta` comparison logic in post-merge script (weighted scoring major=10000, minor=100, patch=1) with "Keeping existing / Overriding existing" log messages.                                                                  |
| 10  | Staging deploys triggered by date-based tags (staging-YYYYMMDD-release-N)                       | VERIFIED | `tag-staging.yml` uses `date -u +%Y%m%d` and constructs `staging-${DATE}-release-${N}`. No `release_tag` input remains. `deploy-staging.yml` trigger broadened to `staging-*`.                                                       |
| 11  | Docker images triple-tagged with component version, latest-staging, and deploy tag              | VERIFIED | `deploy-staging.yml` API image uses `steps.versions.outputs.api`, `latest-staging`, and `DEPLOY_TAG`. TEE image same pattern.                                                                                                        |
| 12  | Desktop release workflow triggers on cipherbox-desktop-v\* tags and publishes updater JSON      | VERIFIED | `.github/workflows/desktop-release.yml` triggers on `cipherbox-desktop-v*`, builds 3 platforms (macOS, Windows, ubuntu-22.04), all use `includeUpdaterJson: true`.                                                                   |
| 13  | RP configured for batched releases; desktop release marked as GitHub "latest" for Tauri updater | VERIFIED | `release-please-config.json` has `"separate-pull-requests": false`. `release-please.yml` un-marks root release with `--latest=false`. `desktop-release.yml` has `mark-latest` job running `gh release edit "$DESKTOP_TAG" --latest`. |

**Score:** 13/13 truths verified

---

## Required Artifacts

### Plan 01 Artifacts

| Artifact                                   | Expected                                                             | Status   | Details                                                                                                                                                 |
| ------------------------------------------ | -------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `release-please-config.json`               | 15-package config, no root extra-files, desktop extra-files retained | VERIFIED | 15 packages confirmed; root has no extra-files; desktop has `extra-files: [apps/desktop/src-tauri/tauri.conf.json, apps/desktop/src-tauri/Cargo.toml]`. |
| `.release-please-manifest.json`            | 15-entry version manifest with 4 new app versions                    | VERIFIED | `apps/api: 0.35.0`, `apps/web: 0.35.0`, `apps/desktop: 0.35.0`, `apps/tee-worker: 0.31.1` all present.                                                  |
| `.github/scripts/create-release-labels.sh` | Label creation script, executable, 61 labels                         | VERIFIED | File is executable. Dry-run outputs "Total expected: 61 labels". Contains all 12 components × 5 types + release:none.                                   |

### Plan 02 Artifacts

| Artifact                                   | Expected                                   | Status   | Details                                                                                                                                                                                                                                                                     |
| ------------------------------------------ | ------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/pr-release-preview.yml` | Triggers on PR events, correct permissions | VERIFIED | Triggers on `pull_request` to main with `opened, synchronize, reopened, labeled, unlabeled`. Permissions `contents: read, pull-requests: write`. Skips release-please PRs. Valid YAML.                                                                                      |
| `.github/scripts/pr-release-preview.js`    | Full commit analysis pipeline              | VERIFIED | 692 lines, valid JS. Contains: conventional commit regex, RP config read, API lock group, JS_DEPS/RUST_DEPS cascade, PATH_TO_LABEL, monotonic handling, release:none escape, PR comment marker `<!-- release-preview -->`, `core.setFailed()` for non-conventional commits. |

### Plan 03 Artifacts

| Artifact                                   | Expected                                    | Status   | Details                                                                                                                                                                                                                         |
| ------------------------------------------ | ------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/post-merge-release.yml` | Pushes to main, concurrency, App token      | VERIFIED | Triggers on `push: branches: [main]`. Concurrency group `post-merge-release` with `cancel-in-progress: false`. Uses `create-github-app-token@v3`. Skip conditions for RP and own commits. Valid YAML.                           |
| `.github/scripts/post-merge-release.js`    | Label-to-version compute + release-as write | VERIFIED | 357 lines, valid JS. Contains: `listPullRequestsAssociatedWithCommit`, `LABEL_TO_PATHS`, `bumpVersion(current, bumpType, isMonotonic)`, `writeFileSync` for release-please-config, `release-please--` skip, monotonic handling. |

### Plan 04 Artifacts

| Artifact                               | Expected                                | Status   | Details                                                                                                                                                                                                   |
| -------------------------------------- | --------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/deploy-staging.yml` | New tag pattern, triple Docker tags     | VERIFIED | Tag trigger is `staging-*`. API and TEE images tagged with `steps.versions.outputs.api/tee`, `latest-staging`, and `DEPLOY_TAG`. `API_VERSION` and `TEE_VERSION` written to `.env.staging`.               |
| `.github/workflows/tag-staging.yml`    | Date-based format, no release_tag input | VERIFIED | `workflow_dispatch` with optional description only. `date -u +%Y%m%d` used to build tag. Sequential counter per date. No `release_tag` input found. Calls `deploy-staging.yml` with `staging_tag` output. |

### Plan 05 Artifacts

| Artifact                                | Expected                                                                   | Status   | Details                                                                                                                                                                                                                                            |
| --------------------------------------- | -------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `release-please-config.json`            | `separate-pull-requests: false`, desktop component tag                     | VERIFIED | Top-level `"separate-pull-requests": false` present. Desktop has `"component": "cipherbox-desktop"` and `"include-component-in-tag": true`.                                                                                                        |
| `.github/workflows/release-please.yml`  | `releases_created` output, step summary, `--latest=false`                  | VERIFIED | Line 16: `releases_created` output. Lines 36-39: `GITHUB_STEP_SUMMARY` logging. Line 50: `gh release edit "$ROOT_TAG" --latest=false`.                                                                                                             |
| `.github/workflows/desktop-release.yml` | Triggers on `cipherbox-desktop-v*`, 3 platforms, updater JSON, mark-latest | VERIFIED | Tag trigger `cipherbox-desktop-v*`. Jobs: `build-desktop-macos` (macos-latest), `build-desktop-windows` (windows-latest), `build-desktop-linux` (ubuntu-22.04). All three use `includeUpdaterJson: true`. `mark-latest` job runs after all builds. |

---

## Key Link Verification

| From                                       | To                                      | Via                                                            | Status   | Details                                                                                                                                             |
| ------------------------------------------ | --------------------------------------- | -------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `release-please-config.json`               | `.release-please-manifest.json`         | Package path keys must match between config and manifest       | VERIFIED | Both have identical 15 package paths.                                                                                                               |
| `.github/scripts/pr-release-preview.js`    | `release-please-config.json`            | Reads package paths as file-to-package mapping                 | VERIFIED | Line 119: `const configPath = path.join(process.cwd(), 'release-please-config.json')`.                                                              |
| `.github/scripts/pr-release-preview.js`    | GitHub PR commits API                   | `pulls/{pr}/commits` for commit analysis                       | VERIFIED | Line 259: `'GET /repos/{owner}/{repo}/pulls/{pull_number}/commits'`.                                                                                |
| `.github/scripts/post-merge-release.js`    | `release-please-config.json`            | Writes `release-as` entries                                    | VERIFIED | Line 302: `config.packages[pkgPath]['release-as'] = targetVersion`. `writeFileSync` confirmed.                                                      |
| `.github/scripts/post-merge-release.js`    | `.release-please-manifest.json`         | Reads current versions for bump computation                    | VERIFIED | Lines 254-257: reads both config and manifest. Line 271: `const currentVersion = manifest[pkgPath]`.                                                |
| `.github/workflows/post-merge-release.yml` | `.github/workflows/release-please.yml`  | Post-merge commit triggers RP workflow                         | VERIFIED | Both trigger on `push: branches: [main]`. Post-merge uses App token so its commits trigger RP.                                                      |
| `.github/workflows/tag-staging.yml`        | `.github/workflows/deploy-staging.yml`  | Creates tag that triggers deploy                               | VERIFIED | Line 77 of tag-staging: `uses: ./.github/workflows/deploy-staging.yml` (direct call with `staging_tag` output).                                     |
| `.github/workflows/release-please.yml`     | `.github/workflows/desktop-release.yml` | RP creates `cipherbox-desktop-v*` tag triggering desktop build | VERIFIED | desktop-release.yml trigger is `push: tags: ['cipherbox-desktop-v*']`, which RP creates from `"include-component-in-tag": true` on desktop package. |

---

## Data-Flow Trace (Level 4)

Phase 41 produces CI/CD workflows and configuration files — no dynamic data rendering components. Level 4 trace is not applicable (no components that render data from state/props/queries).

**Step 7b Behavioral Spot-Checks:**

| Behavior                      | Check                                                                                                                   | Result                      | Status |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------ |
| 15 packages in RP config      | `node -e "const c=require('./release-please-config.json'); console.log(Object.keys(c.packages).length)"`                | `15`                        | PASS   |
| 15 packages in manifest       | `node -e "const m=require('./.release-please-manifest.json'); console.log(Object.keys(m).length)"`                      | `15`                        | PASS   |
| Root extra-files removed      | `node -e "const c=require('./release-please-config.json'); console.log(c.packages['.'].hasOwnProperty('extra-files'))"` | `false`                     | PASS   |
| Label script 61 labels        | `.github/scripts/create-release-labels.sh --dry-run \| tail -1`                                                         | `Total expected: 61 labels` | PASS   |
| PR script is valid JS         | `node --check .github/scripts/pr-release-preview.js`                                                                    | `exit 0`                    | PASS   |
| Post-merge script is valid JS | `node --check .github/scripts/post-merge-release.js`                                                                    | `exit 0`                    | PASS   |
| All workflow YAML valid       | `python3 -c "import yaml; yaml.safe_load(...)"` for all 4 workflows                                                     | `VALID YAML` for all        | PASS   |
| Docker latest-staging tag     | `grep -c 'latest-staging' .github/workflows/deploy-staging.yml`                                                         | `2` (API + TEE)             | PASS   |
| Desktop updater JSON          | `grep -c 'includeUpdaterJson' .github/workflows/desktop-release.yml`                                                    | `3` (all platforms)         | PASS   |
| Batched releases              | `node -e "const c=require('./release-please-config.json'); console.log(c['separate-pull-requests'])"`                   | `false`                     | PASS   |

---

## Requirements Coverage

The requirement IDs D-01 through D-40 are Phase 41's own design decisions defined in `41-CONTEXT.md`, not entries in `.planning/REQUIREMENTS.md`. The main REQUIREMENTS.md does not list D-series requirements and has no Phase 41 traceability entries. This is expected — Phase 41 is a post-milestone infrastructure phase operating under its own scoped decision set.

All 40 decisions (D-01 through D-40) are accounted for across the 5 plans:

| Requirements Block                                            | Plan    | Status    | Evidence                                                                                                                                                                                                               |
| ------------------------------------------------------------- | ------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D-04 through D-14, D-20                                       | Plan 01 | SATISFIED | RP config has 15 independent packages; root extra-files removed; label script with 61 labels.                                                                                                                          |
| D-01, D-15 through D-19, D-21 through D-24, D-37 through D-40 | Plan 02 | SATISFIED | `pr-release-preview.js` implements commit analysis, file-to-package mapping, cascade detection, label application, CI enforcement, release:none escape.                                                                |
| D-02, D-03, D-25 through D-30                                 | Plan 03 | SATISFIED | `post-merge-release.js` reads labels, computes versions, writes release-as; concurrency serialization in workflow. D-30 (RP clears release-as) is inherent RP behavior — noted in plan as integration-time validation. |
| D-34 through D-36                                             | Plan 04 | SATISFIED | `deploy-staging.yml` uses `staging-*` trigger and triple Docker tags; `tag-staging.yml` uses date-based format.                                                                                                        |
| D-31 through D-33                                             | Plan 05 | SATISFIED | `separate-pull-requests: false` in RP config; desktop-release workflow with updater JSON; latest-flag management.                                                                                                      |

**Orphaned requirements:** None. All D-01 through D-40 are covered by plans 01-05.

---

## Anti-Patterns Found

| File | Line | Pattern                                                   | Severity | Impact |
| ---- | ---- | --------------------------------------------------------- | -------- | ------ |
| —    | —    | No TODO/FIXME/PLACEHOLDER found in any new/modified files | —        | None   |

Anti-pattern scan on all new/modified files returned zero hits for TODO, FIXME, XXX, HACK, PLACEHOLDER, "not implemented", "coming soon" patterns.

**Legitimate notes (NOT blockers):**

- D-30 validation (RP clears release-as on release PR merge) is explicitly noted in Plan 03 as "verify during first real release cycle". This is an architectural property of Release Please, not a stub — no code needed to implement it.
- `release-please.yml` un-marks root release as latest conditionally (`steps.release.outputs['tag_name']` — will be empty for non-root releases). The `|| true` guard prevents failures. This is an acceptable edge case.

---

## Human Verification Required

### 1. First Release Cycle Integration Test

**Test:** Merge a PR with conventional commits touching e.g. `packages/core/` and `apps/api/`. Verify:

1. `pr-release-preview.yml` fires and auto-applies `release:core:feat` and `release:api:feat` labels.
2. A cascade label appears for `release:sdk-core:fix` (since sdk-core depends on core).
3. PR comment contains "Release Preview" table.
4. After merging, `post-merge-release.yml` fires and adds `"release-as"` entries to `release-please-config.json` on main.
5. RP's next run creates a release PR with the correct target versions.
6. When RP release PR merges, `release-as` entries are removed from the config (D-30).

**Expected:** Full pipeline completes end-to-end without manual intervention.
**Why human:** Requires an actual GitHub PR with the App token secrets configured — cannot simulate GitHub Actions environment locally.

### 2. Desktop Release Pipeline

**Test:** After RP creates a `cipherbox-desktop-vX.Y.Z` tag, verify:

1. `desktop-release.yml` triggers automatically.
2. All three platform builds complete.
3. `latest.json` appears as a release asset on the desktop-tagged GitHub Release.
4. `/releases/latest/download/latest.json` URL resolves to the desktop release's `latest.json`.
5. Tauri updater in a running desktop app detects and offers the update.

**Expected:** Tauri auto-updater finds the new version and prompts for update.
**Why human:** Requires a real release cycle plus a running desktop app to verify updater resolution.

### 3. Staging Deployment with New Tag Format

**Test:** Manually trigger `tag-staging.yml` (workflow_dispatch). Verify:

1. A tag like `staging-20260331-release-1` is created on main HEAD.
2. `deploy-staging.yml` triggers on this tag (not just `staging-v*`).
3. Docker images are pushed with three tags: component version, `latest-staging`, and the staging tag.

**Expected:** Staging deployment succeeds with date-based tag format; Docker registry shows triple-tagged images.
**Why human:** Requires triggering the actual staging deployment with real Docker push credentials.

---

## Gaps Summary

No gaps. All 13 observable truths are verified, all artifacts exist and are substantive, all key links are wired. The phase goal is fully achieved at the code/configuration level. Three human verification items remain for runtime/integration validation, which cannot be automated programmatically without the live GitHub Actions environment.

---

_Verified: 2026-03-31T22:15:00Z_
_Verifier: Claude (gsd-verifier)_
