# Phase 41: Package and App Versioning and Release Cycles - Research

**Date:** 2026-03-31
**Status:** Complete

## Current State Analysis

### Release Please Configuration

Current `release-please-config.json` has 11 package entries:

| Path                  | Component               | Release Type |
| --------------------- | ----------------------- | ------------ |
| `.` (root)            | `cipher-box`            | node         |
| `packages/core`       | `@cipherbox/core`       | node         |
| `packages/crypto`     | `@cipherbox/crypto`     | node         |
| `packages/api-client` | `@cipherbox/api-client` | node         |
| `packages/sdk-core`   | `@cipherbox/sdk-core`   | node         |
| `packages/sdk`        | `@cipherbox/sdk`        | node         |
| `crates/crypto`       | `cipherbox-crypto`      | rust         |
| `crates/core`         | `cipherbox-core`        | rust         |
| `crates/api-client`   | `cipherbox-api-client`  | rust         |
| `crates/fuse`         | `cipherbox-fuse`        | rust         |
| `crates/sdk`          | `cipherbox-sdk`         | rust         |

**Missing from RP config (must add):**

- `apps/api` — API server (not currently an RP package)
- `apps/web` — Web app (not currently an RP package)
- `apps/desktop` — Desktop app (not currently an RP package)
- `tee-worker` — TEE worker (not currently an RP package; referenced as `apps/tee-worker` in deploy, but lives at `tee-worker/` root level)

**Current root package problem:** The root `.` entry uses `extra-files` to cascade its version to ALL other package.json, Cargo.toml, and tauri.conf.json files — this is the "root version cascades to everything" model being replaced.

### Current Version Manifest

All packages currently at the same version (0.35.0 for root, apps, desktop) or independently versioned SDK packages (0.30.0-0.34.0) and Rust crates (0.4.0-0.5.0). The manifest already tracks per-package versions.

### Dependency Graphs

**JavaScript workspace dependencies (production only):**

```
@cipherbox/crypto          (leaf - no internal deps)
@cipherbox/core            -> crypto
@cipherbox/api-client      (leaf - generated, no internal deps)
@cipherbox/sdk-core        -> api-client, core, crypto
@cipherbox/sdk             -> api-client, core, crypto, sdk-core
@cipherbox/web             -> api-client, core, crypto, sdk, sdk-core
@cipherbox/desktop         -> crypto (TS side only; Rust side has full crate graph)
cipherbox-tee-worker       -> core, crypto, sdk-core
```

**Rust workspace dependencies:**

```
cipherbox-crypto           (leaf)
cipherbox-core             -> crypto
cipherbox-api-client       (leaf - hand-structured, no internal deps)
cipherbox-fuse             -> api-client, core, crypto
cipherbox-sdk              -> api-client, core, crypto
cipherbox-desktop          -> api-client, core, crypto, fuse, sdk
```

### Workflow Inventory

| Workflow             | Trigger          | Relevance                                                                 |
| -------------------- | ---------------- | ------------------------------------------------------------------------- |
| `release-please.yml` | push to main     | Core — runs RP action, needs no changes to workflow itself                |
| `release-gate.yml`   | PR to main       | Has path-based change detection pattern — reusable for PR release preview |
| `deploy-staging.yml` | tag `staging-v*` | Tag pattern must change to `staging-*` for date-based format              |
| `ci.yml`             | PR events        | Not affected                                                              |
| `ci-e2e.yml`         | push to main     | Not affected                                                              |
| `pr-title.yml`       | PR events        | Not affected                                                              |
| `tag-staging.yml`    | unknown          | May need tag pattern update                                               |

### GitHub App Token Pattern

`release-please.yml` uses a GitHub App token (not `GITHUB_TOKEN`) to allow RP commits to trigger other workflows. The post-merge action that writes `release-as` to config also needs to commit to main — it must use this same app token pattern.

### Tauri Auto-Updater

`tauri.conf.json` version: `0.35.0` (currently cascaded from root). `deploy-staging.yml` uses `tauri-action@v0` with:

- `tagName` from the staging tag
- `includeUpdaterJson: true` — publishes `latest.json` as release asset
- Desktop release is NOT marked as prerelease (updater resolves `/releases/latest/`)

**Desktop-specific release tag:** Decision D-33 requires `cipherbox-desktop-vX.Y` tags for the Tauri updater. This means RP must create component-specific tags for desktop alongside the batched release.

### Staging Tag Pattern

Current: `staging-v*` (e.g., `staging-v0.26.0-rc-1`)
Target (D-35): `staging-YYYYMMDD-release-N` (e.g., `staging-20260331-release-1`)

The `deploy-staging.yml` trigger `on.push.tags: ['staging-v*']` must change to `on.push.tags: ['staging-*']` to match the new format. The `tag-staging.yml` workflow (if it creates tags) also needs updating.

## Technical Deep Dive

### Release-As Mechanism in Release Please

RP's `release-as` is a per-package config option in `release-please-config.json`. When set, RP creates the release PR targeting exactly that version, ignoring its own commit analysis. After the release PR is merged, the `release-as` is consumed (should be removed).

**Key finding:** `release-as` is set in the config file, not the manifest. The post-merge action writes to `release-please-config.json` packages entries. Example:

```json
{
  "packages": {
    "packages/core": {
      "release-type": "node",
      "component": "@cipherbox/core",
      "release-as": "0.31.0"
    }
  }
}
```

RP reads this on next run, creates a release PR bumping `@cipherbox/core` to `0.31.0`, and the release PR itself should remove the `release-as` directive.

**Important:** RP's manifest mode processes ALL packages in a single run. When the post-merge action sets `release-as` for 3 packages, RP will create/update one release PR covering all of them.

### PR Commit Analysis Strategy

The PR-time action needs to:

1. **Get PR commits** via `GET /repos/{owner}/{repo}/pulls/{pull_number}/commits` (paginated, max 250 commits)
2. **Parse conventional commit types** from each commit message (type, scope, breaking indicator)
3. **Map changed files to packages** using `release-please-config.json` paths
4. **Determine bump per package** — highest bump wins (breaking > feat > fix/perf/refactor)
5. **Auto-add labels** via `POST /repos/{owner}/{repo}/issues/{pull_number}/labels`

**File-to-package mapping:** Read `release-please-config.json` `packages` keys as path prefixes. For each changed file in each commit, find the longest matching path prefix. Multiple packages may match (e.g., a commit touching both `packages/core/` and `packages/sdk/`).

### Cascade Detection

The action needs the workspace dependency graph to auto-cascade:

**JS graph:** `pnpm list --json -r --depth 0` gives dependencies per package
**Rust graph:** `cargo metadata --no-deps --format-version 1` gives dependencies per crate

Cascade rules from D-22:

- Direct dependency gets major → dependent gets at minimum minor
- Direct dependency gets minor/patch → dependent gets at minimum patch
- Only `dependencies`, not `devDependencies` (D-24)

### Post-Merge Action Flow

1. Trigger: `on: push: branches: [main]` (runs on every push to main)
2. Find originating PR: `gh pr list --search {sha} --state merged --json number,labels`
3. Read final labels from PR
4. Read current versions from `.release-please-manifest.json`
5. Compute target versions (current + bump type)
6. Read existing `release-as` entries (handle multiple PRs merging before RP runs)
7. Take higher bump if conflict (D-29)
8. Write `release-as` to `release-please-config.json`
9. Commit: `chore(release): set release targets from PR #N`
10. Push to main (requires GitHub App token with contents:write)

### Label Pre-Creation

~70 labels needed: 14 components x 5 types = 70, plus `release:none`.

Components (14): `api`, `web`, `desktop`, `tee-worker`, `core`, `crypto`, `api-client`, `sdk-core`, `sdk`, `cipherbox-crypto`, `cipherbox-core`, `cipherbox-api-client`, `cipherbox-fuse`, `cipherbox-sdk`

Types (5): `feat`, `fix`, `perf`, `refactor`, `breaking`

Can be scripted via `gh label create "release:core:feat" --color <hex>`.

### API Lock Group (D-05)

`apps/api` + `packages/api-client` + `crates/api-client` share a version. The action must:

- Detect changes in any of the three
- Apply the highest bump across all three to all three
- Use a single label prefix (e.g., `release:api:feat`) that applies to the group

### Monotonic Versioning for Apps (D-08, D-13)

Web and Desktop use `major.minor` (no patch). This means:

- `fix:` commits → minor bump (not patch)
- `feat:` commits → minor bump
- `breaking:` → major bump
- Version goes 1.0 → 1.1 → 1.2 → 2.0, never 1.0.1

Implementation: The bump computation logic needs a per-package "versioning strategy" flag. For monotonic packages, map fix/perf/refactor → minor instead of patch.

### Docker Image Tagging (D-36)

Current: `cipherbox-api:${DEPLOY_TAG}` and `cipherbox-api:latest`
Target: `cipherbox-api:${component_version}` and `cipherbox-api:latest-staging`

The deploy workflow needs to read the component version from the manifest or a version file. Currently it tags with the git tag name, which will change from `staging-v0.35.0-rc-1` to `staging-20260331-release-1` — no longer contains the version.

**Options for version resolution:**

- Read from `package.json` (API) or manifest at deploy time
- Pass version as workflow input
- Tag with both: deploy tag + version from manifest

## Risks and Mitigations

### Risk 1: Post-Merge Action Race Condition

Multiple PRs merging rapidly could cause concurrent post-merge action runs writing to the same config file.

**Mitigation:** Use `concurrency` group in the workflow to serialize post-merge runs. Only one instance writes to `release-please-config.json` at a time.

### Risk 2: release-as Not Consumed

If RP fails or is delayed, `release-as` entries accumulate.

**Mitigation:** The action reads existing `release-as` and takes the higher bump (D-29). Stale entries are consumed when RP eventually runs. Add monitoring/alerting if release PR is stale for >24h.

### Risk 3: Breaking the Existing Release Flow During Migration

Switching from root-cascaded to per-package versioning is a significant config change.

**Mitigation:** Phase the migration:

1. First: Add missing packages to RP config, remove `extra-files` cascade
2. Second: Add PR-time action (informational mode first)
3. Third: Add post-merge action
4. Fourth: Make PR check required

### Risk 4: Tauri Updater URL Change

Desktop updater resolves `/releases/latest/` for update JSON. If release tag format changes, updater may not find the asset.

**Mitigation:** Desktop-specific release tag (`cipherbox-desktop-vX.Y`) per D-33 ensures updater always has a stable tag to reference. Configure updater endpoint to use component-specific release.

## Implementation Sequence

**Recommended wave structure:**

**Wave 1 — Foundation:**

- Restructure `release-please-config.json` (add missing packages, remove root extra-files, set up API lock group)
- Update `.release-please-manifest.json` with initial versions for new packages
- Pre-create GitHub labels (~70 labels via script)

**Wave 2 — PR-Time Analysis:**

- Create `.github/workflows/pr-release-preview.yml` (or add to existing PR workflow)
- Build the commit analysis + file-to-package mapping + cascade detection logic
- Auto-apply labels to PRs
- Make the check required (after validation)

**Wave 3 — Post-Merge + Staging:**

- Create `.github/workflows/post-merge-release.yml`
- Implement `release-as` injection logic
- Update staging tag format and deploy-staging.yml trigger
- Update Docker image tagging

**Wave 4 — Desktop Release Tag + Cleanup:**

- Configure RP for desktop-specific component tags
- Wire Tauri updater to desktop-specific release
- Update root package to milestone-only versioning
- Documentation and verification

## Validation Architecture

### Unit-Level Validation

- PR-time action: mock PR commits JSON, verify correct labels computed
- Post-merge action: mock PR labels, verify correct `release-as` written
- Cascade logic: test all dependency paths produce correct cascade bumps

### Integration Validation

- Create test PR with multi-package changes, verify labels auto-applied
- Merge test PR, verify `release-as` written to config
- Verify RP creates correct release PR with targeted versions
- Verify staging deploy works with new tag format

### Regression Validation

- Existing RP workflow still functions during migration
- Tauri updater still resolves latest desktop release
- E2E gate still correctly detects changes

## RESEARCH COMPLETE
