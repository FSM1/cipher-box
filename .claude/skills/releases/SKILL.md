---
name: releases
description: CipherBox v2 release and staging-deploy mechanics — release-please layout, the two version surfaces, staging tag pipeline, and the v1 freeze. Use when cutting a release, deploying to staging, or touching release/versioning config.
---

# Releases & Versioning

Normative source: [`blueprint/deploy.md`](../../../blueprint/deploy.md). One product version, one release train.

- The repo releases as a single product `vX.Y.Z` (starting at `v2.0.0`). One release-please component (root, `include-component-in-tag: false`), one CHANGELOG. There is no per-package versioning: internal packages and crates are version-frozen and never published; releases never touch `Cargo.toml`/`Cargo.lock`.
- Version surfaces are exactly two files: root `package.json` (manifest source) and `apps/desktop/src-tauri/tauri.conf.json` (via `extra-files`). Both agree with `.release-please-manifest.json`; a release moves all three together.
- `release-please.yml` runs on every push to `main` and keeps one open release PR. Merging that PR mints the `vX.Y.Z` tag and the GitHub Release that `desktop-release.yml` attaches installers to and `tag-staging.yml` asserts on.
- `release-please-config.json` sets `"package-name": ""` and names no `component`. Grouped release PRs (`separate-pull-requests: false`) live on the plain `release-please--branches--main` branch, but the `node` strategy expects the branch to carry the package name from `package.json`, so at tag time it skips the merged PR with `PR component: undefined does not match configured component: cipher-box` and mints nothing. An empty package name makes both sides empty. `v2.0.0` stalled on 2026-09-13 on this.
- The release path writes nothing to PR branches. The v1 preview-bot (`pr-release-preview.yml`), `release-gate.yml`, and `cargo-lock-release-sync.yml` are deleted — do not resurrect the pattern of bot commits on PR branches.
- `tag-staging.yml` mints the `staging-*` tag and calls `deploy-staging.yml` (manual dispatch → release-tag assertion → e2e gates → `staging-approval` → tag → `deploy-staging.yml`). A hand-made deploy is a `workflow_dispatch` of `deploy-staging.yml` at a `main` SHA.
- A hand-pushed `staging-*` tag deploys nothing; use `tag-staging.yml` or a dispatch of `deploy-staging.yml`.
- v1 is frozen: branch `v1` / tag `v1-freeze` at `07376d0b` (cipher-box-v0.45.1). No new v1 releases. Only the final v1 product release `cipher-box-v0.45.2` is retained (until the first v2.0.0 release is cut); all other v1 tags, per-package release tags, and `staging-*` tags have been pruned — v1 will not be redeployed to staging before the v2 cutover.

## Drive a release to staging

Every `gh` command uses `env -u GITHUB_TOKEN gh ... --repo FSM1/cipher-box`. In the commands below, `R='--repo FSM1/cipher-box'`.

1. Check the commits of the release PR for tool attribution. A squash merge copies every commit trailer into `main`. This command must print `0`:

   ```sh
   env -u GITHUB_TOKEN gh api repos/FSM1/cipher-box/pulls/<N>/commits \
     --jq '.[].commit.message' | grep -ci 'co-authored\|generated with'
   ```

2. Squash-merge the release PR with an explicit subject and body: `--squash --subject "chore: release vX.Y.Z (#N)" --body "<PR body without trailers>"`.
3. Merge nothing else to `main` until staging has the deploy. `tag-staging.yml` reads `main` HEAD, and HEAD must keep the `vX.Y.Z` tag. If HEAD moved, the next merged PR must put `Release-As: X.Y.Z` as the last line of its squash body.
4. Wait for the tag ref, then dispatch the run. `gh api` writes the 404 body to stdout, so test the exit code. Repeat the first command until the exit code is 0. Use the harness wait tool between tries, not a foreground `sleep`:

   ```sh
   env -u GITHUB_TOKEN gh api repos/FSM1/cipher-box/git/ref/tags/vX.Y.Z >/dev/null 2>&1; echo $?
   env -u GITHUB_TOKEN gh workflow run tag-staging.yml $R --ref main
   ```

5. The run stops at `staging-approval` with status `waiting`. The owner approves it in the Actions UI, so give the owner the run URL. An agent approves only when the owner explicitly authorizes it for this release:

   ```sh
   env -u GITHUB_TOKEN gh api repos/FSM1/cipher-box/actions/runs/<run-id>/pending_deployments \
     --jq '.[].environment | "\(.id) \(.name)"'
   env -u GITHUB_TOKEN gh api -X POST repos/FSM1/cipher-box/actions/runs/<run-id>/pending_deployments \
     -F 'environment_ids[]=<id>' -f state=approved -f comment='vX.Y.Z, approved by the owner'
   ```

6. If "Provision Grafana Dashboard" fails with HTTP 404 on `/api/health`, the Grafana Cloud instance is asleep. The secrets are correct. Staging E2E needs the full deploy, so it does not run. Until the readiness step wakes the instance itself, wake it: open the instance login page in a browser session, or send an unauthenticated GET to `<instance>/login?disableAutoLogin=true`. The wake takes 1 to 2 minutes. Then run `env -u GITHUB_TOKEN gh run rerun <run-id> $R --failed`. Do not write the instance URL into an issue or a document.
7. If "Cross-Client E2E (macos)" fails on the second session, it is a known flake. Re-run the failed jobs one time.
8. If the Staging E2E job fails, use the `staging-e2e-triage` skill before any re-run.

For a two-step landing under ADR 0020 (see "A new durable staging prefix" in `blueprint/deploy.md`), merge PR B only after "Deploy to Staging VPS" passed for the release that carries PR A.
