---
name: releases
description: CipherBox v2 release and staging-deploy mechanics — release-please layout, the two version surfaces, staging tag pipeline, and the v1 freeze. Use when cutting a release, deploying to staging, or touching release/versioning config.
---

# Releases & Versioning

Normative source: `blueprint/deploy.md` in [FSM1/cipher-box-next](https://github.com/FSM1/cipher-box-next). One product version, one release train.

- The repo releases as a single product `vX.Y.Z` (starting at `v2.0.0`). One release-please component (root, `include-component-in-tag: false`), one CHANGELOG. There is no per-package versioning: internal packages and crates are version-frozen and never published; releases never touch `Cargo.toml`/`Cargo.lock`.
- Version surfaces are exactly two files: root `package.json` (manifest source) and `apps/desktop/src-tauri/tauri.conf.json` (via `extra-files`). Both agree with `.release-please-manifest.json`; a release moves all three together.
- `release-please.yml` runs on every push to `main` and keeps one open release PR. Merging that PR mints the `vX.Y.Z` tag and the GitHub Release that `desktop-release.yml` attaches installers to and `tag-staging.yml` asserts on.
- `release-please-config.json` pins `release-as: "2.0.0"` to mint the first v2 release from a `1.0.0` manifest. **Delete that pin in the first PR after the `chore: release v2.0.0` PR merges** — while it stands, every later release re-mints 2.0.0.
- The release path writes nothing to PR branches. The v1 preview-bot (`pr-release-preview.yml`), `release-gate.yml`, and `cargo-lock-release-sync.yml` are deleted — do not resurrect the pattern of bot commits on PR branches.
- Staging deploys are triggered by `staging-*` tags via `tag-staging.yml` (manual dispatch → release-tag assertion → e2e gates → `staging-approval` → tag → `deploy-staging.yml`). Pre-v2.0.0 staging deploys of WIP v2 go via `workflow_dispatch` of `deploy-staging.yml` at a `main` SHA.
- v1 is frozen: branch `v1` / tag `v1-freeze` at `07376d0b` (cipher-box-v0.45.1). No new v1 releases. Only the final v1 product release `cipher-box-v0.45.2` is retained (until the first v2.0.0 release is cut); all other v1 tags, per-package release tags, and `staging-*` tags have been pruned — v1 will not be redeployed to staging before the v2 cutover.
