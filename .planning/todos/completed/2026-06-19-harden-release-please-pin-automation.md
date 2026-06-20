---
created: 2026-06-19
title: Harden release-please release-as pin automation against force-push clobber and stale pins
area: ci
files:
  - .github/scripts/pr-release-preview.js
  - .github/workflows/pr-release-preview.yml
  - release-please-config.json
  - .release-please-manifest.json
---

## Problem

`packages/sdk` got stuck in a release-please loop: its CHANGELOG gained a duplicate, self-comparing `0.36.0` entry (`compare/@cipherbox/sdk-v0.36.0...@cipherbox/sdk-v0.36.0`) on every push to `main` (#510, then a byte-identical dupe in #514). The immediate corruption was fixed in the `chore(ci): break sdk changelog self-compare loop` PR (bump sdk `release-as` to 0.37.0 + remove the dup blocks). This todo tracks the **systemic** cause so it stops happening to other packages.

Root cause chain (confirmed against git history on 2026-06-19):

1. `release-as` version pins are injected per-PR by `.github/scripts/pr-release-preview.js`, committed by the bot as `chore(release): set release targets for PR #N`. The pins land on `main` when the PR merges and release-please consumes them.
2. The pins are **never cleared once satisfied**. The script's clear logic (`pr-release-preview.js` ~lines 644-652) only deletes a `release-as` that THIS PR added AND that was not inherited from `main` (`!packageBumps.has(pkgPath) && !baseReleaseAs[pkgPath]`). Inherited, already-consumed pins persist forever. As of 2026-06-19, ~9 packages have `release-as` exactly equal to their manifest version (api, web, core, crypto, api-client, sdk-core, sdk, crates/core, crates/fuse) — each a latent trap.
3. When a pin equals the manifest/tag AND a path-attributed releasable commit lands for that package, release-please tries to "release" the already-shipped version → self-comparing `vX...vX` changelog header, re-appended every push because the version never advances and the pin is never cleared.
4. **Why sdk's pin went stale specifically:** the preview bot's target commit for #509 (`b13e99355`) was **orphaned by a branch rebase/force-push** — it is NOT an ancestor of `main`, and the merged #509 commit (`c36ac6d77`) descends from the #508 release commit instead. That bot run had set targets for api/crypto/api-client but not sdk; the rebase discarded it, and the workflow's `concurrency: cancel-in-progress: true` aborts the bot's re-run on each force-push, so sdk's target was never (re)computed/advanced even though #509 changed `packages/sdk/src/**`. release-please still attributes that feat to sdk by path → loop.

So two failure modes compound: (a) agent/force-push clobbers the bot's release-target commit (and `cancel-in-progress` prevents self-correction), and (b) stale satisfied pins are never cleared.

## Solution

Address both the clobber and the stale-pin accumulation:

1. **Make release targets resilient to force-push / rebase.** Options, pick one:
   - Establish the rule (in tooling + agent instructions) that pushes to a PR branch must `git fetch` + rebase the bot's `chore(release): set release targets` commit rather than force-push over it (matches the known "PR-create triggers a bot release commit" gotcha). Best: enforce, don't rely on discipline.
   - OR move release-target computation off the committed config file entirely (e.g. compute at release time from conventional commits, or have release-please own versioning natively) so there is no bot commit to clobber.
   - Revisit `concurrency: cancel-in-progress: true` in `pr-release-preview.yml` — at minimum re-run the preview on the final state before merge so a clobbered/cancelled run can't ship a stale config.
2. **Clear satisfied/inherited pins.** Patch `pr-release-preview.js` so it also removes any `release-as` that is `<=` the package's manifest version (already consumed), regardless of whether it was inherited. Optionally add a post-release step that strips satisfied pins after release-please cuts a release.
3. **Reconcile path attribution** between `pr-release-preview.js` (its `packageBumps` is path-based at ~line 298) and release-please, so a source change under `packages/<x>/**` can never leave `<x>`'s target behind.
4. **Clean up the existing latent traps:** drop the ~8 other `release-as` entries currently equal to their manifest version.

Verification: after the fix, a feat touching one package's source while another package's pin is stale should NOT produce a self-comparing changelog entry, and a force-push to a PR branch should not be able to drop the package's computed release target.
