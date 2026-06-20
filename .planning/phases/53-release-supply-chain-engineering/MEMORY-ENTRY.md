# MEMORY.md draft entry (Phase 53)

This is a DRAFT to be appended by the user/orchestrator to the shared project
memory at
`~/.claude/projects/-Users-myankelev-Code-random-cipher-box/memory/MEMORY.md`,
under the "gh CLI Auth" / release-automation cluster (next to the existing
"PR-create triggers a bot release commit" entry). Do NOT write the shared
MEMORY.md from a worktree.

## Proposed entry

- [Never force-push over the bot chore(release) commit](project-never-force-push-over-bot-release-commit.md) — `pr-release-preview.yml` has the bot push `chore(release): set release targets for PR #N` onto the PR branch; that commit carries the computed release targets. A `git push --force`/rebase-clobber drops it, so release-please misses the bump on merge (T-53-04, #16). ALWAYS `git fetch && git rebase origin/<branch>` to update a PR branch, never force-push over the bot commit. Safety-net: `pr-release-preview.yml` now uses `concurrency.cancel-in-progress: false` so a queued recompute finishes and the targets self-heal even after a clobber — backstop only, not a license to force-push. Related hygiene: never leave a `release-as` in `release-please-config.json` equal to its `.release-please-manifest.json` version (self-comparing changelog loop, T-53-05); the `.github/scripts/check-stale-release-as.js` guard fails CI on it — delete the stale `release-as` key.
