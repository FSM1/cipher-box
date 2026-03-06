# Conventional Commit Type Accuracy Matters

**Date:** 2026-03-06

## Original Prompt

> Why was that PR created with a `fix` prefix? It's a `chore` at best.

## What I Learned

- Commit type (`fix`, `feat`, `chore`, etc.) is not just a label — it has downstream consequences:
  - `fix:` triggers a **patch version bump** via Release Please and appears under "Bug Fixes" in the changelog
  - `feat:` triggers a **minor version bump** and appears under "Features"
  - `chore:` does **not** appear in the changelog or trigger a version bump
- Using `fix:` for a config cleanup (removing `statusLine` from `.claude/settings.json`) created a misleading changelog entry and an unnecessary version bump
- The branch prefix should match the commit type: `chore/remove-statusline-config`, not `fix/statusline-config`
- When the change is non-functional (config, tooling, dependency cleanup, removing unused settings), always use `chore:`
- When in doubt, prefer `chore:` over `fix:` — a missing changelog entry is less harmful than a misleading one

## What Would Have Helped

- Pausing to ask: "Is this actually fixing a bug?" before choosing the commit type
- Reviewing Release Please config to understand which types trigger version bumps
- Checking `release-please-config.json` for the `changelog-sections` mapping

## Key Files

- `release-please-config.json` — defines which commit types appear in changelog
- `.release-please-manifest.json` — tracks current version
- `.claude/CLAUDE.md` — commit message conventions section
