# GSD Quick Tasks Must Use Feature Branches

**Date:** 2026-02-09

## Original Prompt

> Add staging environment banner (via /gsd:quick)

## What I Learned

- The GSD quick task process template defaults to committing directly on the current branch, which was `main`
- The executor agent made 3 commits directly to `main` before the mistake was caught
- **Fix was safe but required manual intervention**: create branch from HEAD, then `git reset --hard` main back to the correct commit
- The CLAUDE.md rule "NEVER push directly to main — all changes must go through feature branches and PRs" applies to quick tasks too, even though the GSD process template doesn't explicitly enforce it
- The GSD executor needs explicit instructions about branching — it won't infer branch protection rules from CLAUDE.md on its own

## What Would Have Helped

- The orchestrator (main Claude session) should always check the current branch and create a feature branch BEFORE spawning the executor
- Quick task process template should include a "create feature branch" step as mandatory, not optional
- The executor prompt should explicitly say "create branch `feat/<slug>` from current HEAD before any changes"

## Key Files

- `.claude/CLAUDE.md` — git workflow rules (branch protection)
- `.claude/get-shit-done/skills/quick.md` — GSD quick task process (missing branch step)
