# Release Please Commit Parsing Failure

**Date:** 2026-02-23

## Original Prompt

> Can you help me figure out why the release please action failed to run?

## What I Learned

- Release Please's conventional commit parser treats parenthesized text after the type as a **scope** (e.g., `feat(scope): message`)
- If the commit subject contains parentheses with spaces inside (e.g., `(WinFsp virtual filesystem)`), the parser fails with `unexpected token '(' ... valid tokens [)]`
- When a commit can't be parsed, Release Please silently skips it — it doesn't error the workflow
- If ALL commits since the last release are unparseable or non-user-facing, Release Please outputs `No user facing commits found` and skips creating a release PR
- The GitHub Actions job still shows as **successful** (green check) even when nothing was released, making the failure non-obvious

## What Would Have Helped

- Knowing that conventional commit parsing is strict about parentheses in the subject line
- A pre-merge check or commitlint rule that catches this pattern before it lands on main

## Key Files

- `.github/workflows/release-please.yml` — workflow definition
- `release-please-config.json` — Release Please configuration
- `.release-please-manifest.json` — current version tracking

## Prevention Implemented

Two guardrails were added to catch this before it reaches main:

1. **commitlint custom rule** (`commitlint.config.js`) — Added a `subject-no-parens` plugin rule that rejects commit messages containing parenthesized text in the subject. Caught locally via the husky `commit-msg` hook during development.

2. **PR title CI check** (`.github/workflows/pr-title.yml`) — Added a second validation step that extracts the description portion of the PR title and rejects it if it contains `(...)`. Provides a clear error message with suggested alternatives (dashes or brackets).

Together these prevent the issue at both local commit time and PR creation in CI.
