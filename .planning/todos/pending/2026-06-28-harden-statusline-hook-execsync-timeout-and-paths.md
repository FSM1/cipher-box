---
created: 2026-06-28
title: Harden .claude statusline hook — execSync timeouts and cross-platform paths
area: tooling
files:
  - .claude/hooks/statusline.cjs
---

## Problem

CodeRabbit flagged two robustness issues in `.claude/hooks/statusline.cjs` (a Claude Code dev-tooling hook, not product code). They rode into the Phase 61 PR because the statusline `.js`→`.cjs` rename was committed on the phase branch (`df70dce20 chore: fix statusline`), not because Phase 61 touched them. Deferred as out-of-domain for the crypto phase.

- **execSync without timeout (major):** the `git rev-parse` / `git status --porcelain` calls in the statusline hot path have no `timeout`, so a hung git invocation can freeze the status line indefinitely. Add `timeout: 1000` (+ graceful fallback) to each `execSync`.
- **POSIX-only path handling (minor):** `cwd.split('/')` for the directory basename and the `.git/worktrees` substring check are not Windows-safe. Use `path.basename(cwd)` and normalize `gitDir` (`replace(/\\/g, '/')`) before the worktree-marker check.

## Fix

Apply CodeRabbit's suggested diffs: bounded `execSync` timeouts with try/catch fallback, and `path`-helper-based basename + normalized gitDir. Keep the change scoped to `statusline.cjs`.

## Source

Phase 61 ship-loop CodeRabbit review, 2026-06-28 (findings on `.claude/hooks/statusline.cjs`). Non-blocking, out of the AAD-seal phase's domain.
