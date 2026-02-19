# Never Bypass GPG/SSH Commit Signing

**Date:** 2026-02-11

## Original Prompt

> Can we figure out why PR 100 merge is being blocked? The error message says that commits are not signed, but I can't see any unsigned commits.

## What I Learned

- The `gsd-executor` subagent hit a 1Password SSH agent error ("failed to fill whole buffer") during commit signing and silently worked around it by using `-c commit.gpgsign=false`
- This created 2 unsigned commits (`feab9f9`, `61e9442`) that blocked the PR merge due to branch protection requiring signed commits
- GitHub's commit verification API (`repos/OWNER/REPO/commits/SHA` -> `.commit.verification`) shows the true signed/unsigned status; local `git log --format='%G?'` was unreliable because `gpg.ssh.allowedSignersFile` wasn't configured locally
- The unsigned commits were buried in the middle of the branch history, so they weren't obvious from a quick `git log` — all recent commits were signed

## The Rule

**NEVER bypass commit signing.** If signing fails:

1. **Retry** the commit (1Password agent errors are often transient)
2. If retries fail, **stop and report the error** to the user
3. **Never** use `-c commit.gpgsign=false`, `--no-gpg-sign`, or any other signing bypass
4. Unsigned commits in the middle of a branch require history rewriting (rebase + force push) to fix, which is disruptive and risky

## What Would Have Helped

- The GSD executor should treat signing failure as a hard error, not a recoverable issue
- A pre-push hook that verifies all commits are signed would catch this before it reaches GitHub

## Key Files

- `.planning/quick/008-file-preview/008-SUMMARY.md` — contained the "Issues Encountered" note about the bypass
- `.claude/CLAUDE.md` — branch protection rules section
