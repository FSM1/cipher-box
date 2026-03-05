# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Fix: Codecov Base Upload workflow 404

## Context
The "Codecov Base Upload" workflow (`codecov-base.yml`) fails every time it runs on push to `main`. The step "Download coverage from latest CI run" gets a 404 from the GitHub API. This means Codecov never gets base branch coverage, so PR coverage diffs don't work.

## Root Cause
In `.github/workflows/codecov-base.yml` line 27-29, the `gh api` call uses `-f per_page=5`. The `-f` flag causes `gh api` to switch fr...

### Prompt 2

ok switch back to the pr 268 branch - all 3 rust test jobs are failing

