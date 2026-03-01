# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Consolidate Desktop Build + E2E Pipeline

## Context

The `e2e-desktop.yml` workflow downloads debug binaries uploaded by CI's `build-desktop-*` jobs. When CI skips those builds (no desktop file changes), the E2E workflow fails with "Artifact not found." This cross-workflow artifact dependency is fragile.

The fix: make `e2e-desktop.yml` self-contained — it builds its own debug binaries, runs E2E tests, and only then builds release binaries. Remove the debug b...

### Prompt 2

ok 2 things:
- the branch has already been merged, so this needs to be pushed to a new branch
- Are there any tests for the rust code, and could running these be included in the CI workflow, obviously gated to the cargo checks passing. Would need to check coverage and al

### Prompt 3

ship it

