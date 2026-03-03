# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Plan: Make Release Gate Required & Unify E2E Verification

## Context

The release gate (`release-gate.yml`) has sophisticated E2E verification logic (polling, desktop change detection, `run_executed_tests` check). Meanwhile, `tag-staging.yml` has a simpler, weaker version of the same check (lines 34-66) that doesn't verify desktop E2E jobs actually executed. We need to:

1. Unify the verification logic so both workflows use the same checks
2. Make the release...

### Prompt 2

ok this is a chore type pr, to be created as such

