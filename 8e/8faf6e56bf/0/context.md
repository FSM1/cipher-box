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

### Prompt 3

I would be configuring tag protection I am guessing not branch protection right?

### Prompt 4

ok, I think that maybe it makes more sense to actually have the `create staging tag` workflow to just run the full suite of web and desktop e2e tests, since it is not as time sensitive an operation.

### Prompt 5

is there a real need for the verify-e2e.yml, if its only used in the release-gate workflow? would it not make sense to just keep it as part of that workflow as is?

### Prompt 6

all pushed up to the branch?

