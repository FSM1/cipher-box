# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Plan: CI Migration Drift Check

## Context

Missing `CREATE TABLE` migrations can slip through — a developer adds/modifies an entity but forgets to generate a migration. This was the exact bug that hit in Phase 14 (PR #186). The fix: add a CI job that compares entity decorators against the migrated schema and fails if they diverge.

Follows the same pattern as the existing `api-spec` job that verifies the OpenAPI client is up to date.

## Changes

### File: `....

### Prompt 2

ok great lets get  pr for this up

