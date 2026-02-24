# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Plan: Add Windows Desktop Build to Staging Deployment

## Context

The `deploy-staging.yml` workflow builds macOS desktop binaries (`build-desktop`, line 116) but has no Windows equivalent. Staging releases only include macOS `.dmg` — no `.msi`/`.exe` for Windows testers. CI artifacts can't be reused because staging builds bake in staging-specific env vars (`VITE_API_URL`, `VITE_ENVIRONMENT=staging`, etc.) that CI builds don't have.

## Changes

### File: `.git...

### Prompt 2

yeah ship it and create a pr

