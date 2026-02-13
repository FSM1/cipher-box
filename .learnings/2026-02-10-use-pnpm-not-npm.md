# Use pnpm, not npm — cipher-box is a pnpm workspace

**Date:** 2026-02-10

## Original Prompt

> Install dependencies to run linting

## What I Learned

- This project uses **pnpm** as its package manager, not npm
- Running `npm install` creates a `package-lock.json` which conflicts with the existing `pnpm-lock.yaml`
- Always check for `pnpm-lock.yaml` or `pnpm-workspace.yaml` before installing dependencies
- The correct command is `pnpm i` (or `pnpm install`)

## What Would Have Helped

- Checking the root directory for lock files (`pnpm-lock.yaml`) before running any install command
- Looking at `package.json` for a `packageManager` field

## Key Files

- `pnpm-lock.yaml` — the lock file (presence signals pnpm)
- `pnpm-workspace.yaml` — workspace config
- `package.json` — may contain `packageManager` field
