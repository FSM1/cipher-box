# Parallel Bug Fix Agents — Lessons Learned

**Date:** 2026-02-07

## Original Prompt

> Switch to main, pull latest, knock out easy wins from the todo list. Specifically #1 (registering state stuck), #2 (auth refresh race), and #3 (orphaned IPFS pins) — run #1+#3 and #2 in parallel with separate agents.

## What I Learned

### Use git worktrees for parallel agents, not branch switching

- Two agents running concurrently on the same working tree will fight over `git checkout`. Agent A's checkout changes the files Agent B is working on.
- In this session, the auth refresh agent committed on the wrong branch (`fix/upload-error-recovery` instead of `fix/auth-refresh-race`) because the upload agent had already checked out that branch. Required manual cherry-pick and rebase to untangle.
- **Fix:** Use `git worktree add ../cipher-box-worktree-auth fix/auth-refresh-race` to give each agent its own working directory. Each agent gets a separate `cwd` and there's no checkout contention.

### Dev dependency changes bleed across branches

- Installing `axios-mock-adapter` on one branch modified `pnpm-lock.yaml` in the shared working tree. The lockfile change wasn't committed with the test commit, causing `--frozen-lockfile` CI failures on PR #58.
- Git worktrees would also solve this — each worktree has its own `node_modules` and lockfile state.

### TypeScript narrows `const undefined` to `never`

- `const x: Foo[] | undefined = undefined` — TypeScript knows it's always `undefined`, so `x?.length` narrows to `never` inside the truthy branch. Tests that simulate "undefined path" hit this.
- Fix: extract the conditional logic into a helper function with proper parameter types, then call it with `undefined` as an argument. The function signature prevents TS from over-narrowing.

### Group related fixes that touch the same code

- Todos #1 (registering state stuck) and #3 (orphaned pins) both modified the same catch blocks in `UploadZone.tsx` and `EmptyState.tsx`. Combining them into one branch avoided merge conflicts and made the changes coherent.
- Todo #1 turned out to already be fixed in the current code — the agent verified and skipped it.

## What Would Have Helped

- Knowing upfront to use git worktrees when launching parallel agents
- Remembering to include lockfile changes when adding dev dependencies in test commits
- Checking CI pipeline requirements (`--frozen-lockfile`) before pushing

## Key Files

- `apps/web/src/lib/api/client.ts` — auth refresh interceptor
- `apps/web/src/components/file-browser/UploadZone.tsx` — upload error recovery
- `apps/web/src/components/file-browser/EmptyState.tsx` — upload error recovery (same pattern)
- `apps/web/src/lib/api/__tests__/client-refresh.test.ts` — auth refresh tests
- `apps/web/src/stores/__tests__/upload-error-recovery.test.ts` — upload recovery tests
