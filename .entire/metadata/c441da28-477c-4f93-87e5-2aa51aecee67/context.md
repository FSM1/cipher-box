# Session Context

**Session ID:** c441da28-477c-4f93-87e5-2aa51aecee67

**Commit Message:** Ci is failing on the PR

## Prompt

ci is failing on the PR

## Summary

Unit test fix pushed. The E2E failure ("Create workspace folder at root" timeout) is the pre-existing flaky test tracked in todo `2026-02-10-fix-flaky-post-reload-e2e-tests.md` — not caused by this PR's changes. CI should go green on the unit test job now; the E2E flake is a known issue.

## Key Actions

- - **Bash**: Check CI status on PR #130
- - **Bash**: Get failed Test job logs
- - **Bash**: Get failed E2E Tests job logs
- - **Read**: /Users/michael/Code/cipher-box/apps/api/src/auth/services/jwt-issuer.service.spec.ts
- - **Read**: /Users/michael/Code/cipher-box/apps/api/src/auth/services/jwt-issuer.service.ts
- - **Edit**: /Users/michael/Code/cipher-box/apps/api/src/auth/services/jwt-issuer.service.spec.ts
- - **Bash**: Run jwt-issuer spec to verify fix
- - **Bash**: Run jwt-issuer service spec
- - **Bash**: Run jwt-issuer test directly via jest
- - **Bash**: Commit and push test fix
