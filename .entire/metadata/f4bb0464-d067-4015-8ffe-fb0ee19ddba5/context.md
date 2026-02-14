# Session Context

**Session ID:** f4bb0464-d067-4015-8ffe-fb0ee19ddba5

**Commit Message:** The e2e tests are failing, but I am thinking that we make these optional

## Prompt

the e2e tests are failing, but I am thinking that we make these optional for now, while all these auth tickets are being completed.

## Summary

Done. E2E tests will still run on PRs for visibility but won't block merges. Added a `TODO` comment so we remember to re-enable them once the auth work stabilizes after Phase 12.4.

## Key Actions

- - **Glob**: .github/workflows/*.yml
- - **Read**: /Users/michael/Code/cipher-box/.github/workflows/e2e.yml
- - **Edit**: /Users/michael/Code/cipher-box/.github/workflows/e2e.yml
- - **Bash**: Commit and push E2E non-blocking change
