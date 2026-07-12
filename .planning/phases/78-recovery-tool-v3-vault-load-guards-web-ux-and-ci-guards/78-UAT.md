---
status: testing
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
source: [78-VERIFICATION.md]
started: 2026-07-12T12:58:28Z
updated: 2026-07-12T12:58:28Z
---

## Current Test

number: 1
name: poll-monotonicity same-folder-newer-sequence e2e on a clean DB
expected: |
  With no concurrent pipeline sharing the cipherbox DB, run
  `pnpm --filter @cipherbox/web-e2e test -- poll-monotonicity.spec.ts`.
  A slow in-flight poll response must not overwrite a newer nav-triggered
  folder state; the spec passes deterministically (it was infra-blocked
  earlier by a transient shared-DB UQ_ipns_records_ipns_name duplicate-key
  on new-account init, now cleared).
awaiting: user response

## Tests

### 1. poll-monotonicity same-folder-newer-sequence e2e on a clean DB
expected: poll-monotonicity.spec.ts passes deterministically against the sequenceNumber guard in useSyncPolling.invalidateOpenFolder; no stale-poll clobber.
result: [pending]

### 2. Download/restore spinner on-screen visibility
expected: On a real file download and a real bin restore, the existing FileBrowser spinner and the bin restore status affordance visibly appear (driven by useDownloadStore / useRestoreStore). No automated Playwright assertion exists for on-screen render (Wave 0 gap) — verify via Puppeteer or manual observation.
result: [pending]

## Summary

total: 2
passed: 0
issues: 0
pending: 2
skipped: 0
blocked: 0

## Gaps
