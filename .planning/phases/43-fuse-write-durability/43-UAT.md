---
status: testing
phase: 43-fuse-write-durability
source: [43-VERIFICATION.md]
started: 2026-06-13T05:30:00Z
updated: 2026-06-13T05:30:00Z
---

## Current Test

number: 1
name: Journal survival after SIGKILL
expected: |
  Copy a file into ~/CipherBox, SIGKILL the desktop app before the upload completes, relaunch.
  The file replays on mount and is present remotely. The cb-journal entry disappears after
  successful replay.
awaiting: user response

## Tests

### 1. Journal survival after SIGKILL

expected: Copy a file into ~/CipherBox, SIGKILL desktop before upload completes, relaunch. File replays on mount and is present remotely; the cb-journal entry disappears after successful replay.
result: [pending]

### 2. Park notification render

expected: Force upload failure (stop the API), copy a file, let retries exhaust. An OS notification with the failed-upload count appears (no file names in the copy), the tray shows the WriteParked status, and the journal entry remains on disk with Failed status.
result: [pending]

### 3. Mkdir orphan survival

expected: mkdir under a parent with an induced parent-publish conflict; the folder survives an app restart, the parent publishes correctly on retry/replay, and no orphan remains.
result: [pending]

### 4. Ciphertext-only journal check

expected: Open any cb-journal/*.json file created during the above tests; it contains only base64/hex ciphertext, wrapped keys, IVs, and IPNS names — never readable file content or plaintext paths.
result: [pending]

## Summary

total: 4
passed: 0
issues: 0
pending: 4
skipped: 0
blocked: 0

## Gaps
