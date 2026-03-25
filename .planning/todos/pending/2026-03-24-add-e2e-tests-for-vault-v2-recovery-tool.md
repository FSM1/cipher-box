---
created: 2026-03-24T01:40:00.000Z
title: Add e2e tests for vault v2 recovery tool
area: testing
files:
  - apps/web/public/recovery.html
  - tests/web-e2e/
---

## Problem

The recovery tool (`/recovery.html`) has no automated test coverage. During phase 20 UAT, multiple bugs were found and fixed manually via Playwright:

- `fetchFromIpfs` returning undefined on non-404 failures
- IPNS delegated routing returning CBOR records parsed as garbage CIDs
- IPNS resolution needing gateway `/ipns/` HEAD fallback for local dev
- CipherBox API IPNS endpoint requiring auth (recovery tool runs unauthenticated)

These should be caught by automated tests to prevent regressions.

## Solution

Create Playwright e2e tests exercising both recovery paths:

1. **Export file recovery** — load a known-good export JSON, provide private key, verify folder tree recovery
2. **IPFS-direct v2 blob recovery** — provide private key only, verify IPNS derivation, v2 blob fetch, rootFolderKey ECIES decrypt, folder tree traversal
3. **Error cases** — invalid private key, wrong key length, gateway unreachable, v1 blob format detection, corrupted blob handling

Test infrastructure: use a local Kubo node with pre-seeded IPNS records and v2 blobs. Could use the SDK E2E test harness as a base.
