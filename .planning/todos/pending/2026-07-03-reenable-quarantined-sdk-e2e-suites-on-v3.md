---
created: 2026-07-03T00:00:00Z
title: Re-enable the 11 quarantined sdk-e2e suites on the v3 write chain
area: testing
files:
  - tests/sdk-e2e/src/suites/folder-crud.test.ts:17
  - tests/sdk-e2e/src/helpers/
  - tests/sdk-e2e/src/fixtures/
source: ship-phase 68.1 SDK E2E gate (probe run 2026-07-03)
---

## Problem

11 of 16 sdk-e2e suites (89 of 101 tests) are `describe.skip`-quarantined with the
marker "quarantined D-01: SDK runtime stubbed mid-milestone, re-enable at phase
63-65 consumer re-wire". The re-wire is now complete (phase 68.1), but a probe
re-enable of `folder-crud.test.ts` fails 7/10: the test fixtures still mint
vaults/folders the v2 way with no writeKey seeding, so every mutation trips the v3
write-capability gate — e.g. `createFolder: parent folder k51... has no writeKey —
cannot mint an owned subfolder without a write-capable parent`
(`packages/sdk/src/client.ts:1391`). Same defect class the web-e2e harness had
before 68.1-25 (createTestAccount now publishes a real root Node with write
capability); the sdk-e2e `TestContext`/fixtures never got that treatment.

The active (non-quarantined) surface — rotation-crash-safety, write-chain-rotation,
read-chain-navigation, ipns-publish-gate — passes green, so the v3 publish/resolve
round-trip IS gated; what's missing is coverage breadth (folder CRUD, file ops,
batch upload, bin, shares, invite links, concurrency, error cases, data integrity,
IPNS consistency, vault lifecycle).

## Solution

Port the sdk-e2e harness to the v3 account/vault bootstrap (mirror the 68.1-25
web-e2e `createTestAccount` approach: publish a real root Node with seeded
writeKey), then un-skip suites one at a time and fix per-suite drift (ids vs
ipnsNames, SealedChildRef/WriteChildRef split, moveItem `movedRef` return shape).
Expect real per-suite rework, not a mechanical un-skip. Restores sdk-e2e as the
full cross-package publish gate instead of the current 4-file subset.
