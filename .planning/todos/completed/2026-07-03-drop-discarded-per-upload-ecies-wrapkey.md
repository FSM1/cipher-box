---
created: 2026-07-03T00:00:00Z
title: Stop computing the discarded per-upload ECIES wrapKey on the hot path
area: web
files:
  - packages/sdk-core/src/upload/index.ts:36
  - apps/web/src/workers/encrypt.worker.ts
source: ship-phase 68.1 simplify review
resolves_phase: 77
---

## Problem

`ExternalEncryptFn` (packages/sdk-core/src/upload/index.ts:36) still requires
`wrappedKey`, but phase 68.1 removed the only read of it. The live web upload path
(encrypt.worker) therefore still computes an ECIES `wrapKey` per file whose result
is discarded — wasted asymmetric crypto on the upload hot path. The `folderKey` /
`userPublicKey` parameters threaded for it are likewise unused.

## Solution

Contract change: drop `wrappedKey` from `ExternalEncryptFn`, remove the wrapKey
computation from the worker, and stop threading `folderKey`/`userPublicKey`.
Ripples across the worker, sdk-core types, and callers — do as one focused change
gated by upload unit tests + a batch-upload web-e2e spec run, and measure the
upload-throughput win on a many-file batch.
