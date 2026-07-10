---
created: 2026-07-03T00:00:00Z
title: Hoist base64ToBytes into @cipherbox/crypto
area: crypto
files:
  - apps/web/src/services/download.service.ts:8
  - packages/sdk-core/src/share/grant.ts
source: ship-phase 68.1 simplify review
resolves_phase: 77
---

## Problem

A private `base64ToBytes` helper is copy-pasted ~10x repo-wide: 6 in apps/web
(4 added by phase 68.1 — download.service.ts:8, file-metadata.service.ts:47,
useFileVersions.ts:18, useStreamingPreview.ts:35) and 4 in sdk-core (share/grant,
rotation/engine, share/navigate, file/index). `@cipherbox/crypto` has hex helpers
but no base64 decoder.

## Solution

Add `base64ToBytes` (and the matching encoder if the sites need it) to
`@cipherbox/crypto`, re-point all 10 sites, delete the local copies. Mechanical;
gate with package unit suites + typecheck of consumers (rebuild crypto dist before
consumer typechecks — cross-package dist staleness).
