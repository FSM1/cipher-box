---
created: 2026-07-03T00:00:00Z
title: Port standalone recovery tool to v3 vault format
area: web
files:
  - apps/web/public/recovery.html
  - tests/web-e2e/tests/recovery.spec.ts
source: 68.1-VERIFICATION.md (human-approved deferral, override 1 of 2)
---

## Problem

The standalone recovery tool (`apps/web/public/recovery.html`) still speaks the v2
vault/metadata format. Phase 68.1 moved the web client onto the node/v3 read+write
chain (sealed nodes, WriteChildRef write plane, AAD triad), so the tool can no
longer decrypt/recover a current vault. `recovery.spec.ts` fails against v3 vaults
for this reason — recorded as a human-approved deferral override in the Phase 68.1
verification (one of the two allowed residual full-suite failures).

## Solution

Own feature plan (explicitly deferred out of 68.1 by the user): port the recovery
tool to the v3 node format — unseal via the v3 envelope (readKey chain), understand
`WriteChildRef`/`SealedChildRef` split, and keep it a fully offline, standalone HTML
artifact. Un-defer `recovery.spec.ts` once ported so the full web-e2e suite has zero
expected failures.
