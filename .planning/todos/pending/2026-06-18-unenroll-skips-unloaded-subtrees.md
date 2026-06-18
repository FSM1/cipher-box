---
created: 2026-06-18T00:00:00.000Z
title: collectSubtreeIpnsNames skips unloaded subtrees, leaving nested IPNS records un-unenrolled
area: bug
severity: medium
source: Phase 29 (29-02-SUMMARY key-decisions); verified against live code 2026-06-18
files:
  - packages/sdk/src/client.ts
---

## Problem

Phase 29 wired TEE/IPNS unenrollment into all four deletion paths via
`collectSubtreeIpnsNames`, but the collector only walks **already-loaded** folder state
(`folderTree.get()` and an early return when a folder is not loaded —
`packages/sdk/src/client.ts:232`). Deleting a folder whose subtree was never expanded in the
session returns only the top folder's IPNS name, so **nested file/folder IPNS records below an
unloaded subtree are never unenrolled**. Those records keep being republished by the TEE (wasting
compute) and linger until natural expiry.

## Fix

Resolve and traverse the persisted folder metadata for the subtree being deleted (fetch+decrypt
child folder metadata on demand) rather than relying on the in-memory `folderTree`, so the full set
of descendant IPNS names is collected regardless of load state. Alternatively, pair with the
"periodic unenroll reconciliation job" already in BACKLOG as a backstop.

## Acceptance

Deleting a folder with an unloaded subtree unenrolls every descendant file/folder IPNS name (assert
the unenroll batch count matches the full subtree, not just loaded nodes).
