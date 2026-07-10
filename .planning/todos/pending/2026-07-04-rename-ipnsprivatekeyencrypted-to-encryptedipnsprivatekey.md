---
created: 2026-07-04T00:00:00Z
title: Rename in-memory ipnsPrivateKeyEncrypted → encryptedIpnsPrivateKey (terminology)
area: sdk
files:
  - packages/sdk-core/src/upload/index.ts:22
source: ship-phase 68.1 CodeRabbit finding 22 (deep write-plane verification)
resolves_phase: 77
---

## Problem

The upload metadata return shape uses `ipnsPrivateKeyEncrypted`, violating the
project terminology standard which requires `encryptedIpnsPrivateKey` (CLAUDE.md
terminology table). It is an IN-MEMORY-ONLY return field — the persisted/wire
`FileIpnsRecordPayload` already uses the correct `encryptedIpnsPrivateKey`, and no
production consumer reads the misnamed field (it is redundant) — so renaming is
safe for the wire format. It was NOT renamed during ship because ~30 fixtures in
the `packages/sdk-core/src/__tests__` and `packages/sdk/src/__tests__` dirs
reference the old name, and those dirs were owned by a concurrent test-modernization
workstream during ship (must not be edited in parallel).

## Solution

Rename `ipnsPrivateKeyEncrypted` → `encryptedIpnsPrivateKey` in the upload return
type and its ~30 test-fixture references in one atomic change. Pure rename, no
behavior change; gate with the sdk/sdk-core unit suites.
