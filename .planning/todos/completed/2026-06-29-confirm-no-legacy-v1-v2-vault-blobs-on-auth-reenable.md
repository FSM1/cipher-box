---
created: 2026-06-29
title: Confirm no legacy v1/v2 vault blobs (or add migration) when auth path is re-enabled
area: auth
files:
  - packages/sdk-core/src/vault/index.ts
  - apps/web/src/hooks/useAuth.ts
  - packages/core/src/vault/blob.ts
---

## Problem

Phase 62 hard-cut the vault recovery blob to v3 and deleted the v1/v2
deserializers (D-05). `loadVaultKeyBlob` (`packages/sdk-core/src/vault/index.ts`)
and the existing-vault path in `apps/web/src/hooks/useAuth.ts` now call
`deserializeVaultBlobV3` unconditionally, which throws `'Not a v3 vault blob'`
for any blob whose first byte is `0x01` (v1 JSON) or `0x02` (v2 binary).

The hard-cut is intentional: this is a greenfield system and staging is wiped,
so there are expected to be no v1/v2 vaults in existence. But both auth paths
are currently stubbed (D-01), so the assumption is not exercised anywhere. When
phase 63 un-stubs the auth flow, any surviving v1/v2 vault would lock its owner
out with a hard throw. Greptile flagged this (P1) on PR #578.

## Solution

When the auth/vault-load path is re-enabled (phase 63):

- Confirm the greenfield assumption still holds — no v1/v2 vault key blobs exist
  in any environment that will be migrated forward. If true, the hard-cut stands;
  add a one-line code comment at each call site recording that v1/v2 is
  intentionally unsupported (D-05), so the hard throw is understood as a guard,
  not a regression.
- If any legacy v1/v2 blobs must be preserved, add an explicit one-time migration
  (detect the version byte, decrypt with the legacy scheme, re-seal as v3) before
  removing the throw — do not silently fall through.

Deferred from phase 62 (`/ship-phase`): the auth paths are stubbed mid-milestone,
so the assumption can only be validated at the phase 63 re-wire. Related:
[[2026-06-29-recovery-html-vault-v3-migration]].

## Resolution

NOT APPLICABLE / WON'T DO — retired 2026-07-11 (user decision).

The greenfield assumption is confirmed: there is no v1/v2 → v3 vault migration, and
all legacy v1/v2 vaults have been deprecated. The `deserializeVaultBlobV3` hard-cut
(throw on any non-`0x03` blob) stands intentionally as the D-05 guard — no legacy
blobs exist in any environment that will be carried forward, so neither a migration
nor a special-case fallback is needed. No code change required.
