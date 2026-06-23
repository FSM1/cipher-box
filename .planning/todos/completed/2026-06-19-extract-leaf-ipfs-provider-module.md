---
created: 2026-06-19T00:00:00.000Z
title: Extract leaf IpfsProviderModule and fix misleading IN-04 circular-dependency comments
area: tech-debt
severity: low
files:
  - apps/api/src/ipfs/ipfs.module.ts
  - apps/api/src/vault/vault.module.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts
---

## Problem

The IN-04 "accepted circular-dependency" comments in `ipfs.module.ts`,
`vault.module.ts`, and `pending-unpin.module.ts` give a factually-wrong
rationale. They claim a shared module providing `IPFS_PROVIDER` would create a
circular dependency, so each module self-provides the factory instead.

That is not true. The `IPFS_PROVIDER` factory depends only on `ConfigService`
(a leaf — `ConfigModule` imports nothing from these modules). A standalone:

```ts
@Module({
  imports: [ConfigModule],
  providers: [IPFS_PROVIDER],
  exports: [IPFS_PROVIDER],
})
class IpfsProviderModule {}
```

imported by all three modules would NOT create a cycle. The real cycle is
`IpfsModule → VaultModule`, which is orthogonal to where `IPFS_PROVIDER` is
provided.

The net effect is that the `IPFS_PROVIDER` factory and its default-URL strings
are triplicated across the three modules, justified by an incorrect comment.

## Fix

- Extract the leaf `IpfsProviderModule` (imports `ConfigModule`, provides and
  exports `IPFS_PROVIDER`).
- Import it from `IpfsModule`, `VaultModule`, and `PendingUnpinModule`,
  removing the three duplicated factory definitions and default-URL strings.
- Delete / correct the misleading IN-04 circular-dependency comments.

## Source

Surfaced by Phase 50 /simplify (altitude).
