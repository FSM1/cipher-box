---
created: 2026-07-12T00:00:00.000Z
title: Vault-init dead-ends when both IPNS records published but backend registration failed
area: desktop
severity: medium
files:
  - apps/desktop/src-tauri/src/commands/vault.rs
---

> Surfaced by Greptile (P1) on the Phase 76 PR (#610). Distinct from the SC1 work Phase 76
> shipped: Phase 76 handles the (key-blob published, root NOT published) partial-init via the
> `RecoverResume` route. This is a DIFFERENT partial-failure mode — both IPNS records are
> durable but the final `register_vault` (`/vault/init`) call failed or timed out.

## Problem

`initialize_vault` publishes both IPNS records inside the `route_vault_init` match, then calls
`register_vault(...)` once AFTER the match (`vault.rs:539`). If registration fails there, the
IPNS records are already durable. On the next attempt, `route_vault_init` sees
`(key_blob_absent=false, root_absent=false)` and returns `Err` "vault already fully initialized
— route through the vault load path" (`vault.rs:125`). But the load path
(`fetch_and_decrypt_vault` → `GET /vault`) returns no vault row because registration never
completed. Result: the user is stuck — `initialize_vault` refuses to register, and the load
path fails, with durable IPNS records but no registered vault.

## Suggested fix

Disambiguate the `(false, false)` case: before erroring, `GET /vault`; if the vault row is
absent, treat it as a register-only resume and call `register_vault` (which must be idempotent,
or gated on a not-found check) rather than routing to the failing load path. Add a
`VaultInitRoute::RegisterOnly` variant + a unit test mirroring the existing route/recovery seam
tests. Confirm `register_vault` backend idempotency first.
