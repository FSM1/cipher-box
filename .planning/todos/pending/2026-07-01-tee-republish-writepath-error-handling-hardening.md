---
created: 2026-07-01T00:00:00.000Z
title: Harden TEE republish write-path error handling and epoch-upgrade concurrency
area: correctness
severity: medium
files:
  - apps/api/src/republish/republish.service.ts
  - apps/tee-worker/src/services/key-manager.ts
  - apps/tee-worker/src/routes/republish.ts
---

> Deferred from the Phase 67 ship (CodeRabbit, 4 MAJOR findings). All four touch the
> republish write path and change error-handling / concurrency semantics — deliberately
> deferred because a naive fix risks behavior regressions (over-escalating failures,
> masking network-publish success) and each needs a dedicated test. The phase's happy
> path, security invariants, and live E2E round-trip are all verified.

## Findings

### 1. Epoch-upgrade write is not CAS-guarded (`republish.service.ts` ~197-211)

The epoch-upgrade `ipnsRecordRepository.update({ ipnsName }, { encryptedIpnsPrivateKey, keyEpoch })`
is unconditional. If a user rotates their key between batch-load and this write (a
grace-period re-encrypt racing a concurrent rotation), the upgrade clobbers the newer
key with a re-encryption of the old one. Guard it with the same equality-CAS shape as
`renewIpnsRecordEol` (e.g. `WHERE ipns_name = :name AND key_epoch = :loadedEpoch`) and
discard on `affected === 0`, or skip the upgrade entirely when the EOL CAS missed.

### 2. `renewIpnsRecordEol` swallows real DB errors as success (`republish.service.ts` ~421-442)

The `catch` treats every failure as non-fatal (logs `warn`, returns). The `affected === 0`
CAS-miss is genuinely harmless, but a real DB error (connection drop, constraint) is
masked and the entry is still counted as `succeeded`. Current behavior is intentional
(the network publish already succeeded; the DB row self-heals next cycle by re-renewing
the same CID+seq), but real DB errors should at least surface at `error` level or as a
distinct metric so silent write-back failures are observable. Keep the CAS-miss path
non-fatal; distinguish it from real exceptions.

### 3. Key-decrypt fallback masks config/infra errors as "corrupted key" (`key-manager.ts` ~90-109)

`decryptWithFallback`'s two trials use bare `catch {}`, so a `getKeypair()` failure
(e.g. epoch out of MIN/MAX range, simulator-in-production guard) is swallowed and
reported as the generic "key may be corrupted or from an unknown epoch". Only the
expected unwrap/epoch-mismatch failure should advance to the next trial; rethrow (or
wrap with cause) other exceptions from `getKeypair()`/`decryptIpnsKey()` so a
deployment misconfiguration is not misdiagnosed.

### 4. Per-entry null guard in the republish route (`republish.ts` ~94-99, ~180)

A `null`/non-object `entry` makes `entry.signedRecord` throw, and the `catch` then
dereferences `entry.ipnsName` — throwing again and crashing the whole batch (500).
The relay is trusted and never sends null entries, so this is defense-in-depth: validate
each `entry` is a non-null object at the top of the loop and skip/serialize invalid
items safely in the failure path.
