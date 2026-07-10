---
created: 2026-07-01T00:00:00.000Z
title: Harden TEE republish write-path error handling and epoch-upgrade concurrency
area: correctness
severity: low
files:
  - apps/api/src/republish/republish.service.ts
  - apps/tee-worker/src/services/key-manager.ts
  - apps/tee-worker/src/routes/republish.ts
resolves_phase: 76
---

> Deferred from the Phase 67 ship (CodeRabbit). These touch the republish write path and
> change error-handling semantics — deliberately deferred because a naive fix risks
> behavior regressions (over-escalating failures, masking network-publish success) and
> each needs a dedicated test. The phase's happy path, security invariants, and live E2E
> round-trip are all verified.
>
> NOTE: the original CodeRabbit/greptile epoch-upgrade finding (unconditional
> `ipnsRecordRepository.update`) was FIXED during the ship — the write now scopes to
> `{ ipnsName, userId, tombstonedAt: IsNull(), keyEpoch: <loaded> }` (tombstone immutability
> + owner scope + epoch CAS), and `getDueEntries` now filters `signedRecord`/`keyEpoch`
> non-null. The items below remain.

## Findings

### 1. `renewIpnsRecordEol` swallows real DB errors as success (`republish.service.ts` ~421-442)

The `catch` treats every failure as non-fatal (logs `warn`, returns). The `affected === 0`
CAS-miss is genuinely harmless, but a real DB error (connection drop, constraint) is
masked and the entry is still counted as `succeeded`. Current behavior is intentional
(the network publish already succeeded; the DB row self-heals next cycle by re-renewing
the same CID+seq), but real DB errors should at least surface at `error` level or as a
distinct metric so silent write-back failures are observable. Keep the CAS-miss path
non-fatal; distinguish it from real exceptions.

### 2. Key-decrypt fallback masks config/infra errors as "corrupted key" (`key-manager.ts` ~90-109)

`decryptWithFallback`'s two trials use bare `catch {}`, so a `getKeypair()` failure
(e.g. epoch out of MIN/MAX range, simulator-in-production guard) is swallowed and
reported as the generic "key may be corrupted or from an unknown epoch". Only the
expected unwrap/epoch-mismatch failure should advance to the next trial; rethrow (or
wrap with cause) other exceptions from `getKeypair()`/`decryptIpnsKey()` so a
deployment misconfiguration is not misdiagnosed.

### 3. Per-entry null guard in the republish route (`republish.ts` ~94-99, ~180)

A `null`/non-object `entry` makes `entry.signedRecord` throw, and the `catch` then
dereferences `entry.ipnsName` — throwing again and crashing the whole batch (500).
The relay is trusted and never sends null entries, so this is defense-in-depth: validate
each `entry` is a non-null object at the top of the loop and skip/serialize invalid
items safely in the failure path.
