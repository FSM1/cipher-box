---
created: 2026-07-01T00:00:00.000Z
title: Enforce renewIpnsRecord later-EOL invariant and strengthen renewal tests
area: testing
severity: low
files:
  - apps/tee-worker/src/services/ipns-signer.ts
  - apps/tee-worker/src/__tests__/ipns-signer.test.ts
  - apps/tee-worker/src/__tests__/key-manager.test.ts
resolves_phase: 76
---

> Deferred from the Phase 67 ship (CodeRabbit, 1 MAJOR + 3 MINOR). The "later EOL only"
> invariant already holds by construction in production — `renewIpnsRecord` builds the new
> record with `createIpnsRecord(..., now + 48h)` and republish always runs after creation,
> so time advance guarantees a later EOL. The findings below are hardening + test-quality
> improvements; adding a runtime throw to the crypto primitive needs care (clock skew must
> not cause spurious failures), so defer.

## Findings

### 1. Enforce strictly-later EOL in `renewIpnsRecord` (`ipns-signer.ts`, MAJOR)

The primitive accepts a `lifetimeMs` param; a caller passing a lifetime shorter than the
elapsed-since-creation could, in theory, mint an equal/earlier EOL. The TEE never passes a
custom lifetime today. If a custom-lifetime caller is ever added, parse the existing
record's validity and reject when the renewed EOL is not strictly later.

### 2. Assert the renewal invariant directly in the unit test (`ipns-signer.test.ts`)

The current test only checks byte inequality. Parse both records and assert
`renewed.validity > original.validity`; add an edge case where the original already has a
lifetime longer than the default renewal window.

### 3. Wrap parse/sign/marshal in a sanitized try/catch (`ipns-signer.ts`, MINOR)

The route-level catch already sanitizes errors (no key material logged), so this is
defense-in-depth: wrap `parseIpnsRecord`/`createIpnsRecord`/`marshalIpnsRecord` and rethrow
a sanitized error preserving only safe operation context.

### 4. Make the "corrupted key" test actually corrupt the ciphertext (`key-manager.test.ts`)

The `decryptWithFallback` corrupted-key test only exercises the epoch-mismatch branch
(valid ciphertext, mismatched epochs). Actually mutate the `wrapKey` output (or rename the
test) so the `caughtErr` assertion validates the intended corrupted-key branch.
