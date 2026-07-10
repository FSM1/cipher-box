---
created: 2026-07-01T00:00:00.000Z
title: Rename encryptedIpnsKey/upgradedEncryptedKey to canonical encryptedIpnsPrivateKey
area: code-quality
severity: low
files:
  - apps/tee-worker/src/routes/republish.ts
  - apps/api/src/tee/tee.service.ts
  - apps/api/src/republish/republish.service.ts
resolves_phase: 77
---

> Deferred from the Phase 67 ship (CodeRabbit, MAJOR). This is a cross-layer rename of
> the TEE↔relay wire contract, and the `encryptedIpnsKey` naming predates Phase 67 (the
> phase kept it while reshaping the entry). Per the ship operating rule, pre-existing +
> contract-wide → defer to a dedicated change with matching relay/test updates.

## Problem

The CLAUDE.md terminology standard mandates `encryptedIpnsPrivateKey` and lists
`encrypted_ipns_key` as a name to avoid. The TEE republish contract still uses
`encryptedIpnsKey` (request `RepublishEntry`) and `upgradedEncryptedKey` (response
`RepublishResult`) in `apps/tee-worker/src/routes/republish.ts`.

## Proposed fix

Rename to `encryptedIpnsPrivateKey` (and e.g. `upgradedEncryptedIpnsPrivateKey`)
consistently across:

- the TEE worker route request/response shapes,
- the API relay that builds the request and reads the response (`tee.service.ts` /
  `republish.service.ts`),
- the tee-worker + api tests.

Preserve semantics (base64 ECIES ciphertext; re-encryption on epoch upgrade). Land it as
one atomic rename so the wire contract never drifts between layers.
