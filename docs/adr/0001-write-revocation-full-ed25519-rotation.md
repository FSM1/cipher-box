---
status: accepted
date: 2026-06-26
---

# Write-revocation uses full Ed25519 rotation (approach c)

Revoking a write delegate must make the signing key they have already cached unusable. Because the relay is untrusted and IPNS publish authorization is key-possession only (`apps/api/src/ipns/ipns.service.ts` performs no ownership/share check), the only way to deny a holder's future writes is to change the signing key itself. We rotate the affected subtree's Ed25519 IPNS keypair(s) — approach (c) — accepting that this changes each node's k51 `ipnsName`, cascades a parent-pointer re-seal up to the share root, re-enrolls the new names with the TEE, and re-points every surviving co-grant and owner device.

## Considered options

- **(a) Mediated relay → TEE signing** — rejected as the default. It turns the untrusted relay into a confused-deputy signing oracle (a token-validation bug, SSRF, or auth bypass would forge IPNS records under the owner's identity), requires a new synchronous `/ipns/sign` enclave endpoint with airtight token-to-name verification, and couples write-time to TEE/relay liveness. It is, however, the only option that cheaply serializes the IPNS sequence race and yields an O(1) write-revoke, so it remains the documented flip target.
- **(b) Per-grant ephemeral subkey** — dominated by (c): same k51-name break and subtree cascade, plus an extra key indirection, with no compensating benefit (all writers to one mutable node share a single IPNS identity).
- **(d) Hybrid (owner self-signs, delegated writes mediated)** — rejected: it does not serialize the sequence race (two signing paths contend on one per-row counter) and still drags the mediated trust base in for the delegated subset.

## Consequences

Write-revocation is the most expensive operation in the system: O(subtree) republishes + a fresh keypair and k51 name per node + a parent re-point cascade to the share root + TEE unenroll/re-enroll (a fresh ECIES-to-TEE-pubkey wrap per node) + re-mint of all surviving co-grants and owner-device pointers + a co-writer re-key. A co-writer offline during rotation cannot write until they re-fetch the re-wrapped key. The read schema is unchanged — the write-body is sealed under an independent `writeKey` the read grant never conveys — so this decision did not affect the read chain.

Flip to (a) only if all three hold: frequent write-revokes on large shared subtrees become a measured cost; a trustworthy TEE sign-endpoint with token-to-name binding can be delivered; and write-time TEE/relay liveness coupling is acceptable.
