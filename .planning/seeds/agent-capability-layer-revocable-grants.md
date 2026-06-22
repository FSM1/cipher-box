---
title: "Agent capability layer — eager, scoped, cryptographically-revocable grants"
trigger_condition: "The next milestone (agent-native or otherwise) is scoped, OR the sharing/delegation subsystem is reworked, OR a hostile-agent / compliance threat model is taken on. Pullable FORWARD on its own as a consumer-sharing security fix."
planted_date: 2026-06-22
source: "Exploration session 2026-06-22 (see notes/next-milestone-agent-native-zk-storage.md); adversarial analysis of the agent-native repositioning."
---

## Idea

Replace today's coarse, lazy, leak-prone delegation with **eager, scoped, time-boxed,
cryptographically-revocable capabilities** — usable for agent↔human and agent↔agent
access, and a security upgrade for existing consumer sharing.

## Why (the current gap)

- **Write-delegation leaks the raw key.** Granting write ECIES-wraps the folder's
  **real, un-rotatable Ed25519 IPNS private key** to the recipient (`shared-write.ts`).
  Deleting the `share_keys` row does **not** cryptographically revoke it: the holder
  can keep signing IPNS records directly and the TEE keeps republishing them. The owner
  cannot rotate the IPNS name without re-deriving the folder keypair and re-publishing
  the parent.
- **Read revocation is lazy + coarse.** `executeLazyRotation` only rotates on the
  sharer's *next write* to the folder; there is no TTL/expiry and no scope finer than
  the IPNS-folder boundary. A revoked party retains decryption until a future write.

For "treat every agent call as hostile," this is a security gap, not a UX nit.

## Shape of the work

- **Eager rotation on revoke** — rotate the wrapped key immediately, not deferred to
  the next write.
- **Capability expiry / TTL** — time-boxed grants (TTL on the re-wrapped key / session
  key); a possible hook is the existing JWT `scope[]` claim.
- **Finer scope** — per-file and read-only grants, op-count caps; below folder level.
- **Cryptographic write-revocation** — the core crypto fork: either
  (a) **mediated writes** (recipient calls a CipherBox/MCP endpoint that performs the
  IPNS publish server-side via the principal's TEE-republish path, gated by a revocable
  session — recipient never holds the raw signing key), or
  (b) **per-grant rotatable IPNS subkeys** (a delegated folder gets its own ephemeral
  IPNS keypair the parent can swap on revoke, time-boxed via the TEE schedule).
  Pick one; this is the single biggest design decision and is worth a spike.

## Notes / dependencies

- Likely touches `METADATA_EVOLUTION_PROTOCOL` (share-metadata schema) and the TEE
  republish scheduling.
- The ECIES re-wrap-for-a-recipient-pubkey primitive already exists and is the right
  base — an agent wallet pubkey is just another recipient node in the share graph.
- Closely related: `seeds/blind-share-social-graph.md` (capability-based shares keyed
  by IPNS name + CRDT-over-IPNS recipient discovery) and
  `todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md`.
- Independent value: this is a genuine improvement to v1.0 consumer sharing security —
  it does **not** require the agent direction to be worth doing.
