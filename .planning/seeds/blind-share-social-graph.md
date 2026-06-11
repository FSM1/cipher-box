---
title: Blind the share social graph via capability-based shares
trigger_condition: A privacy-hardening milestone is scoped, or the sharing subsystem is reworked for any reason.
planted_date: 2026-06-11
area: privacy
related:
  - .planning/notes/ipns-write-auth-is-cryptographic.md
  - .planning/todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md
---

## Idea

The only remaining privacy gap on the API is the social graph. `shares(sharer_id,
recipient_id, permission, created_at, revoked_at)` is a directed, typed,
timestamped owner→recipient edge list that resolves to real identities
(`users.publicKey` → `auth_methods.identifier`), with per-share item counts
(`share_keys`) and a plaintext `item_name`. Blind it by moving to capability-based
shares where the server stores no recipient identity.

## Why this is now a small lever, not a redesign

Per the `ipns-write-auth-is-cryptographic` note, the server does not authorize
writes — `findActiveWriteShare` only routes a recipient's publish onto the owner's
DB row. The enabling change is therefore narrow:

- Server verifies the inbound IPNS record's Ed25519 signature against the
  `ipnsName`, and keys the canonical record by `ipnsName` (not `userId`).
- Once the publish path is self-authorizing, `recipient_id` is no longer needed
  for writes, and the same change fixes the sequence self-increment / divergence
  bug.

A share then becomes `{ipnsName + ECIES-wrapped folderKey [+ wrapped IPNS
privateKey for write]}` handed to the recipient out-of-band — the invite /
URL-fragment primitive already exists for link shares. Revocation = key rotation
(already required).

## Open design questions (resolve at plan time)

- Discovery model — where "what's shared with me" lives without a server edge:
  - Vault-synced capabilities: recipient stores received capabilities in their own
    encrypted vault blob; server sees zero graph; a wiped device with no vault
    recovery loses the list until re-shared.
  - Blinded inbox: per-recipient inbox keyed by a recipient-derived pseudonym;
    server-backed listing survives device loss and stays unlinkable. This is the
    existing CRDT-IPNS-inbox todo (`2026-02-22-crdt-ipns-inbox-sharing.md`) — fold
    that exploration in here when chosen.
- Server-side IPNS record validation in Nest: which library validates Ed25519
  signature + sequence + validity against the signed bytes.
- Quota / pin attribution for shared content once the edge is gone (`pinned_cids`
  is per-`userId`).
- What `GET /shares/received` and revocation become without `recipient_id`; stop
  the link-share claim path from writing `claimed_by`.
- Residual traffic correlation: JWT-authed `GET /ipns/resolve?ipnsName=` still ties
  a recipient's 30s polling to specific shares — full blinding may require
  unauthenticated, padded, or proxied resolves.

## Lower-hanging hardening (independent of the redesign)

- Drop the plaintext `item_name` from `shares` and `share_invites`.
- Stop co-storing `recipientPublicKey` in the same row as the wrapped key — the
  wrapping target currently sits in plaintext beside the ciphertext.
