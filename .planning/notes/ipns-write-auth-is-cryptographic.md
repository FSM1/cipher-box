---
title: IPNS write authorization is cryptographic, not server-enforced
created: 2026-06-11
area: architecture
related:
  - .planning/seeds/blind-share-social-graph.md
  - .planning/todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md
---

## Finding

The CipherBox API does not authorize IPNS writes. Authorization to publish to an
IPNS name is possession of that name's Ed25519 private key — real DHT resolvers
verify the record signature against the `ipnsName` (which is the encoded public
key). A write-share recipient can publish solely because they hold the
ECIES-wrapped IPNS private key. The server is not in that trust path.

## What the server actually does on publish

- The publish path keys the canonical DB row by `(userId, ipnsName)`
  (`apps/api/src/ipns/ipns.service.ts:351-353`).
- When a write-share recipient publishes to the owner's `ipnsName`, they have no
  row of their own, so `findActiveWriteShare` redirects the update onto the
  owner's row (`ipns.service.ts:213-218`). This is DB-row routing, not a security
  check — strip it and the recipient's publish merely forks a duplicate row under
  their own `userId`.
- The resolve path keys by `ipnsName` alone (`ipns.service.ts:418-419`); it never
  consults the share edge.
- `publishRecord` validates base64 and, only when `publicKey` is supplied, that it
  derives to the `ipnsName` (`ipns.service.ts:68-83`). It never verifies the
  record's Ed25519 signature, and it self-increments the sequence number
  (`ipns.service.ts:246`) instead of reading it from the signed record — the
  acknowledged cause of DB-seq vs record-seq divergence (`ipns.service.ts:543`).

## Implications

- The owner→recipient social edge stored in `shares` is a caching/routing
  dependency, not a security boundary.
- It is not even sufficient for revocation: a revoked recipient still physically
  holds the IPNS private key, so real revocation requires key rotation (which the
  rotation path already performs).
- The social graph can therefore be blinded without weakening write control — see
  the `blind-share-social-graph` seed. The enabling change (server verifies the
  record signature against the `ipnsName` and keys the record by `ipnsName`) also
  closes the sequence-integrity gap, so the privacy and protocol-hardening threads
  converge on one change.
