---
created: 2026-07-11T00:00:00.000Z
title: Scope-exit re-mint trusts the zero-knowledge server for recipient public-key binding
area: sharing-rotation-crypto
severity: medium
source: Phase 74 crypto-privacy-review (2026-07-11) — MEDIUM finding
files:
  - crates/fuse/src/write_ops/rotation_deps.rs
  - crates/sdk/src/rotation/engine.rs
  - packages/sdk-core/src/rotation/engine.ts
resolves_phase: null
---

## Problem

On a covered scope-exit rotation the owner re-wraps the NEW post-rotation read
key under `recipient_public_key` as returned by `GET /shares/sent`
(`query_grants_rooted_at` in `rotation_deps.rs` ~:265-285), then feeds it to
`wrap_key(new_read_key, &grant.recipient_public_key)`
(`engine.rs:610` / TS `engine.ts:613`). That public key comes from the
untrusted, zero-knowledge server.

A malicious or compromised server that substitutes an attacker-controlled
pubkey would cause the owner to ECIES-wrap the fresh post-rotation read key TO
THE ATTACKER — granting continued read access to the shared subtree the
rotation was meant to protect. This is a confidentiality break against the
exact adversary (malicious server) that the zero-knowledge model names as
untrusted.

## Scope / inheritance

This trust assumption is INHERITED, not introduced by Phase 74: initial grant
issuance and the TS owner-reconcile path already source `recipientPublicKey`
through the server, so the sharing feature already trusts the server for
recipient identity binding. Phase 74's contribution is making this re-mint path
reachable on desktop/FUSE for the first time (previously the ROT-04 no-op).

## Fix (if zero-knowledge against recipient-key substitution is required)

Bind `recipient_public_key` to a client-trusted record: pin the recipient key
captured at grant issuance (client-side) and compare it on re-mint, rejecting
if the server-returned key differs. Otherwise, explicitly document that
recipient-identity binding trusts the server as an accepted limitation of the
sharing model.

## Acceptance

Either (a) re-mint compares the server-returned recipient pubkey against a
client-pinned value and fails closed on mismatch, or (b) the sharing threat
model documents server-trusted recipient-identity binding as an accepted risk
with rationale.

## Resolution

Resolved by Phase 80 (rotation-write-plane-and-re-mint-durability), shipped on branch `feat/rotation-write-plane-and-re-mint-durability`. D-01/D-02/D-03/D-04 implemented and verified (SDK-E2E 106/106, fuse 130).
