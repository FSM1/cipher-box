---
created: 2026-02-22T00:00
title: Research CRDT-based IPNS inbox for serverless share discovery
area: architecture
related:
  - .planning/todos/pending/2026-02-21-ipns-resolution-alternatives.md
  - .planning/phases/14-user-to-user-sharing/14-CONTEXT.md
  - .planning/todos/pending/2026-02-21-move-root-folder-key-to-ipfs.md
---

## Summary

Research using CRDTs over IPNS as a decentralized share discovery mechanism, replacing the centralized `shares` table. This is part of a broader strategy to solve IPNS write-conflict issues once as a horizontal concern rather than working around them per-feature.

## Context

Phase 14 chose server-side share records (PostgreSQL `shares`/`share_keys` tables) over metadata-embedded ACLs. The server knows the sharing graph (who shared with whom) but never sees plaintext keys. This was the right pragmatic tradeoff, but it moves further from the serverless ideal.

A recurring pattern across CipherBox: every time we hit an IPNS limitation (write conflicts, resolution flakiness, last-writer-wins), we bolt on a centralized workaround (DB-cached CIDs, share tables, pinned_cids tracking). Each workaround is individually reasonable, but collectively they erode the serverless premise. Solving IPNS reliability and conflict resolution as a horizontal concern would unblock multiple features simultaneously.

## Core Idea: IPNS Inbox with CRDT Content Model

### Share Discovery via Deterministic IPNS Address

Derive a per-recipient IPNS "inbox" address from their public key:

```text
inbox_ipns_privkey = HKDF(recipient_pubkey, info="share-inbox")
inbox_ipns_name    = derive_public(inbox_ipns_privkey)
```

- Sharers publish encrypted share invitations (ECIES-wrapped keys) to the recipient's inbox
- Recipients resolve their own inbox IPNS to discover shares
- Content encrypted so only recipient can decrypt
- Server never sees the sharing graph

### Why CRDTs Solve the Write-Conflict Problem

The naive IPNS inbox has a fundamental issue: IPNS is last-writer-wins, so concurrent shares from different users overwrite each other. CRDTs (Conflict-free Replicated Data Types) turn this weakness into a feature:

- **G-Set (Grow-only Set):** Share invitations are append-only — new shares are added, never removed from the inbox. A G-Set merges concurrent additions without conflict.
- **OR-Set (Observed-Remove Set):** If revocation needs to remove entries, OR-Set supports both add and remove with deterministic conflict resolution.
- Each write includes the full CRDT state. Concurrent writers produce valid states that merge on read.

### Cross-Cutting Benefit

The same CRDT-over-IPNS pattern applies to other conflict-prone areas:

- **Folder metadata sync** — concurrent edits from multiple devices
- **Device registry** — multiple devices registering simultaneously
- **Share inbox** — multiple sharers publishing to the same recipient
- **Any future multi-writer state**

Solving this once gives all features coordination-free merging.

## Known Challenges to Investigate

### Write Access Control

If the IPNS private key is derivable from public information (recipient's pubkey), anyone can publish to the inbox. Possible mitigations:

- **Spam tolerance via encryption:** Attacker can write junk but can't forge valid encrypted invitations (would need to know a valid share key)
- **Signed envelopes:** Each invitation signed by the sharer's key — recipient verifies sender authenticity and ignores unsigned/invalid entries
- **Per-pair ECDH channels:** `HKDF(ECDH(sharer_priv, recipient_pub), info="share-channel")` — only the two parties can derive the key. But kills open discovery (recipient must try ECDH with every known pubkey)

### IPNS Reliability

This approach makes IPNS reliability _more_ critical, not less. Pairs with the sibling IPNS resolution alternatives todo — any solution there directly benefits this approach.

### Revocation

Currently a DB flag (`revoked_at`). With IPNS inbox:

- Sharer can't "un-publish" an invitation the recipient already cached
- Revocation becomes eventually-consistent at best
- May need to separate "discovery" (inbox) from "access" (key rotation) — revoke by rotating the shared folder's key, not by modifying the inbox

### State Size Growth

CRDT state grows monotonically (especially G-Set). Need a compaction/garbage-collection strategy for long-lived inboxes.

## Relationship to Existing Work

- **IPNS resolution alternatives todo:** Solving resolution reliability is a prerequisite. Self-hosted IPNS or improved caching directly benefits this approach.
- **Phase 14 trade-offs:** This is a third option beyond "server-side records" and "metadata-embedded ACLs" — a decentralized discovery layer that keeps metadata schemas clean.
- **Move rootFolderKey to IPFS todo:** Same philosophical direction — reducing server-side state.

## Success Criteria

- Identify a CRDT data structure suitable for share invitations (likely G-Set or OR-Set)
- Prototype write-conflict resolution: two concurrent IPNS publishes to the same inbox merge correctly on read
- Evaluate whether the write-access-control problem is solvable without reintroducing a centralized component
- Determine if this pattern generalizes to folder metadata sync (the bigger win)
- Assess IPNS publish/resolve latency impact of CRDT-encoded content vs current approach
