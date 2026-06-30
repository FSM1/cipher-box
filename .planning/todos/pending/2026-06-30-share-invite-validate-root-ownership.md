---
created: 2026-06-30T00:00:00.000Z
title: Validate sharer owns the root before issuing a share invite
area: security
severity: medium
files:
  - apps/api/src/shares/share-invite.service.ts
---

> Deferred from the Phase 66 ship (CodeRabbit major finding, share-invite.service.ts:42).
> CodeRabbit itself tags this a "Heavy lift": it needs an ownership source-of-truth
> decision (which table proves a user owns rootIpnsName/rootNodeId) plus a
> cross-check, so it is not a low-risk in-scope fix.

## Problem

`createInvite` copies `rootIpnsName` and `rootNodeId` straight from the client
DTO into the persisted invite for `sharerId`, with no check that the sharer
actually owns that root or that the `rootIpnsName`/`rootNodeId` pair is
consistent. A spoofed invite (root the sharer does not own, or a mismatched
name/node pair) is later copied verbatim into the `Share` row during claim
(`share-invite.service.ts` mints the Share from invite fields — T-66-S1).

The claim path is already hardened against claimer-side spoofing (root identity
is sourced from the invite, write authority is presence-derived — T-66-E1), but
the INVITE-issuance side trusts the sharer's input unconditionally.

## Proposed fix

Before persisting the invite, verify ownership and pair-consistency:

- Look up the sharer's root (e.g. `ipns_records` / `folder_ipns` row for
  `userId = sharerId` with `ipnsName = rootIpnsName`, or the vault root) and
  confirm it exists and is owned by `sharerId`.
- Confirm `rootNodeId` corresponds to that same root (define the node→root
  mapping that proves the pair).
- Reject with 403/400 on mismatch before save.

## Before doing this

Decide the authoritative ownership lookup for a "root" (vault entity vs
ipns_records.isRoot vs folder tree). This determines whether the check is a
single indexed lookup or needs a new query path.
