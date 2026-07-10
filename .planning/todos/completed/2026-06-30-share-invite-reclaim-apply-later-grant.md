---
created: 2026-06-30T00:00:00.000Z
title: Apply (or explicitly reject) a later invite's grant when a share already exists
area: data-integrity
severity: low
files:
  - apps/api/src/shares/share-invite.service.ts
---

> Deferred from the Phase 66 ship (CodeRabbit major finding, share-invite.service.ts:184).
> Current behavior fails SAFE (it never escalates access), and changing it needs a
> share-upgrade/merge semantics decision, so it is a deliberate design question
> rather than a low-risk in-scope fix.

## Problem

In `claimInvite`, when a `Share` already exists for the (sharer, recipient,
rootNodeId) triple, the invite is marked claimed and the method returns the
existing `shareId` WITHOUT applying the new invite's `readDescriptorRef`,
optional `writeDescriptorRef`, or `rootGeneration`. So a recipient who first
accepted a read-only invite and later claims a write (or newer-generation)
invite "succeeds" but keeps their stale read-only access.

This fails safe today — the recipient ends up with LESS access than the new
invite grants, never more, so it is not an escalation vulnerability — but the
write/generation upgrade is silently dropped, which is surprising.

## Proposed fix (decision required)

Pick one:

1. **Upgrade-merge:** when the existing share is found, update its
   `readDescriptorRef` / `writeDescriptorRef` / `rootGeneration` from the new
   (validated) invite before returning. Must preserve the T-66-E1 invariant:
   write authority is presence-derived from the INVITE
   (`invite.writeDescriptorRef !== null`), never from claimer input. Only ever
   widen access from a legitimately-issued invite; never let a read-only invite
   downgrade/clobber an existing write grant.
2. **Reject:** if the new invite's grant differs from the existing share, throw a
   conflict BEFORE consuming the invite, and require an explicit re-share /
   rotation flow to change access.

Add unit coverage for read→write re-claim and generation-bump re-claim.
