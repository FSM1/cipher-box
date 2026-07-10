---
created: 2026-07-08T00:00:00.000Z
title: Desktop query_grants_rooted_at is a no-op — scope-exit rotation de-authorizes ALL recipients
area: desktop-fuse-rotation
severity: medium
source: Phase 70.1 plan 09 (sanctioned ROT-04 deferral) + plan 13 SUMMARY; flagged 2026-07-08
files:
  - crates/fuse/src/write_ops/rotation_deps.rs
  - crates/sdk/src/rotation/engine.rs
resolves_phase: 74
---

## Problem

Phase 70.1 wired the production `RotationDeps` adapter (plan 09) so a covered
shared-scope-exit delete/move on the desktop performs `rotate_read_from_node`
and completes. However the adapter's `query_grants_rooted_at` seam is a NO-OP on
desktop: the rotation re-mints the grant-root read key and re-seals the
remaining subtree, but does NOT re-wrap the new key for the recipients who
SHOULD retain access. Net effect: a scope-exit rotation currently
de-authorizes EVERY recipient of the grant, not just the departing item's
implicit exposure — every remaining sharee is cut off until re-shared.

This was an explicitly sanctioned deferral in plan 09 (ROT-04). It makes the
Phase 70.1 desktop-e2e "revoked recipient (Bob) can no longer read" assertion
pass for the wrong reason (everyone is cut, not selectively), so that assertion
must be revisited when this lands.

## Fix

Implement `query_grants_rooted_at` in the FUSE `RotationDeps` adapter (fetch the
active grants rooted at the rotated node from `/shares/sent`) so the engine's
`re_mint_grants_rooted_at` path re-wraps the NEW read key under each retained
recipient's public key — preserving access for still-authorized sharees while
the departed item is cut off.

## Acceptance

After a covered scope-exit delete/move on the desktop: the departed item is
unreachable by prior keys, a still-authorized co-recipient retains read access
to the remaining subtree (their grant is re-minted to the new generation), and
only a genuinely-revoked recipient loses access. Update the Phase 70.1
desktop-e2e leg's "recipient cut off" assertion to distinguish retained vs
revoked recipients.
