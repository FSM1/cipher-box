---
created: 2026-07-12T00:00:00.000Z
title: Recipient-pin lifecycle hardening — pruning on revoke, growth bound, atomic issuance
area: sharing-rotation-crypto
severity: medium
source: Phase 80 crypto-privacy-review + security review (2026-07-12) — MEDIUM findings
files:
  - packages/sdk-core/src/folder/registration.ts
  - packages/sdk-core/src/share/recipient-pins.ts
  - packages/sdk/src/rotation/engine.ts
  - crates/sdk/src/rotation/engine.rs
  - apps/web/src/components/file-browser/ShareDialog.tsx
  - docs/METADATA_SCHEMAS.md
resolves_phase: null
---

## Context

Phase 80 (D-03) pins each share recipient's pubkey in the owner-sealed
`NodeWriteBody.recipientPins` and fail-closes re-mint on a server-fed pubkey that
is not pinned. That closes the substituted-relay-pubkey confidentiality break.
Three residual lifecycle gaps remain (all MEDIUM, none a fresh confidentiality
break — the fail-closed direction is always safe):

## 1. Pins are never pruned on revoke (revocation integrity gap)

`registration.ts` makes `recipientPins` a monotonically-growing union that is
never pruned. Revocation deletes the grant row but leaves the revoked
recipient's pin. Because the D-03d check only tests pin membership and grant
rows come from the untrusted relay (`GET /shares/sent`), a malicious relay can
re-inject a grant row for a previously-revoked-but-still-pinned recipient
(`isRevoked=false`); the pin check passes and the owner re-wraps the freshly
rotated read key to the revoked recipient — defeating rotation-based revocation.
Caveat: revocation already relies on relay grant-row honesty, so this is a
defense-in-depth gap, not a fresh break.

Fix: prune the recipient's pin at revocation time (accepting that a genuinely
concurrent re-share re-adds it), OR explicitly document in
`docs/METADATA_SCHEMAS.md` that the pin list does not enforce revocation and
revocation integrity still rests on relay grant-row honesty.

## 2. Unbounded, non-prunable pin-list growth (DoS / write-body bloat)

The CAS-409 merge in `registration.ts` unions local ∪ remote pins on every
publish; `appendRecipientPin` is O(current) per pin → O(n²) per retry, and pins
are never removed. A write-capable co-tenant or accumulation over many
share/revoke cycles grows the sealed write-body without bound; every re-mint
then iterates it. Not an escalation (a junk pin grants nothing without a matching
grant row), but an unbounded-allocation / permanent-bloat vector. Pruning on
revoke (item 1) largely resolves this; otherwise add a length cap.

## 3. Non-atomic share-create → pin-write (revocation liveness) — RESOLVED

RESOLVED during Phase 80 ship (greptile P1 / thread review): `ShareDialog.tsx`
now commits the pin BEFORE creating the server grant (pin-first), so a partial
failure leaves at most a harmless orphan pin, never an unpinned share that blocks
rotation. Residual (still deferred): a cross-client window where a pin added on
web is absent from a FUSE mount's offline `InodeTable` cache until re-resolve —
reconciliation (`owner-reconcile`) could backfill a missing pin for an existing
grant rather than only fail-closed.

## 4. Crash-replay pin preservation for a journaled shared-node write

The routine (non-crash) reseal paths now preserve `recipientPins`
(`build_folder_metadata`, `publish_file_node`, all TS `client.ts` sites). Two
crash-recovery sites still seal pin-less:

- `crates/fuse/src/journal_helpers.rs` `build_upload_journal_entry` (~:328/:456)
  seals the journaled file placeholder with `recipient_pins: Vec::new()`.
- `crates/fuse/src/replay.rs` `replay_upload_entry` (~:1113) re-seals the file
  node with empty pins on replay (it has no `InodeTable`, and its input — the
  journaled placeholder — is already pin-less).

So a shared FILE that is overwritten, journaled, and crash-replayed before its
first publish could republish pin-less. Note this is narrow and likely largely
unreachable in practice: for an already-published (existing) shared file,
`replay::publish_child_node`'s idempotency check skips re-publishing a node that
still resolves, so it does not clobber the pinned record. The failure direction
is fail-closed-safe (a later re-mint hard-fails, requiring reconciliation — no
key leak). A complete fix is coordinated: `build_upload_journal_entry` sources
the file inode's pins into the placeholder (it has `self.inodes` access), and
`replay_upload_entry` decodes + threads them from the placeholder write-body
(mirroring `fetch_splice_publish_parent`). Deferred because it is a
crash-recovery path that cannot be integration-tested locally and the routine
paths already cover ordinary usage.

## 5. File-share recipient pinning is not wired (folder-only issuance)

`client.ts::addRecipientPubkeyPin` reseals the shared node's OWN folder
write-body via `requireFolder` → `ensureFolderLoaded` → `dfsFindFolder`, which
walks the FOLDER tree only. A shared FILE is a leaf child (not a folder-tree
entry), so `addRecipientPubkeyPin(fileIpnsName)` throws "Shared item not loaded".
Consequently file shares are issued WITHOUT an owner-sealed recipient pin (the
`ShareDialog` issuance now skips the pin for `kind === 'file'` to avoid blocking
file sharing — greptile P1 regression). This is a pre-existing D-03 limitation
(the folder-only helper never pinned files), not introduced here.

Impact: if a file share is ever scope-exit re-minted, the D-03e fail-closed pin
check would reject it (no pin) — file-share revocation-rotation would fail
closed. Fix: extend pin issuance to load a file node's own write-body and reseal
its `recipientPins` (or route file-share re-mint to tolerate an absent pin with
an explicit file-share policy). Add a file-share pin round-trip test.

## Acceptance

- Revoking a share prunes the recipient's pin (or the residual relay-trust is
  documented in `METADATA_SCHEMAS.md`), closing the re-inject path.
- Pin-list growth is bounded (via pruning or an explicit cap).
- Share issuance is atomic (pin committed before/with the share row), so a
  partial failure never strands an unpinned share that blocks rotation.
