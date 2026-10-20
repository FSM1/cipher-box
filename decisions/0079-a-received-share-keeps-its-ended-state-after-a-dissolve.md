# ADR 0079: A received share keeps its ended state after a dissolve

- **Status:** Accepted on 2026-10-19
- **Date:** 2026-10-18
- **Relates to:** [#2298](https://github.com/FSM1/cipher-box/issues/2298),
  [#2469](https://github.com/FSM1/cipher-box/issues/2469),
  [ADR 0077](./0077-a-scope-root-stops-being-one-by-a-re-seal-into-new-node-ids.md) D1 (the final
  records hold for one more EOL term),
  [ADR 0014](./0014-a-verified-commitments-cut-epoch-raises-the-floor-without-an-unseal.md) (the
  cut-epoch floor rises with no unseal),
  [ADR 0006](./0006-owner-local-sealed-store.md) (the received-shares list),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) (a durable record reads the
  previous release)
- **Implemented by:** [#2476](https://github.com/FSM1/cipher-box/pull/2476) (the reader of `ended`
  and `grantCut`), [#2500](https://github.com/FSM1/cipher-box/pull/2500) (the writer)
- **Amends:** —

## Context

An owner-signed root that leaves out the personal tag tells a grantee that the share ended
(`blueprint/engine.md` "Revocation is discovered, not delivered"). After a dissolve, ADR 0077 D1
keeps the final records for one more EOL term, then retires them. After that, the grantee reads
"unresolvable", and a write grantee can raise a false withheld-update escalation. The verdict is
in memory only (`ReceivedVerdicts`). The owner ruled R1 on 2026-10-17 and 2026-10-18: the grantee
keeps "this share ended" after the term.

## Decision

**D1 — A received-share bookmark records the cut that ended the share.** The bookmark
(`received-shares` kind, `0x01`) gets the optional unsigned key `ended`: the cut epoch of the
verified grant-set commitment that left the personal tag out. While the mark is set, the row
reports `RevocationSignal`, and `observe_pointer_pins` skips the bookmark, so no withheld-update
escalation comes from it. The mark stays through an unavailable read, an unresolvable read, an
absent pointer, and a grant blob that is present but does not open. The mark removes no custody
key. A link-held bookmark keeps its revoke path.

**D2 — The engine sets the mark only above an opened-grant baseline, never from the cut-epoch
floor.** The bookmark gets a second optional unsigned key `grantCut`: the cut epoch of the latest
verified commitment in which this device opened its personal grant blob. The engine writes it in
the same bookmark persist as the open (`accept_share` and the refresh). The engine sets
`ended` only when the commitment verifies, the personal tag is not in it, `grantCut` is present,
and the cut epoch of the commitment is above `grantCut`. A bookmark with no `grantCut` never gets
the mark. The bar is strictly above, because an append adds a row at the same cut epoch: a
committed writer can serve the set from before the append, and that is not an owner cut.

**D3 — Only a successful personal open clears the mark.** The engine clears `ended` only when the
personal grant blob opens (`personal_blob_opens`) in a verified commitment at a cut epoch at or
above the mark. A committed tag alone, a blob that does not open, a forged blob and a failed read
do not clear it.

## Alternatives considered

- **Set the mark above the cut-epoch floor (D2).** Rejected: `accept_share` persists the bookmark
  before `PendingAdoption::commit` raises the floor, so a crash between the two leaves a low floor,
  and a later read of the same commitment forges an exclusion. ADR 0014 also raises the floor with
  no unseal, so the floor does not show that this device held a grant.
- **Set the mark from evidence that a writer of the share can forge (D2), option (b).** For
  example, a blob that is absent while the tag is committed, or a tag that is absent at the
  baseline cut epoch. Rejected: a writer can then hide a live grant behind "ended".
- **An owner-signed "ended" notice to the mailbox of each grantee, option (c).** Rejected: it needs
  a new mailbox kind and its own ADR, and `blueprint/api.md` gives unacknowledged mail a 90-day
  TTL, so a device that stays offline past the TTL gets no notice. It can be a later issue.
- **Clear the mark on a committed tag or on blob presence (D3).** Rejected: the classifier gives
  `Granted` from blob presence alone, and a committed writer can strip or forge a blob.

## Consequences

- `blueprint/engine.md` "Grants and ledger": the received-shares bookmark lists `grantCut` and
  `ended` as optional unsigned keys. Older bytes read as absent. A value that is not unsigned
  refuses the whole list and writes nothing.
- `blueprint/engine.md` "Grants and ledger": `reconcile` in `grants/accept.rs` keeps the held
  `ended` in every case and takes the higher of the held and the new `grantCut`. `same_bookmark`
  compares `grantCut`. Each writer of the list writes both keys back. The clear is an in-place edit
  after `reconcile`.
- `blueprint/engine.md` "Revocation is discovered, not delivered": D1 to D3. A bounded backfill
  writes `grantCut`: in each session, each bookmark with no `grantCut` gets at most one refresh
  attempt, within half of the resolve budget of each pass.
- `blueprint/deploy.md` "A new durable staging prefix": the release before the reader refuses the
  whole bookmark list at an unknown key (ADR 0020). So the reader of both keys ships in a tagged
  release before the code that writes them merges.
- `blueprint/testing.md`: the mark sets only above `grantCut`; a replay at `grantCut`, a stripped
  blob, a crash between the persist and the floor commit, and a bookmark with no `grantCut` set
  nothing; a forged blob and a failed open do not clear it; an opened re-grant clears it; no
  withheld-update escalation after the pointer retires; custody keys stay; both keys survive each
  writer; the reader decodes the bookmark list of the release before it.
- The PR that writes `ended` and `grantCut` carries the `blueprint/engine.md` and
  `blueprint/testing.md` rewords.
- Accepted residual, the R1 scope: the owner ruled option (a) on 2026-10-18, a narrowing of the R1
  ruling of 2026-10-17. The mark works only for a share that this device opened at least once under
  the release that writes `grantCut`, before the owner cut it. A share cut before that open shows
  "ended" during the term, then "unresolvable", as before this ADR. No device gets a false mark.
- Accepted residual, the strip residual: after a cut and a re-grant at the same cut epoch, a
  committed writer that serves the cut set again keeps the mark until this device opens the grant.
