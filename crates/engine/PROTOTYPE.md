# PROTOTYPE: instant read from the link blob

This branch is throwaway. Do not merge it. It answers one question from [sharing: the engine cost of instant read from the link blob (#1947)](https://github.com/FSM1/cipher-box/issues/1947): what does it cost in the engine to let a read-link holder read at once from the link's grant blob, before the owner converts the claim?

## What the change does

1. Claim. `claim_invite_link` (`src/facade.rs:9161`) posts the claim as before. Then it resolves the scope root that the fragment names and calls `accept_link_share` (`src/grants/link_read.rs:28`). That function runs the accept steps with the ephemeral encryption subkey in place of the device subkey. It persists a bookmark with the label "shared via link" and the invite secret.
2. State. The received-shares list holds the invite secret per bookmark key (`src/grants/accept.rs:204`). The secret is an optional `linkSecret` field in the stored list (`src/grants/accept.rs:425`, `:521`). The list stays sealed under the `ReceivedShares` owner-local kind.
3. Read. `ReceivedShareStatus.refresh` (`src/grants/received_status.rs:405`) re-derives the ephemeral identity from the stored secret. `classified` (`:578`) checks the personal tag first. If the commitment names the personal tag and a blob is there, the pass reads the personal blob. If not, and the bookmark holds a link secret, the pass reads the link blob. A link read is read-only (`:431`).
4. Switch. When a pass reads the personal blob and the bookmark still holds a link secret, the pass drops the secret and persists the list (`:504`). The personal share-pointer accept also drops it (`src/grants/accept.rs:1021`).
5. Write links. `accept_link_share` returns `Ok(None)` for a write link. No link keys are stored for it.

## Divergences from the brief

- No new owner-local store kind. A new kind needs a new `OwnerLocalKind` in `crates/core` and a KAT change. This branch touches `crates/engine` only, so the secret rides the received-shares list.
- The bookmark stores the invite secret, not the two derived keys. The secret is 32 bytes and re-derives both halves.
- The instant read runs inside `claim_invite_link`. A failed resolve fails the command after the claim post. A production version retries the read on the tick.

## Test

`prototype_a_link_holder_reads_at_once_and_switches_after_conversion` (`src/grants/received_status.rs:3353`). It proves: a claim bookmarks the share through the link blob; the first pass renders the folder; conversion switches the pass to the personal blob and drops the secret; a link revoke after the switch leaves the share granted; a link revoke before the switch is a revocation signal.

Run it with `cargo test -p cipherbox-engine prototype_a_link_holder`.
