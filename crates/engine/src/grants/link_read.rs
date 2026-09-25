//! The link-held read path (ADR 0024 D1, D2, D5).
//!
//! A person who joins through a link reads the folder at once, through the
//! link's own grant blob, until the owner converts the claim into a personal
//! grant. The join records a bookmark that holds the link keys
//! ([`LinkHold`]); the received-share refresh
//! ([`ReceivedShareStatus`](super::received_status)) is the one read path for
//! it, the first read included.
//!
//! A hold reads through the scope pointer the fragment named, never through a
//! root name alone: a write wave moves the scope root, and the pointer's
//! owner-signed re-point object names the root that stands. The old-name
//! tombstone and the mailbox mirror stay accelerators (`CONTEXT.md`
//! "Re-point object").

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{GrantSetEntryKind, GrantSetEntry, Permission};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use zeroize::Zeroizing;

use crate::facade::POINTER_PAYLOAD_VERSION;
use crate::gate::Candidate;
use crate::net::rotation::OwnerPointerRead;
use crate::net::{PointerConsult, PointerConsultError};
use crate::seams::{FloorStore, RecordTransport};

use super::accept::{LinkHold, ReceivedShare};
use super::contact::Contact;
use super::invite::InviteFragment;

/// The label a link-held share shows when the fragment's names do not verify
/// under the owner code (ADR 0027 D5).
pub(crate) const LINK_SHARE_LABEL: &str = "shared via link";

/// The bookmark a join records before its first read, and the link keys it
/// reads through.
///
/// The bookmark names no scope root yet: the first read takes it from the
/// scope pointer. The label is the fragment's folder name when the owner
/// signature over the names verifies, and [`LINK_SHARE_LABEL`] otherwise.
pub(crate) fn pending_link_bookmark(
    fragment: &InviteFragment,
    owner: &Contact,
) -> (ReceivedShare, LinkHold) {
    let owner_identity = owner.identity_pk();
    let display_name = fragment
        .verified_names(&owner_identity)
        .map_or(LINK_SHARE_LABEL, |(_, folder)| folder)
        .to_owned();
    (
        ReceivedShare {
            scope_root_name: Vec::new(),
            scope_id: fragment.scope_id,
            sharer_identity_pk: owner_identity.to_sec1(),
            display_name,
            permission: Permission::Read,
            pointer_read_key: fragment.pointer_read_key.clone(),
        },
        LinkHold::new(
            fragment.invite_secret.clone(),
            fragment.scope_pointer_name.clone(),
        ),
    )
}

/// The pointer read edges of one link hold, as the fragment carried them.
struct HeldPointerKeys<'a> {
    name: &'a IpnsName,
    read_key: &'a SecretBytes,
}

impl OwnerPointerRead for HeldPointerKeys<'_> {
    fn pointer_read_key(&self, _scope_id: &[u8; 16]) -> Zeroizing<[u8; SECRET_LEN]> {
        Zeroizing::new(*self.read_key.as_bytes())
    }

    fn pointer_name(&self, _scope_id: &[u8; 16]) -> IpnsName {
        self.name.clone()
    }
}

/// The scope root `share`'s pointer vouches for now: open the re-point object
/// under the bookmark's pointer read key, verify it under `owner`, and refuse a
/// rolled-back write epoch against `floors`.
///
/// `floors` must be the sharer-scoped view the share's other floors live in.
/// `Ok(None)` when no pointer record stands at the name.
pub(crate) async fn held_scope_root<T: RecordTransport, F: FloorStore>(
    transport: &T,
    floors: &F,
    share: &ReceivedShare,
    hold: &LinkHold,
    owner: &EcdsaVerifier,
) -> Result<Option<IpnsName>, PointerConsultError> {
    let keys = HeldPointerKeys {
        name: &hold.scope_pointer_name,
        read_key: &share.pointer_read_key,
    };
    Ok(PointerConsult {
        scope_keys: &keys,
        owner_identity: owner,
        payload_version: POINTER_PAYLOAD_VERSION,
    }
    .run(transport, floors, &share.scope_id)
    .await?
    .map(|consulted| consulted.current_root))
}

/// The owner-signed link entry at `tag`, or `None` when the commitment names
/// no entry there or names one that is not a link entry.
pub(crate) fn committed_link_entry<'c>(
    candidate: &'c Candidate,
    tag: &[u8; 32],
) -> Option<&'c GrantSetEntry> {
    candidate
        .grant_section
        .commitment
        .entries
        .iter()
        .find(|entry| entry.tag == *tag && entry.kind == GrantSetEntryKind::Link)
}
