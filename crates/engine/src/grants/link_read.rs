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
use cipherbox_core::seal::{GrantSetEntry, GrantSetEntryKind, Permission};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use zeroize::Zeroizing;

use crate::content::Gateway;
use crate::facade::POINTER_PAYLOAD_VERSION;
use crate::gate::{Candidate, read_cut_epoch_floor, verify_commitment_in_force};
use crate::net::rotation::OwnerPointerRead;
use crate::net::{PointerConsult, PointerConsultError, assemble_candidate, fanout_get_verify};
use crate::seams::{FloorStore, Http, RecordTransport, UnixMillis};

use super::accept::{LinkHold, ReceivedShare};
use super::contact::Contact;
use super::invite::{EphemeralInvitee, InviteFragment};
use super::ledger::recipient_blinded_tag;

/// The bookmark a join records before its first read, and the link keys it
/// reads through.
///
/// The bookmark names no scope root yet: the first read takes it from the
/// scope pointer. The label is the fragment's folder name when the owner
/// signature over the names verifies, and empty otherwise, which a host
/// renders as a share through a link (ADR 0027 D5).
pub(crate) fn pending_link_bookmark(
    fragment: &InviteFragment,
    owner: &Contact,
) -> (ReceivedShare, LinkHold) {
    let owner_identity = owner.identity_pk();
    let display_name = fragment
        .verified_names(&owner_identity)
        .map_or("", |(_, folder)| folder)
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

/// The seams the join's own read runs over. `floors` must be the sharer-scoped
/// view the share's floors live in.
pub(crate) struct JoinSeams<'a, T, H, F> {
    pub transport: &'a T,
    pub gateway: &'a Gateway,
    pub http: &'a H,
    pub floors: &'a F,
}

/// What the join's own read found through the link, before a claim posts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JoinRead {
    /// The owner-signed set at `root` commits the link, and its deadline
    /// stands.
    Live { root: Box<IpnsName> },
    /// The link entry's deadline is reached (ADR 0025 D5).
    Expired,
    /// The owner-signed set commits no link entry at the link tag.
    Revoked,
    /// The pointer or the record did not answer, or the record carries no set
    /// the owner signed. The tick reads again under the full gate.
    Unavailable,
}

/// The join's one read (ADR 0024 D5): follow the scope pointer, then read the
/// link entry in the owner-signed set at the root it vouches for. Only a set
/// that verifies under `owner` answers expired or revoked. A refused re-point
/// object is the one error.
pub(crate) async fn join_read<T: RecordTransport, H: Http, F: FloorStore>(
    seams: &JoinSeams<'_, T, H, F>,
    share: &ReceivedShare,
    hold: &LinkHold,
    owner: &Contact,
    invitee: &EphemeralInvitee,
    now: UnixMillis,
) -> Result<JoinRead, PointerConsultError> {
    let owner_identity = owner.identity_pk();
    let root =
        match held_scope_root(seams.transport, seams.floors, share, hold, &owner_identity).await {
            Ok(Some(root)) => root,
            Ok(None) | Err(PointerConsultError::Unavailable) => return Ok(JoinRead::Unavailable),
            Err(PointerConsultError::Rejected) => return Err(PointerConsultError::Rejected),
        };
    let Some((_, record)) = fanout_get_verify(seams.transport, &root).await else {
        return Ok(JoinRead::Unavailable);
    };
    let Ok(candidate) = assemble_candidate(seams.gateway, seams.http, &root, &record, None).await
    else {
        return Ok(JoinRead::Unavailable);
    };
    let Ok(cut_epoch_floor) = read_cut_epoch_floor(seams.floors, &share.scope_id).await else {
        return Ok(JoinRead::Unavailable);
    };
    let name = root.as_str().as_bytes();
    if verify_commitment_in_force(
        &owner_identity,
        &candidate.grant_section,
        name,
        cut_epoch_floor,
    )
    .is_err()
    {
        return Ok(JoinRead::Unavailable);
    }
    let entry = recipient_blinded_tag(invitee.enc_secret(), &owner.enc_subkey(), name)
        .and_then(|tag| committed_link_entry(&candidate, &tag));
    Ok(match entry {
        None => JoinRead::Revoked,
        Some(entry) if now.reached(entry.deadline.map(|at| UnixMillis(at.get()))) => {
            JoinRead::Expired
        }
        Some(_) => JoinRead::Live {
            root: Box::new(root),
        },
    })
}
