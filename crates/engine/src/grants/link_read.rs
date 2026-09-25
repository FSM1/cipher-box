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

use cipherbox_core::error::TrustViolation;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, ChildRef, GrantSetEntry, GrantSetEntryKind, Permission, ReadBody,
    STRUCT_TAG_GRANT_BLOB, open_grant_blob, open_read_body,
};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use zeroize::Zeroizing;

use crate::content::Gateway;
use crate::facade::POINTER_PAYLOAD_VERSION;
use crate::gate::floor;
use crate::gate::{
    Candidate, GateError, GateRejection, GateStage, ReaderContext, RejectionReason, SeedBlob,
    adopt, read_cut_epoch_floor, verify_commitment_in_force,
};
use crate::net::rotation::OwnerPointerRead;
use crate::net::{PointerConsult, PointerConsultError, assemble_candidate, fanout_get_verify};
use crate::seams::{FloorStore, Http, NoPersistFloorStore, RecordTransport, UnixMillis};

use super::accept::{LinkHold, ReceivedShare};
use super::contact::Contact;
use super::invite::{EphemeralInvitee, InviteFragment};
use super::ledger::{recipient_blinded_tag, self_locate_signed};

/// The bookmark a join records before its first read, and the link keys it
/// reads through.
///
/// The bookmark names no scope root yet: the first read takes it from the
/// scope pointer. `display_name` is the fragment's folder name when the owner
/// signature over the names verifies, and empty otherwise, which a host
/// renders as a share through a link (ADR 0027 D5).
pub(crate) fn pending_link_bookmark(
    fragment: &InviteFragment,
    owner: &Contact,
    display_name: String,
) -> (ReceivedShare, LinkHold) {
    (
        ReceivedShare {
            scope_root_name: Vec::new(),
            scope_id: fragment.scope_id,
            sharer_identity_pk: owner.identity_pk().to_sec1(),
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
    pub floors: F,
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

/// One read of the link entry through the scope pointer, shared by the join
/// and the preview.
enum LinkEntryRead {
    /// The owner-signed set at `root` commits the link, and its deadline
    /// stands. `candidate` is that record, for the caller that opens it.
    Live {
        root: Box<IpnsName>,
        candidate: Box<Candidate>,
        conversion_permission: Permission,
    },
    Expired {
        conversion_permission: Permission,
    },
    Revoked,
    Unavailable,
}

/// Follow the scope pointer, then read the link entry in the owner-signed set
/// at the root it vouches for (ADR 0024 D5). Only a set that verifies under
/// `owner` answers expired or revoked. A refused re-point object, a head block
/// the gate rejects, and a commitment that does not verify are the errors.
async fn read_link_entry<T: RecordTransport, H: Http, F: FloorStore>(
    seams: &JoinSeams<'_, T, H, F>,
    share: &ReceivedShare,
    hold: &LinkHold,
    owner: &Contact,
    invitee: &EphemeralInvitee,
    now: UnixMillis,
) -> Result<LinkEntryRead, LinkReadRefusal> {
    let owner_identity = owner.identity_pk();
    let root =
        match held_scope_root(seams.transport, &seams.floors, share, hold, &owner_identity).await {
            Ok(Some(root)) => root,
            Ok(None) | Err(PointerConsultError::Unavailable) => {
                return Ok(LinkEntryRead::Unavailable);
            }
            Err(PointerConsultError::Rejected) => return Err(LinkReadRefusal::Repoint),
        };
    let Some((_, record)) = fanout_get_verify(seams.transport, &root).await else {
        return Ok(LinkEntryRead::Unavailable);
    };
    let candidate = match assemble_candidate(seams.gateway, seams.http, &root, &record, None).await
    {
        Ok(candidate) => candidate,
        Err(GateError::Rejected(rejection)) => return Err(LinkReadRefusal::Gate(rejection)),
        Err(GateError::Seam(_)) => return Ok(LinkEntryRead::Unavailable),
    };
    let Ok(cut_epoch_floor) = read_cut_epoch_floor(&seams.floors, &share.scope_id).await else {
        return Ok(LinkEntryRead::Unavailable);
    };
    let name = root.as_str().as_bytes();
    verify_commitment_in_force(
        &owner_identity,
        &candidate.grant_section,
        name,
        cut_epoch_floor,
    )
    .map_err(|e| {
        LinkReadRefusal::Gate(GateRejection {
            stage: GateStage::CommitmentVerify,
            reason: RejectionReason::Trust(e),
        })
    })?;
    let Some(entry) = recipient_blinded_tag(invitee.enc_secret(), &owner.enc_subkey(), name)
        .and_then(|tag| committed_link_entry(&candidate, &tag))
    else {
        return Ok(LinkEntryRead::Revoked);
    };
    let Some(conversion_permission) = entry.conversion_permission else {
        return Ok(LinkEntryRead::Revoked);
    };
    if now.reached(entry.deadline.map(|at| UnixMillis(at.get()))) {
        return Ok(LinkEntryRead::Expired {
            conversion_permission,
        });
    }
    Ok(LinkEntryRead::Live {
        root: Box::new(root),
        candidate: Box::new(candidate),
        conversion_permission,
    })
}

/// The join's one read (ADR 0024 D5), ahead of every write.
pub(crate) async fn join_read<T: RecordTransport, H: Http, F: FloorStore>(
    seams: &JoinSeams<'_, T, H, F>,
    share: &ReceivedShare,
    hold: &LinkHold,
    owner: &Contact,
    invitee: &EphemeralInvitee,
    now: UnixMillis,
) -> Result<JoinRead, LinkReadRefusal> {
    Ok(
        match read_link_entry(seams, share, hold, owner, invitee, now).await? {
            LinkEntryRead::Live { root, .. } => JoinRead::Live { root },
            LinkEntryRead::Expired { .. } => JoinRead::Expired,
            LinkEntryRead::Revoked => JoinRead::Revoked,
            LinkEntryRead::Unavailable => JoinRead::Unavailable,
        },
    )
}

/// What the preview read through the link (ADR 0028 D2, D5).
#[derive(Debug)]
pub(crate) enum PreviewRead {
    /// The link stands: the permission conversion grants, and the scope
    /// root's direct children.
    Live {
        conversion_permission: Permission,
        children: Vec<ChildRef>,
    },
    Expired {
        conversion_permission: Permission,
    },
    Revoked,
    Unavailable,
}

/// A trust verdict that refuses a read through a link. Availability is never
/// one.
#[derive(Debug)]
pub(crate) enum LinkReadRefusal {
    /// The scope pointer's re-point object was refused.
    Repoint,
    /// The adoption gate refused the scope root's commitment or its open.
    Gate(GateRejection),
}

/// The preview's read (ADR 0028 D3): the join's read, then one open of the
/// scope root through the link's grant blob under the adoption gate. It runs
/// over a view of `seams.floors` that persists nothing, so it raises no floor.
pub(crate) async fn preview_read<T: RecordTransport, H: Http, F: FloorStore>(
    seams: &JoinSeams<'_, T, H, F>,
    share: &ReceivedShare,
    hold: &LinkHold,
    owner: &Contact,
    invitee: &EphemeralInvitee,
    now: UnixMillis,
) -> Result<PreviewRead, LinkReadRefusal> {
    let seams = JoinSeams {
        transport: seams.transport,
        gateway: seams.gateway,
        http: seams.http,
        floors: NoPersistFloorStore::over(&seams.floors),
    };
    let (root, candidate, conversion_permission) =
        match read_link_entry(&seams, share, hold, owner, invitee, now).await? {
            LinkEntryRead::Live {
                root,
                candidate,
                conversion_permission,
            } => (root, candidate, conversion_permission),
            LinkEntryRead::Expired {
                conversion_permission,
            } => {
                return Ok(PreviewRead::Expired {
                    conversion_permission,
                });
            }
            LinkEntryRead::Revoked => return Ok(PreviewRead::Revoked),
            LinkEntryRead::Unavailable => return Ok(PreviewRead::Unavailable),
        };
    let children = open_through_link(&seams.floors, &candidate, &root, share, owner, invitee)
        .await
        .map_err(LinkReadRefusal::Gate)?;
    Ok(match children {
        LinkOpen::Opened(children) => PreviewRead::Live {
            conversion_permission,
            children,
        },
        LinkOpen::NoBlob => PreviewRead::Revoked,
        LinkOpen::Unavailable => PreviewRead::Unavailable,
    })
}

enum LinkOpen {
    Opened(Vec<ChildRef>),
    /// The set commits the link entry, but no grant blob stands at its tag.
    NoBlob,
    Unavailable,
}

/// Open the scope root through the link's grant blob under the adoption gate.
/// A record at exactly the sequence floor, at or above the read-epoch floor,
/// is the one this account already adopted, and reads as the tick's
/// equal-floor recovery reads it.
async fn open_through_link<F: FloorStore>(
    floors: &F,
    candidate: &Candidate,
    root: &IpnsName,
    share: &ReceivedShare,
    owner: &Contact,
    invitee: &EphemeralInvitee,
) -> Result<LinkOpen, GateRejection> {
    let refused = |e| GateRejection {
        stage: GateStage::Unseal,
        reason: RejectionReason::Trust(e),
    };
    let envelope = &candidate.envelope;
    if envelope.id != share.scope_id || envelope.scope != share.scope_id {
        return Err(refused(TrustViolation::SealOpenFailed.into()));
    }
    let Some(blob) = recipient_blinded_tag(
        invitee.enc_secret(),
        &owner.enc_subkey(),
        root.as_str().as_bytes(),
    )
    .and_then(|tag| self_locate_signed(&candidate.grant_section.grant_blobs, &tag)) else {
        return Ok(LinkOpen::NoBlob);
    };
    let aad = AadContext {
        v: envelope.v,
        id: envelope.id,
        scope: envelope.scope,
        epoch: envelope.epoch,
        struct_tag: STRUCT_TAG_GRANT_BLOB,
    };
    let grant = open_grant_blob(invitee.enc_secret(), &blob.enc, &aad, &blob.ciphertext)
        .map_err(refused)?;
    let node_seed = kdf::node_seed(grant.read_scope_seed(), &envelope.id);
    let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());
    let owner_identity = owner.identity_pk();
    let reader = ReaderContext {
        owner_identity: &owner_identity,
        scope_id: share.scope_id,
        read_key: &read_key,
        parent_node_seed: None,
        seed_blob: Some(SeedBlob::Grantee {
            enc_secret: invitee.enc_secret(),
            enc: blob.enc,
            ciphertext: blob.ciphertext.clone(),
            aad,
        }),
    };
    let body = match adopt(floors, &reader, candidate).await {
        Ok((adopted, _)) => adopted.read_body,
        Err(GateError::Seam(_)) => return Ok(LinkOpen::Unavailable),
        Err(GateError::Rejected(rejection)) => {
            let RejectionReason::SequenceNotNewer { floor, sequence } = rejection.reason else {
                return Err(rejection);
            };
            let Ok(epoch_floor) = floor::read_epoch_floor(floors, &share.scope_id).await else {
                return Ok(LinkOpen::Unavailable);
            };
            if sequence != floor || envelope.epoch < epoch_floor.unwrap_or(0) {
                return Err(rejection);
            }
            open_read_body(envelope, &read_key).map_err(refused)?
        }
    };
    Ok(LinkOpen::Opened(match body {
        ReadBody::Folder { children, .. } => children,
        ReadBody::File { .. } => Vec::new(),
    }))
}
