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

use core::cell::RefCell;

use cipherbox_core::error::TrustViolation;
use cipherbox_core::hex::lower as hex_lower;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, ChildRef, GrantSetEntry, GrantSetEntryKind, Permission, ReadBody,
    STRUCT_TAG_GRANT_BLOB, open_grant_blob, open_read_body,
};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::content::Gateway;
use crate::entropy::{Entropy, fresh_ephemeral};
use crate::facade::POINTER_PAYLOAD_VERSION;
use crate::gate::floor;
use crate::gate::{
    Candidate, GateError, GateRejection, GateStage, ReaderContext, RejectionReason, SeedBlob,
    adopt, read_cut_epoch_floor, verify_commitment_in_force,
};
use crate::net::rotation::OwnerPointerRead;
use crate::net::{PointerConsult, PointerConsultError, assemble_candidate, fanout_get_verify};
use crate::seams::{
    FloorStore, Http, Mailbox, NoPersistFloorStore, RecordTransport, StagingStore, UnixMillis,
};

use super::accept::{LinkHold, ReceivedShare, ReceivedShareStore, ReceivedSharesLock};
use super::contact::Contact;
use super::contact_store::{StagingContactStore, resolve_recipient};
use super::invite::{EphemeralInvitee, InviteFragment, post_invite_claim};
use super::ledger::{recipient_blinded_tag, self_locate_signed};
use super::received_share_store::StagingReceivedShareStore;
use super::received_status::committed_blob;

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
    /// stands. `personal` is [`LinkEntryRead::Live`]'s.
    Live { root: Box<IpnsName>, personal: bool },
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
    ///
    /// `personal` says whether the same set still grants this account in its
    /// own name. A person the owner cut keeps the bookmark at rest, and ADR
    /// 0025 E4 lets that person join again through another live link, so a
    /// bookmark alone does not make a join a no-op.
    Live {
        root: Box<IpnsName>,
        candidate: Box<Candidate>,
        conversion_permission: Permission,
        personal: bool,
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
    link: &LinkReader<'_>,
    now: UnixMillis,
) -> Result<LinkEntryRead, LinkReadRefusal> {
    let LinkReader {
        share,
        hold,
        owner,
        invitee,
        my_enc_secret,
    } = *link;
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
    let personal = committed_blob(
        &candidate.grant_section,
        my_enc_secret,
        &owner.enc_subkey(),
        name,
    )
    .is_some();
    Ok(LinkEntryRead::Live {
        root: Box::new(root),
        candidate: Box::new(candidate),
        conversion_permission,
        personal,
    })
}

/// What one read through a link reads with: the bookmark the fragment makes,
/// its link keys, the owner the fragment names, and this account's own
/// encryption secret, which locates its own grant in the owner-signed set.
#[derive(Clone, Copy)]
pub(crate) struct LinkReader<'a> {
    pub share: &'a ReceivedShare,
    pub hold: &'a LinkHold,
    pub owner: &'a Contact,
    pub invitee: &'a EphemeralInvitee,
    pub my_enc_secret: &'a X25519Secret,
}

/// The join's one read (ADR 0024 D5), ahead of every write.
pub(crate) async fn join_read<T: RecordTransport, H: Http, F: FloorStore>(
    seams: &JoinSeams<'_, T, H, F>,
    link: &LinkReader<'_>,
    now: UnixMillis,
) -> Result<JoinRead, LinkReadRefusal> {
    Ok(match read_link_entry(seams, link, now).await? {
        LinkEntryRead::Live { root, personal, .. } => JoinRead::Live { root, personal },
        LinkEntryRead::Expired { .. } => JoinRead::Expired,
        LinkEntryRead::Revoked => JoinRead::Revoked,
        LinkEntryRead::Unavailable => JoinRead::Unavailable,
    })
}

/// What the preview read through the link (ADR 0028 D2, D5).
#[derive(Debug)]
pub(crate) enum PreviewRead {
    /// The link stands: the permission conversion grants, the scope root's
    /// direct children, and [`LinkEntryRead::Live`]'s `personal`.
    Live {
        conversion_permission: Permission,
        children: Vec<ChildRef>,
        personal: bool,
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
    link: &LinkReader<'_>,
    now: UnixMillis,
) -> Result<PreviewRead, LinkReadRefusal> {
    let seams = JoinSeams {
        transport: seams.transport,
        gateway: seams.gateway,
        http: seams.http,
        floors: NoPersistFloorStore::over(&seams.floors),
    };
    let (root, candidate, conversion_permission, personal) =
        match read_link_entry(&seams, link, now).await? {
            LinkEntryRead::Live {
                root,
                candidate,
                conversion_permission,
                personal,
            } => (root, candidate, conversion_permission, personal),
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
    let children = open_through_link(
        &seams.floors,
        &candidate,
        &root,
        link.share,
        link.owner,
        link.invitee,
    )
    .await
    .map_err(LinkReadRefusal::Gate)?;
    Ok(match children {
        LinkOpen::Opened(children) => PreviewRead::Live {
            conversion_permission,
            children,
            personal,
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

/// Post again every held claim that is due at `now`, under the key of its first
/// post, and schedule the next post (ADR 0023 D4). A hold past its deadline
/// posts nothing. A failed post waits for its next slot. A list writer, so it
/// holds `list_lock` from the load to the persist.
pub(crate) async fn repost_held_claims<M, St, E>(
    mailbox: &M,
    staging: &St,
    entropy: &RefCell<E>,
    enc_secret: &X25519Secret,
    list_lock: &ReceivedSharesLock,
    v: u64,
    now: UnixMillis,
) where
    M: Mailbox,
    St: StagingStore,
    E: Entropy,
{
    let _list_guard = list_lock.lock().await;
    let store = StagingReceivedShareStore::new(staging, enc_secret, entropy);
    let Ok(mut received) = store.load().await else {
        return;
    };
    let contacts = StagingContactStore::new(staging, enc_secret, entropy);
    let mut posted = false;
    for (key, hold) in received.link_holds_mut() {
        let (true, Some(held)) = (hold.repost_due(now), hold.claim.as_mut()) else {
            continue;
        };
        posted = true;
        held.posted(now);
        let Ok(owner) = resolve_recipient(&contacts, &key.0).await else {
            continue;
        };
        let Ok(invitee) = EphemeralInvitee::from_secret(hold.invite_secret.as_bytes()) else {
            continue;
        };
        let (Ok(ephemeral), Ok(claim)) = (
            fresh_ephemeral(&mut *entropy.borrow_mut()),
            held.claim.encode(),
        ) else {
            continue;
        };
        let _ = post_invite_claim(
            mailbox,
            &owner,
            &invitee,
            &ephemeral,
            v,
            &claim,
            &hex_lower(&held.idempotency_key),
        )
        .await;
    }
    if posted {
        let _ = store.persist(&received).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::kdf;
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use crate::grants::accept::{
        CLAIM_KEY_LEN, CLAIM_MAX_POSTS, CLAIM_REPOST_FIRST_WAIT, CLAIM_REPOST_MAX_WAIT, HeldClaim,
        ReceivedSharesList,
    };
    use crate::grants::contact_store::ContactStore;
    use crate::grants::invite::{CLAIM_ID_LEN, InviteClaim};
    use crate::testkit::fakes::{InMemoryMailboxHub, InMemoryStagingStore};
    use crate::testkit::{SeededEntropy, block_on};

    const OWNER: [u8; 32] = [0x31; 32];
    const HOLDER: [u8; 32] = [0x32; 32];
    const KEY: [u8; CLAIM_KEY_LEN] = [0x6b; CLAIM_KEY_LEN];
    const FIRST: UnixMillis = UnixMillis(1_000);
    const WAIT: u64 = CLAIM_REPOST_FIRST_WAIT;

    /// A holder whose device posted one claim at `FIRST` through a link.
    struct Holder {
        staging: InMemoryStagingStore,
        entropy: RefCell<SeededEntropy>,
        enc: X25519Secret,
        hub: InMemoryMailboxHub,
        owner_pk: Vec<u8>,
    }

    impl Holder {
        fn new(deadline: Option<UnixMillis>) -> Self {
            let staging = InMemoryStagingStore::default();
            let entropy = RefCell::new(SeededEntropy::new(7));
            let enc = kdf::enc_subkey(&HOLDER);
            let owner = EcdsaSigner::from_scalar(&OWNER).expect("valid identity scalar");
            let code = ContactCode::create(&owner, kdf::enc_subkey(&OWNER).public()).encode();
            block_on(StagingContactStore::new(&staging, &enc, &entropy).record(&code))
                .expect("the owner records");
            let pointer =
                IpnsName::from_public_key(&Ed25519Signer::from_seed([0x5d; 32]).verifying_key());
            let share = ReceivedShare {
                scope_root_name: Vec::new(),
                scope_id: [0x8a; 16],
                sharer_identity_pk: owner.verifying_key().to_sec1(),
                display_name: "s".into(),
                permission: Permission::Read,
                pointer_read_key: SecretBytes::new([0x8a; 32]),
            };
            let key = share.key();
            let mut list = ReceivedSharesList::new();
            list.reconcile(share);
            list.hold_link(
                key,
                LinkHold {
                    invite_secret: SecretBytes::new([0x4e; 32]),
                    scope_pointer_name: pointer.clone(),
                    deadline,
                    claim: Some(HeldClaim::first_post(
                        InviteClaim {
                            claim_id: [0x71; CLAIM_ID_LEN],
                            scope_pointer_name: pointer,
                            contact_code: vec![0x02; 40],
                            name: "Grace".to_owned(),
                        },
                        KEY,
                        FIRST,
                    )),
                },
            );
            block_on(StagingReceivedShareStore::new(&staging, &enc, &entropy).persist(&list))
                .expect("the list persists");
            Self {
                staging,
                entropy,
                enc,
                hub: InMemoryMailboxHub::default(),
                owner_pk: owner.verifying_key().to_sec1().to_vec(),
            }
        }

        /// Run the re-post step at `now` and answer every key posted so far.
        fn repost_at(&self, now: u64) -> Vec<String> {
            block_on(repost_held_claims(
                &self.hub.mailbox_for(b"holder"),
                &self.staging,
                &self.entropy,
                &self.enc,
                &ReceivedSharesLock::default(),
                1,
                UnixMillis(now),
            ));
            self.hub.posted_keys(&self.owner_pk)
        }
    }

    /// ADR 0023 D4: a claim posts again when due, under the key of its first
    /// post, and each wait doubles.
    #[test]
    fn a_held_claim_posts_again_under_its_first_key_with_exponential_backoff() {
        let holder = Holder::new(None);
        assert!(
            holder.repost_at(FIRST.0 + WAIT - 1).is_empty(),
            "not due yet"
        );

        let keys = holder.repost_at(FIRST.0 + WAIT);
        assert_eq!(keys, vec![hex_lower(&KEY)], "one post under the first key");
        assert_eq!(
            holder.repost_at(FIRST.0 + 2 * WAIT).len(),
            1,
            "the next wait is twice the first"
        );
        let keys = holder.repost_at(FIRST.0 + 3 * WAIT);
        assert_eq!(keys, vec![hex_lower(&KEY); 2]);
    }

    /// A claim the owner never converts stops at its post bound, so a link
    /// with no deadline does not post for ever.
    #[test]
    fn a_held_claim_stops_at_its_post_bound() {
        let holder = Holder::new(None);
        let mut now = FIRST.0;
        for _ in 0..CLAIM_MAX_POSTS + 5 {
            now += CLAIM_REPOST_MAX_WAIT;
            holder.repost_at(now);
        }
        let reposts = u64::try_from(holder.repost_at(now + CLAIM_REPOST_MAX_WAIT).len())
            .expect("a small count");
        assert_eq!(
            reposts,
            CLAIM_MAX_POSTS - 1,
            "the first post is not a re-post"
        );
    }

    /// ADR 0023 D4: the re-posts stop at the link's deadline.
    #[test]
    fn a_held_claim_posts_nothing_past_the_deadline() {
        let holder = Holder::new(Some(UnixMillis(FIRST.0 + WAIT)));
        assert!(holder.repost_at(FIRST.0 + WAIT).is_empty());
        assert!(holder.repost_at(FIRST.0 + 100 * WAIT).is_empty());
    }
}
