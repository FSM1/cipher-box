//! What a bookmarked shared scope root answers with now, as the facts
//! [`super::revocation`] classifies (blueprint/web-client.md "/shared";
//! #25 D3/D4).
//!
//! Revocation is discovered, not delivered, so every fact here comes from a live
//! resolve of the scope root the bookmark names — never from the bookmark's own
//! copy of the permission or the label, which the owner may have superseded.
//! Both anchors are the **verified contact's**: the identity the commitment must
//! verify under, and the encryption subkey the self-locating tag folds in. A key
//! the resolved record supplied would let the record vouch for itself.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, ChildRef, ReadBody, STRUCT_TAG_GRANT_BLOB, open_grant_blob, open_read_body,
    verify_grant_set_bound,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use futures_channel::mpsc;
use zeroize::Zeroizing;

use crate::content::Gateway;
use crate::entropy::Entropy;
use crate::facade::{Event, NodeId, NodeKind, ScopeSeeds, deposit_seed};
use crate::gate::floor;
use crate::gate::{Candidate, ReaderContext, RejectionReason, SeedBlob, adopt};
use crate::net::rotation::scope_name;
use crate::net::{assemble_candidate, fanout_get_verify};
use crate::profile::SyncTimingProfile;
use crate::seams::{
    FloorStore, Http, RecordTransport, SharerScopedFloorStore, StagingStore, UnixMillis,
};
use crate::sync::model::{NodeMeta, Snapshot};
use crate::sync::project::project_folder;
use crate::sync::tick::on_access_refresh_due;

use super::accept::ReceivedShareStore;
use super::accept::{BookmarkKey, ReceivedShare};
use super::contact::Contact;
use super::contact_store::{ContactStore, StagingContactStore};
use super::grafted::GraftedSharers;
use super::ledger::{recipient_blinded_tag, self_locate_signed};
use super::received_share_store::StagingReceivedShareStore;
use super::revocation::{ResolutionClass, ResolutionFacts, classify};

/// How many shared scope roots one pass resolves. Each costs a fan-out GET and
/// a head fetch, and a bookmarked set may hold
/// [`MAX_RECEIVED_SHARES`](super::accept::MAX_RECEIVED_SHARES) — the rest keep
/// their held verdict and stay due for the next pass.
const MAX_RESOLVES_PER_PASS: usize = 16;

/// One shared scope's last resolution verdict, and when the pass that reached
/// it ran — the stamp the refresh damper paces against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceivedVerdict {
    /// What the resolve classified.
    pub class: ResolutionClass,
    /// When the pass that reached it ran.
    pub at: UnixMillis,
}

/// Each bookmarked shared scope's latest verdict, keyed the way the bookmark
/// itself is ([`BookmarkKey`]). Two sharers may hold one scope id, and the id
/// alone would collapse their rows onto one verdict cell.
pub(crate) type ReceivedVerdicts = BTreeMap<BookmarkKey, ReceivedVerdict>;

/// Where an adopted shared scope lands: the render tree a focus reads
/// (blueprint/web-client.md "/shared": browsing a shared scope is the same
/// browser over the same snapshot), the per-scope read-seed cache the leg below
/// its root reads with, and the repaint signal a merge emits.
pub(crate) struct ScopeRender<'a> {
    /// The last-known-good render tree.
    pub base: &'a RefCell<Snapshot>,
    /// Scope id -> the recovered read scope seed.
    pub read_seeds: &'a RefCell<ScopeSeeds>,
    /// Which identity granted each scope root the tree holds by graft — the
    /// floor namespace every leg below such a root must read in.
    pub grafted_sharers: &'a RefCell<GraftedSharers>,
    /// The host event stream.
    pub events: &'a mpsc::UnboundedSender<Event>,
}

/// The seams one received-share resolve reads, plus this device's own
/// encryption subkey — the self-locating tag's other half. Borrowed: the
/// session stays its terminal owner.
pub(crate) struct ReceivedShareStatus<'a, T, H, F> {
    /// The record plane the scope root resolves over.
    pub transport: &'a T,
    /// The content read source for the record's head block.
    pub gateway: &'a Gateway,
    /// The HTTP seam that fetch rides.
    pub http: &'a H,
    /// The durable floors — the read-epoch floor an epoch lag is measured
    /// against.
    pub floors: &'a F,
    /// This device's encryption subkey.
    pub enc_secret: &'a X25519Secret,
}

impl<T: RecordTransport, H: Http, F: FloorStore> ReceivedShareStatus<'_, T, H, F> {
    /// Re-classify the bookmarked shared scope roots that are due, into
    /// `verdicts`.
    ///
    /// Paced by [`on_access_refresh_due`], the same damper the focus window's
    /// folder leg uses, and capped at [`MAX_RESOLVES_PER_PASS`]: an undamped
    /// pass over a full bookmark list would not finish inside its own tick, and
    /// the legs after it would never run. A verdict not re-reached this pass is
    /// carried forward.
    ///
    /// Rebuilt each pass, so a share the list no longer holds leaves no verdict
    /// behind. A store failure leaves the last pass's verdicts standing rather
    /// than blanking them.
    pub(crate) async fn refresh<St, E>(
        &self,
        staging: &St,
        entropy: &RefCell<E>,
        verdicts: &RefCell<ReceivedVerdicts>,
        render: &ScopeRender<'_>,
        now: UnixMillis,
        profile: &SyncTimingProfile,
    ) where
        St: StagingStore,
        E: Entropy,
    {
        let Ok(received) = StagingReceivedShareStore::new(staging, self.enc_secret, entropy)
            .load()
            .await
        else {
            return;
        };
        // Ahead of the contact book, which costs one signature verify per entry
        // to decode: a vault that has accepted nothing pays none of it.
        if received.iter().next().is_none() {
            verdicts.borrow_mut().clear();
            render.grafted_sharers.borrow_mut().clear();
            return;
        }
        let Ok(contacts) = StagingContactStore::new(staging, self.enc_secret, entropy)
            .contacts()
            .await
        else {
            return;
        };
        // Indexed once: `to_sec1` re-encodes a point, so a scan per share would
        // pay that per (share, contact) pair.
        let by_identity: BTreeMap<[u8; IDENTITY_PUBLIC_LEN], &Contact> = contacts
            .iter()
            .map(|contact| (contact.identity_pk().to_sec1(), contact))
            .collect();

        // A browse addresses a scope by its id alone, but the id is the sharer's
        // to author: `granted_scope_roots` decides ambiguity over every bookmark,
        // and an id two of them claim answers for neither. Only what survives
        // that rule may reach the render tree.
        let renderable: BTreeSet<[u8; 16]> = received
            .granted_scope_roots()
            .into_iter()
            .map(|granted| granted.scope_id)
            .collect();
        // Every bookmarked scope id, ambiguous ones included: a third sharer may
        // not name as its own child an id that two others contest.
        let scope_roots: BTreeSet<[u8; 16]> = received.iter().map(|share| share.scope_id).collect();
        // Rebuilt each pass, like the verdicts. It covers every renderable
        // scope and not only the ones this pass grafts: a revoked share keeps
        // the listing it last rendered, and the leg below it must keep reading
        // the floor that revoked it.
        *render.grafted_sharers.borrow_mut() = received
            .iter()
            .filter(|share| renderable.contains(&share.scope_id))
            .map(|share| (share.scope_id, share.sharer_identity_pk))
            .collect();

        let mut refreshed = BTreeMap::new();
        let mut budget = MAX_RESOLVES_PER_PASS;
        for share in received.iter() {
            let key = share.key();
            let held = verdicts.borrow().get(&key).copied();
            let due = held.is_none_or(|held| on_access_refresh_due(now, held.at, profile));
            if !due || budget == 0 {
                if let Some(held) = held {
                    refreshed.insert(key, held);
                }
                continue;
            }
            budget -= 1;
            // Both anchors are contact-held, so a forgotten sharer leaves no
            // verified identity to hold the record to.
            let Some(contact) = by_identity.get(&share.sharer_identity_pk) else {
                refreshed.insert(
                    key,
                    ReceivedVerdict {
                        class: ResolutionClass::Unresolvable,
                        at: now,
                    },
                );
                continue;
            };
            // One resolve serves both legs: the verdict this row renders, and
            // the subtree a browse of it opens.
            let (candidate, epoch_floor) = self.resolved(share).await;
            let class = match &candidate {
                Some(candidate) => classify(&facts_from(
                    candidate,
                    share,
                    self.enc_secret,
                    &contact.identity_pk(),
                    &contact.enc_subkey(),
                    epoch_floor,
                )),
                None => classify(&ResolutionFacts::unresolved(epoch_floor)),
            };
            if class == ResolutionClass::Granted && renderable.contains(&share.scope_id) {
                if let Some(candidate) = &candidate {
                    self.graft(candidate, share, contact, epoch_floor, render, &scope_roots)
                        .await;
                }
            }
            refreshed.insert(key, ReceivedVerdict { class, at: now });
        }
        *verdicts.borrow_mut() = refreshed;
    }

    /// `share`'s floors, filed under the identity that granted it.
    ///
    /// The sharer authors its own `scopeId`, so a floor read or raised under the
    /// plain id reaches every other sharer's scope of that id and this vault's
    /// own anchored root scope.
    fn sharer_floors(&self, share: &ReceivedShare) -> SharerScopedFloorStore<'_, F> {
        SharerScopedFloorStore::granted_by(self.floors, share.sharer_identity_pk)
    }

    /// The record `share`'s scope root answers with now, and the read-epoch
    /// floor every verdict on it is measured against. `None` is absence — an
    /// unparsable bookmark, an unresolvable name, an unassemblable record, or a
    /// floor this pass could not read — never a removal.
    async fn resolved(&self, share: &ReceivedShare) -> (Option<Candidate>, u64) {
        // A floor this pass could not read is availability, not a verdict: with
        // no floor the epoch-lag rung cannot fire, so a stale record would read
        // as granted. Absent (`Ok(None)`) is a genuine zero.
        let Ok(epoch_floor) =
            floor::read_epoch_floor(&self.sharer_floors(share), &share.scope_id).await
        else {
            return (None, 0);
        };
        let epoch_floor = epoch_floor.unwrap_or(0);
        let unresolved = (None, epoch_floor);

        let Ok(name) = scope_name(&share.scope_root_name) else {
            return unresolved;
        };
        let Some((verified, record_bytes)) = fanout_get_verify(self.transport, &name).await else {
            return unresolved;
        };
        // Fan-out has no memory — it answers with the best of what endpoints
        // served. A suppressing relay could otherwise re-serve the record that
        // still committed this device and pin the verdict at `Granted`. Read the
        // durable bar only; a body this pass never unsealed may not raise it
        // (the floor law's provenance rule).
        let Ok(sequence_floor) = floor::sequence_floor(self.floors, &share.scope_root_name).await
        else {
            return unresolved;
        };
        if sequence_floor.is_some_and(|floor| verified.sequence < floor) {
            return unresolved;
        }
        let Ok(candidate) =
            assemble_candidate(self.gateway, self.http, &name, &record_bytes, None).await
        else {
            return unresolved;
        };
        (Some(candidate), epoch_floor)
    }

    /// Merge the accepted scope's own folder into the render tree, and cache the
    /// read scope seed the leg below its root reads with.
    ///
    /// Two records may render, and no third. A strictly-newer one adopts through
    /// the gate. One at exactly the durable sequence floor, at or above the
    /// read-epoch floor, is the record this vault already adopted, so re-rendering
    /// it downgrades nothing — the equal-floor recovery the owner's own root leg
    /// makes, and sound for the same reason: the gate authenticates the grant
    /// section under the contact-anchored owner identity before any floor stage
    /// runs.
    async fn graft(
        &self,
        candidate: &Candidate,
        share: &ReceivedShare,
        contact: &Contact,
        epoch_floor: u64,
        render: &ScopeRender<'_>,
        scope_roots: &BTreeSet<[u8; 16]>,
    ) {
        // A scope root is the node its own scope is named for, and the bookmark
        // opens under that id. The reader-scope bind is stage 6's, so state it
        // here too: the equal-floor arm below unseals without reaching stage 6.
        if candidate.envelope.id != share.scope_id || candidate.envelope.scope != share.scope_id {
            return;
        }
        // The scope root is a node id like any other, and a sharer authors it.
        // One this vault's own tree holds would be renamed here and pruned to the
        // children this body names. A root another *sharer's* subtree holds is
        // grafted anyway: a foreign body can link any id under its own folders,
        // and refusing on that alone would let one contact deny another contact's
        // share for good.
        if in_own_tree(&render.base.borrow(), NodeId(share.scope_id)) {
            return;
        }
        let Some(tag) = recipient_blinded_tag(
            self.enc_secret,
            &contact.enc_subkey(),
            &share.scope_root_name,
        ) else {
            return;
        };
        let Some(blob) = self_locate_signed(&candidate.grant_section.grant_blobs, &tag) else {
            return;
        };
        let aad = AadContext {
            v: candidate.envelope.v,
            id: candidate.envelope.id,
            scope: candidate.envelope.scope,
            epoch: candidate.envelope.epoch,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        };
        let Ok(grant) = open_grant_blob(self.enc_secret, &blob.enc, &aad, &blob.ciphertext) else {
            return;
        };
        let node_seed = kdf::node_seed(grant.read_scope_seed(), &candidate.envelope.id);
        let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());
        let reader = ReaderContext {
            owner_identity: &contact.identity_pk(),
            scope_id: share.scope_id,
            read_key: &read_key,
            parent_node_seed: None,
            seed_blob: Some(SeedBlob::Grantee {
                enc_secret: self.enc_secret,
                enc: blob.enc,
                ciphertext: blob.ciphertext.clone(),
                aad,
            }),
        };
        // The seed's stamp is the epoch that entitles it: an adopt names the one
        // it just raised the floor to, and an equal-floor recovery takes the
        // pre-resolve floor, so no record can extend its own seed's residency.
        let opened = match adopt(&self.sharer_floors(share), &reader, candidate).await {
            Ok((adopted, _)) => Some((adopted.read_body, adopted.sequence, adopted.epoch)),
            Err(e) => match e.rejection().map(|r| &r.reason) {
                Some(RejectionReason::SequenceNotNewer { floor, sequence })
                    if sequence == floor && candidate.envelope.epoch >= epoch_floor =>
                {
                    open_read_body(&candidate.envelope, &read_key)
                        .ok()
                        .map(|body| (body, *sequence, epoch_floor))
                }
                _ => None,
            },
        };
        let Some((
            ReadBody::Folder {
                modified_at,
                children,
                ..
            },
            sequence,
            epoch,
        )) = opened
        else {
            return;
        };
        deposit_seed(
            render.read_seeds,
            share.scope_id,
            Zeroizing::new(*grant.read_scope_seed()),
            Some(epoch),
        );

        let root = NodeId(share.scope_id);
        let mut base = render.base.borrow_mut();
        let children: Vec<ChildRef> = children
            .into_iter()
            .filter(|child| {
                !claimed_elsewhere(&base, NodeId(child.id), share.scope_id, scope_roots)
            })
            .collect();
        // The scope root has no parent here to name it, so the pointer's label
        // is the only name a browse can show.
        let named = match base.node_mut(root) {
            Some(meta) if meta.name() != share.display_name => {
                meta.rename(share.display_name.clone());
                true
            }
            Some(_) => false,
            None => {
                let mut meta = NodeMeta::new(root, share.display_name.clone(), NodeKind::Folder);
                meta.ipns_name = Some(share.scope_root_name.clone());
                base.upsert_node(meta);
                true
            }
        };
        if project_folder(&mut base, root, &children, sequence, modified_at) || named {
            let _ = render.events.unbounded_send(Event::SnapshotUpdated);
        }
    }
}

/// Whether `id` is already spoken for by a plane other than the grafted scope
/// `under`: this vault's own tree, or any other bookmarked scope root and the
/// subtree below it.
///
/// A sharer names their own nodes only. [`project_folder`] never unlinks the old
/// parent, so a link accepted for an id another tree already holds would leave
/// the node under both, and the higher `link_counter` would win it
/// ([`Snapshot::winning_link`]). The rule covers the grafted root as well as its
/// children: the root is a node id like any other, and a body that names one
/// another tree holds would rename that node and prune it to its own children.
///
/// Ambiguous ids count. A scope id two bookmarks claim renders for neither, so a
/// third sharer must not reach it either.
fn claimed_elsewhere(
    base: &Snapshot,
    id: NodeId,
    under: [u8; 16],
    scope_roots: &BTreeSet<[u8; 16]>,
) -> bool {
    let foreign_root = |node: NodeId| node.0 != under && scope_roots.contains(&node.0);
    in_own_tree(base, id) || foreign_root(id) || base.ancestors(id).into_iter().any(foreign_root)
}

/// Whether `id` is a node this vault's own tree holds.
fn in_own_tree(base: &Snapshot, id: NodeId) -> bool {
    id == base.root || base.is_descendant_of(id, base.root)
}

/// What a resolved scope root supports, as a pure function of the record and the
/// verified contact anchors.
///
/// A commitment that does not verify under `sharer_identity`, or that is bound
/// to another name, is not a fresh owner-signed record — an untrusted party
/// republishing at that name proves nothing about your grant, so it classifies
/// as unresolvable rather than as a removal.
pub(crate) fn facts_from(
    candidate: &Candidate,
    share: &ReceivedShare,
    my_enc_secret: &X25519Secret,
    sharer_identity: &EcdsaVerifier,
    sharer_enc_pub: &X25519Public,
    epoch_floor: u64,
) -> ResolutionFacts {
    let scope_root_name = share.scope_root_name.as_slice();
    // The epoch below is measured against `share.scope_id`'s floor, so the
    // record must claim that scope — the binding the adoption gate makes, on a
    // path that reaches no verdict from unsealing.
    if candidate.envelope.scope != share.scope_id {
        return ResolutionFacts::unresolved(epoch_floor);
    }
    let section = &candidate.grant_section;
    let owner_signed = EcdsaSignature::from_compact(&section.commitment_sig).is_some_and(|sig| {
        verify_grant_set_bound(sharer_identity, &section.commitment, &sig, scope_root_name).is_ok()
    });
    if !owner_signed {
        return ResolutionFacts::unresolved(epoch_floor);
    }
    // The owner-signed commitment is the authority, so a blob at an uncommitted
    // tag is not a grant: it counts as removal, the same verdict the accept flow
    // reaches by refusing an uncommitted tag.
    let blob_present = recipient_blinded_tag(my_enc_secret, sharer_enc_pub, scope_root_name)
        .is_some_and(|tag| {
            section.commitment.entries.iter().any(|e| e.tag == tag)
                && self_locate_signed(&section.grant_blobs, &tag).is_some()
        });
    ResolutionFacts {
        owner_signed_record: true,
        blob_present,
        record_epoch: candidate.envelope.epoch,
        epoch_floor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::ipns::{IpnsName, IpnsRecord};
    use cipherbox_core::kdf;
    use cipherbox_core::seal::{NodeKind as CoreNodeKind, Permission, PreservedFields};
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::{EcdsaSigner, IDENTITY_PUBLIC_LEN};
    use cipherbox_core::suite::secret::SecretBytes;

    use crate::content::GatewaySource;
    use crate::rotation::derive_write_name;
    use crate::seams::{EndpointId, HttpResponse};
    use crate::seams::{FloorRaise, SeamError, SeamResult};
    use crate::testkit::fakes::InMemoryFloorStore;
    use crate::testkit::fakes::{InMemoryRecordStore, InMemoryStagingStore, ScriptedHttp};
    use crate::testkit::{
        OWNER_ROOT_EPOCH, OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootFixture, OwnerRootSpec,
        SeededEntropy, block_on, owner_root_fixture,
    };

    use super::super::accept::ReceivedSharesList;
    use super::super::ledger::mint_grant_row;
    use super::super::revocation::{ResolutionClass, classify};

    const SCOPE: [u8; 16] = [0x5c; 16];
    /// This vault's own root, which the shared scope is grafted in beside.
    const VAULT_ROOT: [u8; 16] = [0u8; 16];
    const SHARER_IDENTITY_PK: [u8; IDENTITY_PUBLIC_LEN] = [0x02; IDENTITY_PUBLIC_LEN];
    fn sharer_signer() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x31; 32]).expect("valid scalar")
    }

    /// The sharer's encryption subkey — the blinded tag's owner-side half.
    fn sharer_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x33; 32])
    }

    /// This device's encryption subkey.
    fn my_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x44; 32])
    }

    fn scope_root_name() -> IpnsName {
        derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE)
    }

    /// The published scope root at the shared scope, committing a grant to each
    /// recipient in `recipients`.
    fn published(sharer: &EcdsaSigner, recipients: &[&X25519Public]) -> OwnerRootFixture {
        let name = scope_root_name();
        let grants = recipients
            .iter()
            .map(|recipient| {
                mint_grant_row(
                    sharer,
                    &sharer_enc(),
                    SHARER_IDENTITY_PK,
                    recipient,
                    &SCOPE,
                    name.as_str().as_bytes(),
                    Permission::Read,
                )
                .expect("a contributory recipient key")
            })
            .collect();
        owner_root_fixture(OwnerRootSpec {
            owner_identity: sharer,
            owner_enc: &sharer_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            grants,
            parent_node_seed: None,
            owner_write_blob_epoch: None,
            write_history_link: Vec::new(),
        })
    }

    /// That same root as the candidate a resolve would assemble.
    fn resolved(sharer: &EcdsaSigner, recipients: &[&X25519Public]) -> Candidate {
        let fixture = published(sharer, recipients);
        Candidate {
            name: fixture.name,
            record_bytes: Vec::new(),
            grant_section: fixture.grant_section,
            envelope: fixture.envelope,
        }
    }

    /// The bookmark an accept left behind for the shared scope.
    fn bookmark() -> ReceivedShare {
        ReceivedShare {
            scope_root_name: scope_root_name().as_str().as_bytes().to_vec(),
            scope_id: SCOPE,
            sharer_identity_pk: SHARER_IDENTITY_PK,
            display_name: "shared-folder".to_owned(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([0x9a; 32]),
        }
    }

    fn classify_at(candidate: &Candidate, sharer: &EcdsaSigner, floor: u64) -> ResolutionClass {
        classify(&facts_from(
            candidate,
            &bookmark(),
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            floor,
        ))
    }

    /// A floor store that answers every read with a seam failure, and a record
    /// plane that serves the shared scope root — so the only thing standing
    /// between this resolve and `Granted` is how the failed floor read is
    /// treated.
    struct UnreadableFloors;

    impl FloorStore for UnreadableFloors {
        async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn sequence_floor(&self, _name: &[u8]) -> SeamResult<Option<u64>> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn raise_sequence_floor(&self, _name: &[u8], _seq: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn commit_floors(&self, _raises: &[FloorRaise]) -> SeamResult<()> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn clear(&self) -> SeamResult<()> {
            Err(SeamError::new("floor store unavailable"))
        }
    }

    /// A floor store that answers the read-epoch floor and fails the per-name
    /// sequence floor — the shape that reaches the replay-bar rung.
    struct UnreadableSequenceFloor;

    impl FloorStore for UnreadableSequenceFloor {
        async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
            Ok(None)
        }
        async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn sequence_floor(&self, _name: &[u8]) -> SeamResult<Option<u64>> {
            Err(SeamError::new("sequence floor unavailable"))
        }
        async fn raise_sequence_floor(&self, _name: &[u8], _seq: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn commit_floors(&self, _raises: &[FloorRaise]) -> SeamResult<()> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn clear(&self) -> SeamResult<()> {
            Err(SeamError::new("floor store unavailable"))
        }
    }

    /// The published scope root and a record plane serving it — everything a
    /// resolve needs except the floor store under test.
    struct ServedScopeRoot {
        fixture: OwnerRootFixture,
        records: InMemoryRecordStore,
        http: ScriptedHttp,
        gateway: Gateway,
    }

    impl ServedScopeRoot {
        fn new(sharer: &EcdsaSigner) -> ServedScopeRoot {
            let fixture = published(sharer, &[&my_enc().public()]);
            let endpoint = EndpointId::new("e0");
            let records = InMemoryRecordStore::new(vec![endpoint.clone()]);
            records.seed_record(
                &endpoint,
                fixture.name.as_str(),
                IpnsRecord::create_v2(
                    &kdf::ipns_keypair(
                        kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE).as_bytes(),
                    ),
                    format!("/ipfs/{}", fixture.head_cid_str).as_bytes(),
                    1,
                    2_000_000_000,
                    "2099-01-01T00:00:00Z",
                )
                .marshal(),
            );
            ServedScopeRoot {
                fixture,
                records,
                http: ScriptedHttp::default(),
                gateway: Gateway {
                    accelerator: None,
                    public_fallbacks: vec![GatewaySource::public("https://gateway.invalid")],
                },
            }
        }

        fn resolve<F: FloorStore>(&self, floors: &F, sharer: &EcdsaSigner) -> ResolutionClass {
            self.http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: self.fixture.head_block.clone(),
            });
            let (candidate, epoch_floor) = block_on(
                ReceivedShareStatus {
                    transport: &self.records,
                    gateway: &self.gateway,
                    http: &self.http,
                    floors,
                    enc_secret: &my_enc(),
                }
                .resolved(&bookmark()),
            );
            classify(&match candidate {
                Some(candidate) => facts_from(
                    &candidate,
                    &bookmark(),
                    &my_enc(),
                    &sharer.verifying_key(),
                    &sharer_enc().public(),
                    epoch_floor,
                ),
                None => ResolutionFacts::unresolved(epoch_floor),
            })
        }
    }

    /// The epoch-lag rung is measured against a floor read from the host. With
    /// no floor the rung can never fire, so a failed read must reach "no
    /// verdict" rather than the `Granted` this very record would otherwise earn.
    #[test]
    fn a_floor_the_host_cannot_read_reaches_no_verdict() {
        let sharer = sharer_signer();
        let served = ServedScopeRoot::new(&sharer);

        // The same resolve against a readable floor store is `Granted` — the
        // record, the commitment and the blob are all in order.
        assert_eq!(
            served.resolve(&InMemoryFloorStore::default(), &sharer),
            ResolutionClass::Granted
        );
        assert_eq!(
            served.resolve(&UnreadableFloors, &sharer),
            ResolutionClass::Unresolvable,
            "an unread floor is availability, never a verdict"
        );
    }

    /// The replay bar is what keeps a suppressing relay from re-serving the
    /// record that still committed this device and pinning the verdict at
    /// `Granted`, so a sequence floor the host cannot read is absence too.
    #[test]
    fn an_unreadable_sequence_floor_reaches_no_verdict() {
        let sharer = sharer_signer();
        assert_eq!(
            ServedScopeRoot::new(&sharer).resolve(&UnreadableSequenceFloor, &sharer),
            ResolutionClass::Unresolvable,
            "an unread replay bar is availability, never a verdict"
        );
    }

    /// The epoch is measured against the bookmarked scope's floor, so a record
    /// claiming another scope is not evidence about this one.
    #[test]
    fn a_record_that_claims_another_scope_is_unresolvable() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let facts = facts_from(
            &candidate,
            &ReceivedShare {
                scope_id: [0x11; 16],
                ..bookmark()
            },
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            OWNER_ROOT_EPOCH,
        );
        assert_eq!(classify(&facts), ResolutionClass::Unresolvable);
    }

    #[test]
    fn a_committed_blob_at_your_tag_is_still_granted() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        assert_eq!(
            classify_at(&candidate, &sharer, OWNER_ROOT_EPOCH),
            ResolutionClass::Granted
        );
    }

    /// The definitive removal: the owner republished the committed set without
    /// you, so a fresh owner-signed record carries no blob at your tag.
    #[test]
    fn a_fresh_owner_signed_record_without_your_blob_is_a_revocation_signal() {
        let sharer = sharer_signer();
        let someone_else = X25519Secret::from_scalar([0x55; 32]).public();
        let candidate = resolved(&sharer, &[&someone_else]);
        assert_eq!(
            classify_at(&candidate, &sharer, OWNER_ROOT_EPOCH),
            ResolutionClass::RevocationSignal
        );
    }

    /// A blob is not authority — the owner-signed commitment is. A record
    /// carrying a blob at your tag that the commitment does not name is a
    /// removal, the verdict the accept flow reaches by refusing that tag.
    #[test]
    fn a_blob_the_commitment_does_not_name_is_a_revocation_signal() {
        let sharer = sharer_signer();
        let someone_else = X25519Secret::from_scalar([0x55; 32]).public();
        let mine = resolved(&sharer, &[&my_enc().public()]);
        // The owner's signed set names only the other recipient; the record
        // still carries this device's blob.
        let mut candidate = resolved(&sharer, &[&someone_else]);
        candidate
            .grant_section
            .grant_blobs
            .extend(mine.grant_section.grant_blobs.iter().cloned());

        let facts = facts_from(
            &candidate,
            &bookmark(),
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            OWNER_ROOT_EPOCH,
        );
        assert!(
            facts.owner_signed_record,
            "the owner's own commitment still verifies"
        );
        assert_eq!(classify(&facts), ResolutionClass::RevocationSignal);
    }

    /// A record another party republished at that name proves nothing about your
    /// grant, so it is never read as a removal.
    #[test]
    fn a_record_the_sharer_did_not_sign_is_unresolvable_never_a_revocation() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let impostor = EcdsaSigner::from_scalar(&[0x71; 32]).expect("valid scalar");

        assert_eq!(
            classify_at(&candidate, &impostor, OWNER_ROOT_EPOCH),
            ResolutionClass::Unresolvable,
        );
    }

    /// The same holds for a commitment bound to some other scope root: it is the
    /// sharer's signature over a different name, not a verdict on this one.
    #[test]
    fn a_commitment_bound_to_another_name_is_unresolvable() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let facts = facts_from(
            &candidate,
            &ReceivedShare {
                scope_root_name: b"some-other-scope-root".to_vec(),
                ..bookmark()
            },
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            OWNER_ROOT_EPOCH,
        );
        assert_eq!(classify(&facts), ResolutionClass::Unresolvable);
    }

    /// Still committed, but behind the durable read-epoch floor: a sweep-pending
    /// staleness, never a revocation.
    #[test]
    fn a_still_committed_record_below_the_floor_is_epoch_lag() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        assert_eq!(
            classify_at(&candidate, &sharer, OWNER_ROOT_EPOCH + 1),
            ResolutionClass::EpochLag
        );
    }

    // -----------------------------------------------------------------------
    // The render leg: an accepted scope's subtree, in the tree a focus reads.
    // -----------------------------------------------------------------------

    /// A child of the shared scope root, as its read body names one.
    fn shared_child(id: u8, name: &str) -> ChildRef {
        ChildRef {
            id: [id; 16],
            name: name.to_owned(),
            ipns_name: vec![id],
            kind: CoreNodeKind::Folder,
            link_counter: 1,
            unknown: PreservedFields::new(),
        }
    }

    /// The whole grantee side: the sharer's published scope root serving
    /// `children`, this vault's durable bookmark and contact book, and the render
    /// tree a focus reads.
    struct RenderedScope {
        fixture: OwnerRootFixture,
        records: InMemoryRecordStore,
        http: ScriptedHttp,
        gateway: Gateway,
        floors: InMemoryFloorStore,
        staging: InMemoryStagingStore,
        entropy: RefCell<SeededEntropy>,
        base: RefCell<Snapshot>,
        read_seeds: RefCell<ScopeSeeds>,
        grafted_sharers: RefCell<GraftedSharers>,
        verdicts: RefCell<ReceivedVerdicts>,
    }

    impl RenderedScope {
        fn new(children: Vec<ChildRef>) -> Self {
            Self::rooted_at(children, VAULT_ROOT)
        }

        /// The same world, with this vault's own root anchored at `vault_root`.
        fn rooted_at(children: Vec<ChildRef>, vault_root: [u8; 16]) -> Self {
            let sharer = sharer_signer();
            let name = scope_root_name();
            let grants = vec![
                mint_grant_row(
                    &sharer,
                    &sharer_enc(),
                    sharer.verifying_key().to_sec1(),
                    &my_enc().public(),
                    &SCOPE,
                    name.as_str().as_bytes(),
                    Permission::Read,
                )
                .expect("a contributory recipient key"),
            ];
            let fixture = owner_root_fixture(OwnerRootSpec {
                owner_identity: &sharer,
                owner_enc: &sharer_enc().public(),
                scope_id: SCOPE,
                root_id: SCOPE,
                children,
                child_scope_index: Vec::new(),
                grants,
                parent_node_seed: None,
                owner_write_blob_epoch: None,
                write_history_link: Vec::new(),
            });
            let endpoint = EndpointId::new("e0");
            let records = InMemoryRecordStore::new(vec![endpoint.clone()]);
            records.seed_record(
                &endpoint,
                fixture.name.as_str(),
                IpnsRecord::create_v2(
                    &kdf::ipns_keypair(
                        kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE).as_bytes(),
                    ),
                    format!("/ipfs/{}", fixture.head_cid_str).as_bytes(),
                    1,
                    2_000_000_000,
                    "2099-01-01T00:00:00Z",
                )
                .marshal(),
            );
            let fx = Self {
                fixture,
                records,
                http: ScriptedHttp::default(),
                gateway: Gateway {
                    accelerator: None,
                    public_fallbacks: vec![GatewaySource::public("https://gateway.invalid")],
                },
                floors: InMemoryFloorStore::default(),
                staging: InMemoryStagingStore::default(),
                entropy: RefCell::new(SeededEntropy::new(9)),
                base: RefCell::new(Snapshot::new(NodeId(vault_root))),
                read_seeds: RefCell::new(ScopeSeeds::new()),
                grafted_sharers: RefCell::new(GraftedSharers::new()),
                verdicts: RefCell::new(ReceivedVerdicts::new()),
            };
            block_on(
                StagingContactStore::new(&fx.staging, &my_enc(), &fx.entropy)
                    .record(&ContactCode::create(&sharer_signer(), sharer_enc().public()).encode()),
            )
            .expect("the sharer's code imports");
            fx
        }

        /// Bookmark every served scope, as an accept would have.
        fn bookmark(&self) {
            self.bookmark_sharers(&[sharer_signer().verifying_key().to_sec1()]);
        }

        /// Bookmark the shared scope once per identity in `sharers` — the same
        /// `scopeId` claimed by each, which is what a second sharer minting that
        /// id looks like from here.
        fn bookmark_sharers(&self, sharers: &[[u8; IDENTITY_PUBLIC_LEN]]) {
            let mut list = ReceivedSharesList::new();
            for sharer in sharers {
                list.reconcile(ReceivedShare {
                    scope_root_name: scope_root_name().as_str().as_bytes().to_vec(),
                    scope_id: SCOPE,
                    sharer_identity_pk: *sharer,
                    display_name: "shared-folder".to_owned(),
                    permission: Permission::Read,
                    pointer_read_key: SecretBytes::new([0x9a; 32]),
                });
            }
            block_on(
                StagingReceivedShareStore::new(&self.staging, &my_enc(), &self.entropy)
                    .persist(&list),
            )
            .expect("the bookmarks persist");
        }

        /// Bookmark the shared scope, plus a second accepted scope at `other`
        /// from the same sharer. `other` names a root no record is seeded at, so
        /// it resolves to nothing and only its renderable id matters here.
        fn bookmark_with_extra_scope(&self, other: [u8; 16]) {
            let mut list = ReceivedSharesList::new();
            for (scope, name) in [
                (SCOPE, scope_root_name()),
                (
                    other,
                    derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &other),
                ),
            ] {
                list.reconcile(ReceivedShare {
                    scope_root_name: name.as_str().as_bytes().to_vec(),
                    scope_id: scope,
                    sharer_identity_pk: sharer_signer().verifying_key().to_sec1(),
                    display_name: "shared-folder".to_owned(),
                    permission: Permission::Read,
                    pointer_read_key: SecretBytes::new([0x9a; 32]),
                });
            }
            block_on(
                StagingReceivedShareStore::new(&self.staging, &my_enc(), &self.entropy)
                    .persist(&list),
            )
            .expect("the bookmarks persist");
        }

        /// One received-share pass, with the head block its resolve fetches
        /// served.
        fn pass(&self, at_millis: u64) -> ResolutionClass {
            self.http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: self.fixture.head_block.clone(),
            });
            let (events, _rx) = mpsc::unbounded();
            block_on(
                ReceivedShareStatus {
                    transport: &self.records,
                    gateway: &self.gateway,
                    http: &self.http,
                    floors: &self.floors,
                    enc_secret: &my_enc(),
                }
                .refresh(
                    &self.staging,
                    &self.entropy,
                    &self.verdicts,
                    &ScopeRender {
                        base: &self.base,
                        read_seeds: &self.read_seeds,
                        grafted_sharers: &self.grafted_sharers,
                        events: &events,
                    },
                    UnixMillis(at_millis),
                    &SyncTimingProfile::CI,
                ),
            );
            self.verdicts
                .borrow()
                .get(&(sharer_signer().verifying_key().to_sec1(), SCOPE))
                .map_or(ResolutionClass::Unresolvable, |verdict| verdict.class)
        }

        /// The names the render tree lists under the shared scope root.
        fn listing(&self) -> Vec<String> {
            self.base
                .borrow()
                .children(NodeId(SCOPE))
                .into_iter()
                .map(|child| child.name().to_owned())
                .collect()
        }
    }

    /// The gap this leg closes: a member could read a share's standing but never
    /// open it, because nothing grafted the accepted scope into the tree a focus
    /// resolves against.
    #[test]
    fn an_accepted_scope_root_and_its_children_reach_the_render_tree() {
        let fx = RenderedScope::new(vec![
            shared_child(0xa1, "photos"),
            shared_child(0xa2, "notes"),
        ]);
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        let base = fx.base.borrow();
        let root = base
            .node(NodeId(SCOPE))
            .expect("the accepted scope root is a node a focus can name");
        assert_eq!(root.kind, NodeKind::Folder);
        assert_eq!(
            root.name(),
            "shared-folder",
            "the pointer's label is the only name a browse can show"
        );
        drop(base);
        assert_eq!(fx.listing(), vec!["photos".to_owned(), "notes".to_owned()]);
    }

    /// The read scope seed the leg below the root needs is recovered from the
    /// grant blob, not persisted — so it must land in the per-scope cache the
    /// focus leg reads.
    #[test]
    fn an_accepted_scope_caches_the_read_seed_its_subtree_is_read_with() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert!(
            fx.read_seeds.borrow().contains_key(&SCOPE),
            "the subtree below the root has read material to resolve with"
        );
    }

    /// A scope no accept ever bookmarked is not this vault's to render, however
    /// resolvable its record is.
    #[test]
    fn a_scope_the_accept_never_reached_renders_nothing() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);

        fx.pass(0);

        assert!(
            fx.base.borrow().node(NodeId(SCOPE)).is_none(),
            "an unbookmarked scope is no part of the tree"
        );
        assert!(fx.read_seeds.borrow().is_empty());
    }

    /// `scopeId` is the sharer's to author and every vault anchors its own root
    /// at the same id, so a bookmark that names this vault's anchor must render
    /// nothing — it would otherwise rename the vault root and unlink every child
    /// the sharer's body does not list.
    #[test]
    fn a_bookmark_at_this_vaults_own_root_scope_grafts_nothing() {
        let fx = RenderedScope::rooted_at(vec![shared_child(0xa1, "photos")], SCOPE);
        fx.base.borrow_mut().upsert_node(NodeMeta::new(
            NodeId([0x11; 16]),
            "mine",
            NodeKind::Folder,
        ));
        fx.base
            .borrow_mut()
            .link_next(NodeId(SCOPE), NodeId([0x11; 16]));
        fx.bookmark();

        fx.pass(0);

        assert_eq!(
            fx.listing(),
            vec!["mine".to_owned()],
            "this vault's own tree stands"
        );
        assert!(
            fx.read_seeds.borrow().is_empty(),
            "and its seed is untouched"
        );
    }

    /// A sharer names their own children. An id this vault already owns is not
    /// one of them, so a foreign body cannot relink a node out of the vault and
    /// under the shared root.
    #[test]
    fn a_child_id_this_vault_already_owns_is_not_grafted() {
        let mine = [0x11; 16];
        let fx = RenderedScope::new(vec![
            shared_child(0xa1, "photos"),
            ChildRef {
                id: mine,
                name: "stolen".to_owned(),
                ipns_name: vec![0x11],
                kind: CoreNodeKind::Folder,
                link_counter: 9,
                unknown: PreservedFields::new(),
            },
        ]);
        fx.base
            .borrow_mut()
            .upsert_node(NodeMeta::new(NodeId(mine), "mine", NodeKind::Folder));
        fx.base
            .borrow_mut()
            .link_next(NodeId(VAULT_ROOT), NodeId(mine));
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        let base = fx.base.borrow();
        assert_eq!(base.parent_of(NodeId(mine)), Some(NodeId(VAULT_ROOT)));
        assert_eq!(
            base.node(NodeId(mine)).expect("still held").name(),
            "mine",
            "and the sharer could not rename it either"
        );
    }

    /// `project_folder` never unlinks a child's old parent, so a child id this
    /// sharer does not own would leave the node under two parents, and the
    /// higher `link_counter` would hand it to the sharer. Another accepted
    /// scope's root is such an id: it is parentless, so the vault-root filter
    /// alone lets it through.
    #[test]
    fn another_accepted_scopes_root_is_not_grafted_as_a_child() {
        let other = [0x77; 16];
        let fx = RenderedScope::new(vec![
            shared_child(0xa1, "photos"),
            ChildRef {
                id: other,
                name: "stolen-scope".to_owned(),
                ipns_name: vec![0x77],
                kind: CoreNodeKind::Folder,
                link_counter: 9,
                unknown: PreservedFields::new(),
            },
        ]);
        fx.base
            .borrow_mut()
            .upsert_node(NodeMeta::new(NodeId(other), "theirs", NodeKind::Folder));
        fx.bookmark_with_extra_scope(other);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        let base = fx.base.borrow();
        assert_eq!(
            base.parent_of(NodeId(other)),
            None,
            "the other scope root stays parentless"
        );
        assert_eq!(
            base.node(NodeId(other)).expect("still held").name(),
            "theirs",
            "and this sharer could not rename it"
        );
    }

    /// The same rule one level down: a node already linked below another
    /// accepted scope belongs to that sharer's tree, not to this one.
    #[test]
    fn a_node_inside_another_accepted_scope_is_not_grafted_as_a_child() {
        let other = [0x77; 16];
        let theirs = [0x78; 16];
        let fx = RenderedScope::new(vec![
            shared_child(0xa1, "photos"),
            ChildRef {
                id: theirs,
                name: "stolen-node".to_owned(),
                ipns_name: vec![0x78],
                kind: CoreNodeKind::Folder,
                link_counter: 9,
                unknown: PreservedFields::new(),
            },
        ]);
        {
            let mut base = fx.base.borrow_mut();
            base.upsert_node(NodeMeta::new(NodeId(other), "theirs", NodeKind::Folder));
            base.upsert_node(NodeMeta::new(NodeId(theirs), "their-doc", NodeKind::Folder));
            base.link_next(NodeId(other), NodeId(theirs));
        }
        fx.bookmark_with_extra_scope(other);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        let base = fx.base.borrow();
        assert_eq!(
            base.parent_of(NodeId(theirs)),
            Some(NodeId(other)),
            "the node stays under the sharer that owns it"
        );
        assert_eq!(
            base.node(NodeId(theirs)).expect("still held").name(),
            "their-doc",
            "and this sharer could not rename it"
        );
    }

    /// A browse addresses a scope by its id alone, but the sharer authors that
    /// id, so two sharers can each claim one. Neither subtree may then render:
    /// an open on that id could only guess which sharer it meant.
    #[test]
    fn a_scope_id_two_sharers_claim_renders_for_neither() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark_sharers(&[
            sharer_signer().verifying_key().to_sec1(),
            SHARER_IDENTITY_PK,
        ]);

        fx.pass(0);

        assert!(
            fx.base.borrow().node(NodeId(SCOPE)).is_none(),
            "the contested id is no part of the tree"
        );
        assert!(
            fx.read_seeds.borrow().is_empty(),
            "and no sharer's seed is cached under it"
        );
        assert!(
            fx.grafted_sharers.borrow().is_empty(),
            "and no floor namespace answers for it either"
        );
    }

    /// The leg below a grafted root reads that root's epoch floors under the
    /// identity that granted it, so the pass that grafts must record who did.
    #[test]
    fn a_grafted_scope_records_the_identity_that_granted_it() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(
            fx.grafted_sharers.borrow().get(&SCOPE).copied(),
            Some(sharer_signer().verifying_key().to_sec1())
        );
    }

    /// A scope root is a node id like any other, and the sharer authors it. A
    /// body whose root names a node this vault already holds would rename that
    /// node and prune it to the children the body lists.
    #[test]
    fn a_scope_root_at_a_node_this_vault_owns_grafts_nothing() {
        let kept = [0x11; 16];
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        {
            let mut base = fx.base.borrow_mut();
            base.upsert_node(NodeMeta::new(NodeId(SCOPE), "mine", NodeKind::Folder));
            base.link_next(NodeId(VAULT_ROOT), NodeId(SCOPE));
            base.upsert_node(NodeMeta::new(NodeId(kept), "keep", NodeKind::Folder));
            base.link_next(NodeId(SCOPE), NodeId(kept));
        }
        fx.bookmark();

        fx.pass(0);

        assert_eq!(
            fx.listing(),
            vec!["keep".to_owned()],
            "this vault's own subtree stands"
        );
        assert_eq!(
            fx.base
                .borrow()
                .node(NodeId(SCOPE))
                .expect("still held")
                .name(),
            "mine",
            "and the sharer could not rename it"
        );
        assert!(fx.read_seeds.borrow().is_empty());
    }

    /// The dangerous shape is the transition, not the fresh state. A scope that
    /// already grafted, and that a second bookmark then contests, must lose its
    /// floor namespace with the authority it lost — the leg below it refuses
    /// rather than falling back to this vault's own plane.
    #[test]
    fn a_scope_contested_after_it_grafted_leaves_the_floor_map() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        assert_eq!(fx.pass(0), ResolutionClass::Granted);
        assert!(fx.grafted_sharers.borrow().contains_key(&SCOPE));

        fx.bookmark_sharers(&[
            sharer_signer().verifying_key().to_sec1(),
            SHARER_IDENTITY_PK,
        ]);
        fx.pass(60_000);

        assert!(
            fx.grafted_sharers.borrow().is_empty(),
            "no identity answers for a contested id"
        );
    }

    /// The steady state: the transport re-serves the record this vault already
    /// adopted on every later pass. That record is at the durable floor, so the
    /// gate refuses to re-adopt it — and the listing must still stand rather than
    /// vanish behind the refusal.
    #[test]
    fn a_re_resolve_at_the_durable_floor_keeps_the_listing_it_already_rendered() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        // Past the on-access damper, so the second pass genuinely re-resolves.
        assert_eq!(fx.pass(60_000), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        assert!(fx.read_seeds.borrow().contains_key(&SCOPE));
    }
}
