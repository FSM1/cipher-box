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
use std::collections::BTreeMap;

use cipherbox_core::seal::verify_grant_set_bound;
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

use crate::content::Gateway;
use crate::entropy::Entropy;
use crate::gate::Candidate;
use crate::gate::floor;
use crate::net::rotation::scope_name;
use crate::net::{assemble_candidate, fanout_get_verify};
use crate::profile::SyncTimingProfile;
use crate::seams::{
    FloorStore, Http, RecordTransport, SharerScopedFloorStore, StagingStore, UnixMillis,
};
use crate::sync::tick::on_access_refresh_due;

use super::accept::ReceivedShareStore;
use super::accept::{BookmarkKey, ReceivedShare};
use super::contact::Contact;
use super::contact_store::{ContactStore, StagingContactStore};
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
            let class = match by_identity.get(&share.sharer_identity_pk) {
                Some(contact) => classify(
                    &self
                        .facts(share, &contact.identity_pk(), &contact.enc_subkey())
                        .await,
                ),
                // Both anchors are contact-held, so a forgotten sharer leaves no
                // verified identity to hold the record to.
                None => ResolutionClass::Unresolvable,
            };
            refreshed.insert(key, ReceivedVerdict { class, at: now });
        }
        *verdicts.borrow_mut() = refreshed;
    }

    /// The facts `share`'s scope root supports right now: resolve it, then hold
    /// what came back to the contact anchors ([`facts_from`]).
    ///
    /// Every failure classifies as "no fresh owner-signed record" — an
    /// unparsable bookmark, an unresolvable name, an unassemblable record, and
    /// a floor the host could not read are all absence, never a removal.
    pub(crate) async fn facts(
        &self,
        share: &ReceivedShare,
        sharer_identity: &EcdsaVerifier,
        sharer_enc_pub: &X25519Public,
    ) -> ResolutionFacts {
        // A floor this pass could not read is availability, not a verdict: with
        // no floor the epoch-lag rung cannot fire, so a stale record would read
        // as granted. Absent (`Ok(None)`) is a genuine zero.
        let sharer_floors =
            SharerScopedFloorStore::granted_by(self.floors, share.sharer_identity_pk);
        let Ok(epoch_floor) = floor::read_epoch_floor(&sharer_floors, &share.scope_id).await else {
            return ResolutionFacts::unresolved(0);
        };
        let epoch_floor = epoch_floor.unwrap_or(0);
        let unresolved = ResolutionFacts::unresolved(epoch_floor);

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
        facts_from(
            &candidate,
            share,
            self.enc_secret,
            sharer_identity,
            sharer_enc_pub,
            epoch_floor,
        )
    }
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
    use cipherbox_core::seal::Permission;
    use cipherbox_core::suite::ecdsa::{EcdsaSigner, IDENTITY_PUBLIC_LEN};
    use cipherbox_core::suite::secret::SecretBytes;

    use crate::content::GatewaySource;
    use crate::rotation::derive_write_name;
    use crate::seams::{EndpointId, HttpResponse};
    use crate::seams::{FloorRaise, SeamError, SeamResult};
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryFloorStore;
    use crate::testkit::fakes::{InMemoryRecordStore, ScriptedHttp};
    use crate::testkit::{
        OWNER_ROOT_EPOCH, OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootFixture, OwnerRootSpec,
        owner_root_fixture,
    };

    use super::super::ledger::mint_grant_row;
    use super::super::revocation::{ResolutionClass, classify};

    const SCOPE: [u8; 16] = [0x5c; 16];
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
            classify(&block_on(
                ReceivedShareStatus {
                    transport: &self.records,
                    gateway: &self.gateway,
                    http: &self.http,
                    floors,
                    enc_secret: &my_enc(),
                }
                .facts(
                    &bookmark(),
                    &sharer.verifying_key(),
                    &sharer_enc().public(),
                ),
            ))
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
}
