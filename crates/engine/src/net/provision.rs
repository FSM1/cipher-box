//! The production publish arm of first-run vault provisioning
//! ([`crate::sync::provision`]) — the same register-first CAS pipeline every
//! other write rides, with no crypto and no trust logic added.

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, ct_eq};

use crate::api::{ApiClient, ApiError};
use crate::net::MAX_RECORD_BYTES;
use crate::net::fanout::fanout_get_verify;
use crate::net::publish::{
    InlineRecordRequest, PublishError, PublishOutcome, PublishReceipt, publish_inline,
};
use crate::net::record_publish::{
    PreflightedHead, RecordPublishError, RecordPublishRequest, publish_record,
};
use crate::net::resolve::Adopter;
use crate::profile::SyncTimingProfile;
use crate::rotation::WritePublishError;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};
use crate::sync::provision::{GenesisRoot, VaultPointerProbe, VaultProvisionPublisher};

/// The provisioning publish seams over the live net plane.
pub struct VaultProvisionNet<'a, T, H: Http, C: CredentialStore, F, Sch, Ad> {
    /// The record-plane transport the CAS PUT fans out over.
    pub transport: &'a T,
    /// The adoption gate a record at the derived root name is put through, so
    /// the root step confirms by adopt rather than by this run's own PUT.
    pub adopter: &'a Ad,
    /// The API client: register-first and the head-block upload.
    pub api: &'a ApiClient<H, C>,
    /// The durable floors the publish pipeline reads its CAS sequence from.
    pub floors: &'a F,
    /// The scheduler the publish pipeline's background re-PUT rides.
    pub scheduler: &'a Sch,
    /// The publish pipeline's timing policy.
    pub profile: &'a SyncTimingProfile,
}

/// Carry a publish failure onto rule 6's axis: only this build's own
/// release-active refusals and a mis-echoed CID are verdicts a retry repeats.
fn publish_verdict(error: PublishError) -> WritePublishError {
    match error {
        PublishError::Register(_) => WritePublishError::RegistryFull,
        PublishError::EmptyHeadCid
        | PublishError::EmptyInlineValue
        | PublishError::RecordTooLarge { .. } => WritePublishError::Rejected,
        PublishError::AllEndpointsFailed | PublishError::FloorRead(_) => {
            WritePublishError::NotLanded
        }
    }
}

/// Whether a publish durably landed. The per-name sequence floor is left alone:
/// it moves on the AAD-confirmed unseal of an adopt (`gate::floor`), and the
/// session's first resolve of the genesis root is that adopt — the one that also
/// caches the bytes every later write re-authors from.
fn landed(outcome: PublishOutcome) -> Result<(), WritePublishError> {
    match outcome {
        PublishOutcome::Published { .. } => Ok(()),
        PublishOutcome::LostRace { .. } => Err(WritePublishError::LostRace),
        PublishOutcome::Unconfirmed { .. } => Err(WritePublishError::NotLanded),
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, Ad> VaultProvisionPublisher
    for VaultProvisionNet<'_, T, H, C, F, Sch, Ad>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    Ad: Adopter,
{
    async fn genesis_root(
        &self,
        name: &IpnsName,
        read_scope_seed: &[u8; SECRET_LEN],
    ) -> GenesisRoot {
        let Some((_verified, bytes)) = fanout_get_verify(self.transport, name).await else {
            return GenesisRoot::Unclaimed;
        };
        // The gate recovers the scope read seed from the record's OWN owner blob,
        // so a pass proves an owner-readable root stands here — not that it is the
        // one this run derived. The read rotation that re-keys a scope republishes
        // at this same name, so the two must be compared.
        match self.adopter.probe_read_scope_seed(name, &bytes).await {
            Ok(Some(recovered)) if ct_eq(&recovered, read_scope_seed) => GenesisRoot::Adopted,
            Ok(_) => GenesisRoot::Foreign,
            Err(_) => GenesisRoot::Unclaimed,
        }
    }

    async fn require_vacant_vault_pointer(&self, name: &IpnsName) -> Result<(), VaultPointerProbe> {
        // The API's record cache outlives an IPNS EOL lapse, so it still answers
        // for a vault whose record has aged out of the routing tables. It is an
        // accelerator, never an authority — but used only to *refuse*, a hostile
        // or lagging answer can block a mint and never cause a wrong one. A 404
        // is the sole affirmative "no such record"; anything else is silence.
        match self.api.recovery_fetch(name.as_str()).await {
            Ok(bytes) if !bytes.is_empty() => return Err(VaultPointerProbe::AlreadyPublished),
            // A 2xx carrying no record is an intermediary talking, not the cache
            // answering: it proves nothing either way.
            Ok(_) => return Err(VaultPointerProbe::Indeterminate),
            Err(ApiError::Status { status: 404, .. }) => {}
            Err(_) => return Err(VaultPointerProbe::Indeterminate),
        }
        // Then the record plane, unanimously: **every** endpoint must answer, and
        // every answer must be "no record". A tolerated failure is what makes a
        // partial outage indistinguishable from a vacant name — the endpoint
        // holding the account's pointer is down while a peer that never saw it
        // answers `None` — and the mint that follows overwrites the one record
        // naming the one root whose owner-write blob holds a write scope seed
        // nobody can re-derive. Unanimity costs nothing on the refusing side: a
        // single `Some` is already decisive.
        let endpoints = self.transport.endpoints();
        // The seam contracts this set as never empty; inferring vacancy from zero
        // answers is the same bug in its degenerate form, so the guard is
        // release-active rather than an assumption.
        if endpoints.is_empty() {
            return Err(VaultPointerProbe::Indeterminate);
        }
        for endpoint in endpoints {
            match self
                .transport
                .get_record(&endpoint, name.as_str(), MAX_RECORD_BYTES)
                .await
            {
                // Only bytes that verify at this name prove a publication. The
                // endpoint set includes untrusted public endpoints, and the
                // verdict this feeds is permanent, so unverifiable bytes still
                // refuse — nothing here reaches `Ok(())` — but as availability,
                // denying one hostile endpoint the power to forge a permanent
                // trust verdict against an account that never published.
                Ok(Some(bytes)) => {
                    return Err(
                        if IpnsRecord::unmarshal(&bytes)
                            .and_then(|record| record.verify(name))
                            .is_ok()
                        {
                            VaultPointerProbe::AlreadyPublished
                        } else {
                            VaultPointerProbe::Indeterminate
                        },
                    );
                }
                Ok(None) => {}
                Err(_) => return Err(VaultPointerProbe::Indeterminate),
            }
        }
        Ok(())
    }

    async fn publish_root_record(
        &self,
        name: &IpnsName,
        signer: &Ed25519Signer,
        head: &PreflightedHead,
    ) -> Result<(), WritePublishError> {
        let PublishReceipt { outcome, .. } = publish_record(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &RecordPublishRequest {
                name,
                signer,
                head,
                content_cids: Vec::new(),
                min_current_sequence: None,
            },
        )
        .await
        .map_err(|error| match error {
            // A CID the API echoes back wrong is deterministic on the bytes this
            // run built: re-uploading them reaches the same answer.
            RecordPublishError::HeadCidMismatch { .. } => WritePublishError::Rejected,
            RecordPublishError::Upload(_) => WritePublishError::NotLanded,
            RecordPublishError::Publish(e) => publish_verdict(e),
        })?;
        landed(outcome)
    }

    async fn publish_vault_pointer(
        &self,
        name: &IpnsName,
        signer: &Ed25519Signer,
        block: &[u8],
    ) -> Result<(), WritePublishError> {
        let PublishReceipt { outcome, .. } = publish_inline(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &InlineRecordRequest {
                name,
                signer,
                value: block,
                min_current_sequence: None,
            },
        )
        .await
        .map_err(publish_verdict)?;
        landed(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::kdf;

    use zeroize::Zeroizing;

    use crate::gate::{GateError, GateRejection, GateStage, RejectionReason};
    use crate::net::resolve::AdoptOutcome;
    use crate::profile::SyncTimingProfile;
    use crate::seams::{EndpointId, HttpResponse};
    use crate::testkit::fakes::{
        InMemoryCredentialStore, InMemoryFloorStore, InMemoryRecordStore, ScriptedHttp,
        VirtualScheduler,
    };
    use crate::testkit::{FakeDevice, FakeWorld, block_on};

    /// An adopter that answers one fixed verdict — the gate itself is tested at
    /// its own site; what matters here is which verdict reaches [`RootStep`].
    /// The read scope seed the run under test derived — what a record must open
    /// under to be its own genesis root.
    const DERIVED_SEED: [u8; 32] = [0x5a; 32];

    struct StubAdopter {
        admits: bool,
        /// The seed the gate recovers from the record's own owner blob. `None`
        /// models an adopter that recovers none — a gate pass that proves no
        /// ownership, which must be foreign rather than unclaimed.
        recovered: Option<[u8; 32]>,
    }

    impl Adopter for StubAdopter {
        /// Unreachable by contract: the genesis probe must not commit a
        /// sighting, so an arm that reaches the adopt is the bug under test.
        async fn adopt(
            &self,
            _name: &IpnsName,
            _record_bytes: &[u8],
        ) -> Result<AdoptOutcome, GateError> {
            unreachable!("the genesis probe must not advance a sequence floor")
        }

        async fn probe_read_scope_seed(
            &self,
            _name: &IpnsName,
            _record_bytes: &[u8],
        ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError> {
            if !self.admits {
                return Err(GateError::Rejected(GateRejection {
                    stage: GateStage::Sequence,
                    reason: RejectionReason::SequenceNotNewer {
                        floor: 9,
                        sequence: 1,
                    },
                }));
            }
            Ok(self.recovered.map(Zeroizing::new))
        }
    }

    /// The vault-pointer name a first run would mint at.
    fn pointer_name() -> IpnsName {
        IpnsName::from_public_key(&kdf::vault_pointer_index(b"probe-secret", 0).verifying_key())
    }

    /// A signed record at `pointer_name` — the account's existing vault, as an
    /// endpoint holds it.
    fn published_pointer() -> Vec<u8> {
        IpnsRecord::create_v2(
            &kdf::vault_pointer_index(b"probe-secret", 0),
            b"sealed-repoint-block",
            1,
            0,
            "2099-01-01T00:00:00Z",
        )
        .marshal()
    }

    /// Queue the recovery-cache answer the probe reads first.
    fn recovery_reply(device: &FakeDevice, status: u16) {
        device.http.enqueue_response(HttpResponse {
            status,
            headers: Vec::new(),
            body: br#"{"statusCode":404}"#.to_vec(),
        });
    }

    /// The production arm as the tests here assemble it.
    type ProvisionNetUnderTest<'a> = VaultProvisionNet<
        'a,
        InMemoryRecordStore,
        ScriptedHttp,
        InMemoryCredentialStore,
        InMemoryFloorStore,
        VirtualScheduler,
        StubAdopter,
    >;

    /// Build the production arm over `device` and hand it to `f`. The net
    /// borrows the local `ApiClient`, so it cannot be returned.
    fn with_net<R>(
        device: &FakeDevice,
        admits: bool,
        recovered: Option<[u8; 32]>,
        profile: &SyncTimingProfile,
        f: impl FnOnce(&ProvisionNetUnderTest<'_>) -> R,
    ) -> R {
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        f(&VaultProvisionNet {
            transport: &device.record_store,
            adopter: &StubAdopter { admits, recovered },
            api: &api,
            floors: &device.floor_store,
            scheduler: &device.scheduler,
            profile,
        })
    }

    /// Run the production probe over `device`.
    fn probe(device: &FakeDevice, profile: &SyncTimingProfile) -> Result<(), VaultPointerProbe> {
        with_net(device, true, Some(DERIVED_SEED), profile, |net| {
            block_on(net.require_vacant_vault_pointer(&pointer_name()))
        })
    }

    /// Seed a verifiable record at the probed name — the account's own, as an
    /// endpoint holds it.
    fn seed_record(device: &FakeDevice) {
        device.record_store.seed_record(
            &EndpointId::new("fake:someguy"),
            pointer_name().as_str(),
            published_pointer(),
        );
    }

    /// What the production arm sights at the derived root name, over an adopter
    /// that admits or rejects whatever it is handed and recovers `recovered` as
    /// the record's own read scope seed.
    fn genesis_root(device: &FakeDevice, admits: bool, recovered: Option<[u8; 32]>) -> GenesisRoot {
        with_net(device, admits, recovered, &SyncTimingProfile::CI, |net| {
            block_on(net.genesis_root(&pointer_name(), &DERIVED_SEED))
        })
    }

    /// Both halves of D3: the gate admits it AND it opens under the seed this
    /// run derived.
    #[test]
    fn a_gate_passing_record_under_the_derived_seed_is_the_accounts_own_root() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        seed_record(&device);
        assert_eq!(
            genesis_root(&device, true, Some(DERIVED_SEED)),
            GenesisRoot::Adopted
        );
    }

    /// The gate recovers the seed from the record's own owner blob, so a pass
    /// proves only that an owner-readable root stands here. A read rotation
    /// re-keys the scope at this same name: that record is foreign to this mint,
    /// and minting over it would sign an epoch rollback.
    #[test]
    fn a_gate_passing_record_under_another_seed_is_foreign() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        seed_record(&device);
        assert_eq!(
            genesis_root(&device, true, Some([0x77; 32])),
            GenesisRoot::Foreign,
            "a rotated vault at the derived name is never this run's genesis root",
        );
    }

    /// The other half of the `Foreign` arm: an adopt that recovers no seed
    /// proves no ownership either, so it must not be read as a vacant name. If
    /// this collapsed to `Unclaimed` the mint would publish over a gate-admitted
    /// root — the exact rollback the seed binding exists to stop.
    #[test]
    fn a_gate_pass_that_recovers_no_seed_is_foreign() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        seed_record(&device);
        assert_eq!(genesis_root(&device, true, None), GenesisRoot::Foreign);
    }

    /// A record the gate refuses is not this run's root, and neither is an
    /// unreachable record plane: both leave the name unclaimed.
    #[test]
    fn nothing_adoptable_leaves_the_root_name_unclaimed() {
        let world = FakeWorld::new();
        let rejected = world.device(b"alice");
        seed_record(&rejected);
        assert_eq!(
            genesis_root(&rejected, false, Some(DERIVED_SEED)),
            GenesisRoot::Unclaimed
        );

        // A separate world: `FakeWorld` shares one record plane across devices.
        let empty = FakeWorld::new();
        let unresolvable = empty.device(b"bob");
        assert_eq!(
            genesis_root(&unresolvable, true, Some(DERIVED_SEED)),
            GenesisRoot::Unclaimed
        );
    }

    /// The partial outage: the endpoint holding the account's vault pointer is
    /// down, and a peer that never saw it answers "no record". Reading that pair
    /// as a vacant name mints a second genesis vault over the one record naming
    /// the root whose owner-write blob holds the account's only write scope seed.
    /// Unanimity is what makes the pair indeterminate instead.
    #[test]
    fn one_silent_endpoint_is_never_a_vacant_name() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        let holder = EndpointId::new("fake:someguy");
        device
            .record_store
            .seed_record(&holder, pointer_name().as_str(), published_pointer());
        device.record_store.fail_endpoint(&holder);
        recovery_reply(&device, 404);

        assert_eq!(
            probe(&device, &SyncTimingProfile::CI),
            Err(VaultPointerProbe::Indeterminate),
            "a silent endpoint is not an absent record",
        );
    }

    /// A healthy endpoint set with the record still on one of them refuses
    /// outright — the refusing side needs no unanimity, one sighting is decisive.
    #[test]
    fn a_record_at_any_endpoint_refuses_the_mint() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        device.record_store.seed_record(
            &EndpointId::new("fake:public-routing"),
            pointer_name().as_str(),
            published_pointer(),
        );
        recovery_reply(&device, 404);

        assert_eq!(
            probe(&device, &SyncTimingProfile::CI),
            Err(VaultPointerProbe::AlreadyPublished),
        );
    }

    /// The only admitting case: every authority answered, and none held a record.
    #[test]
    fn a_unanimous_no_record_is_the_only_vacancy() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        recovery_reply(&device, 404);

        assert_eq!(probe(&device, &SyncTimingProfile::CI), Ok(()));
    }

    /// The pointer name is derived from the login secret, so only the secret
    /// holder can put real bytes there — but an untrusted public endpoint can
    /// serve anything at any name. Garbage must still refuse (never `Ok(())`),
    /// yet it must not be reported as the permanent verdict that a genuine
    /// publication earns, or one hostile endpoint denies account creation for
    /// good and tells the host it was a trust violation.
    #[test]
    fn unverifiable_bytes_refuse_without_forging_a_permanent_verdict() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        device.record_store.seed_record(
            &EndpointId::new("fake:public-routing"),
            pointer_name().as_str(),
            b"not an ipns record".to_vec(),
        );
        recovery_reply(&device, 404);

        assert_eq!(
            probe(&device, &SyncTimingProfile::CI),
            Err(VaultPointerProbe::Indeterminate),
            "bytes that do not verify at the name prove nothing, but admit nothing",
        );
    }

    /// The same rule on the API leg: a 2xx with no body is an intermediary
    /// talking, not the record cache answering.
    #[test]
    fn an_empty_recovery_body_proves_nothing_either_way() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        device.http.enqueue_response(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        });

        assert_eq!(
            probe(&device, &SyncTimingProfile::CI),
            Err(VaultPointerProbe::Indeterminate),
        );
    }

    /// A transport that offers no endpoint answers nothing, which is the same
    /// inference in its degenerate form — so the loop's `Ok(())` fall-through is
    /// guarded rather than assumed, release-active. The seam contracts the set as
    /// never empty; a host that breaks that contract must not mint a vault.
    #[test]
    fn an_empty_endpoint_set_answers_nothing_and_admits_nothing() {
        #[derive(Clone)]
        struct NoEndpoints;

        impl RecordTransport for NoEndpoints {
            fn endpoints(&self) -> Vec<EndpointId> {
                Vec::new()
            }
            async fn get_record(
                &self,
                _endpoint: &EndpointId,
                _routing_key: &str,
                _max_bytes: usize,
            ) -> crate::seams::SeamResult<Option<Vec<u8>>> {
                unreachable!("no endpoint to ask")
            }
            async fn put_record(
                &self,
                _endpoint: &EndpointId,
                _routing_key: &str,
                _record: &[u8],
            ) -> crate::seams::SeamResult<()> {
                unreachable!("no endpoint to write")
            }
        }

        let world = FakeWorld::new();
        let device = world.device(b"alice");
        recovery_reply(&device, 404);
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let net = VaultProvisionNet {
            transport: &NoEndpoints,
            adopter: &StubAdopter {
                admits: true,
                recovered: Some(DERIVED_SEED),
            },
            api: &api,
            floors: &device.floor_store,
            scheduler: &device.scheduler,
            profile: &SyncTimingProfile::CI,
        };
        assert_eq!(
            block_on(net.require_vacant_vault_pointer(&pointer_name())),
            Err(VaultPointerProbe::Indeterminate),
        );
    }

    /// The recovery cache outlives an IPNS EOL lapse, so it answers for a vault
    /// whose record has aged out of every routing table — and an API that will
    /// not say is silence, never an absence.
    #[test]
    fn the_recovery_cache_refuses_before_the_record_plane_is_asked() {
        for (status, expected) in [
            (200, VaultPointerProbe::AlreadyPublished),
            (500, VaultPointerProbe::Indeterminate),
            (429, VaultPointerProbe::Indeterminate),
        ] {
            let world = FakeWorld::new();
            let device = world.device(b"alice");
            recovery_reply(&device, status);
            assert_eq!(
                probe(&device, &SyncTimingProfile::CI),
                Err(expected),
                "recovery answered {status}",
            );
            assert_eq!(
                device.http.requests().len(),
                1,
                "a decided recovery answer asks no endpoint",
            );
        }
    }
}
