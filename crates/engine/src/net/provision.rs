//! The production publish arm of first-run vault provisioning
//! ([`crate::sync::provision`]) — the same register-first CAS pipeline every
//! other write rides, with no crypto and no trust logic added.

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::suite::ed25519::Ed25519Signer;

use crate::api::{ApiClient, ApiError};
use crate::net::MAX_RECORD_BYTES;
use crate::net::fanout::fanout_get_verify;
use crate::net::pointer_fetch::RecordPointerFetch;
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
use crate::sync::pointer::PointerFetch;
use crate::sync::provision::{RootStep, VaultPointerProbe, VaultProvisionPublisher};

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
        PublishError::EmptyHeadCid | PublishError::RecordTooLarge { .. } => {
            WritePublishError::Rejected
        }
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
    async fn genesis_root_step(&self, name: &IpnsName) -> RootStep {
        // The gate is the whole answer: only a record this session's own read key
        // opens and the gate admits completes the root step. A gate rejection and
        // an unreachable record plane are one arm — publish, and let CAS decide —
        // because neither is a record this run may treat as its own.
        let Some((_verified, bytes)) = fanout_get_verify(self.transport, name).await else {
            return RootStep::MustPublish;
        };
        match self.adopter.adopt(name, &bytes).await {
            Ok(_) => RootStep::AlreadyAdopted,
            Err(_) => RootStep::MustPublish,
        }
    }

    async fn fetch_vault_pointer(&self, name: &IpnsName) -> Option<Vec<u8>> {
        // The same fan-out + core verify the cold-start walk resolves pointers
        // through; the inner unseal and owner verify are the caller's.
        RecordPointerFetch::new(self.transport)
            .fetch(name)
            .await
            .ok()
            .flatten()
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
    use cipherbox_core::seal::{PreservedFields, ReadBody};

    use crate::gate::{GateError, GateRejection, GateStage, RejectionReason};
    use crate::net::resolve::AdoptOutcome;
    use crate::profile::SyncTimingProfile;
    use crate::seams::{EndpointId, HttpResponse};
    use crate::testkit::{FakeDevice, FakeWorld, block_on};

    /// An adopter that answers one fixed verdict — the gate itself is tested at
    /// its own site; what matters here is which verdict reaches [`RootStep`].
    struct StubAdopter {
        admits: bool,
    }

    impl Adopter for StubAdopter {
        async fn adopt(
            &self,
            _name: &IpnsName,
            _record_bytes: &[u8],
        ) -> Result<AdoptOutcome, GateError> {
            if !self.admits {
                return Err(GateError::Rejected(GateRejection {
                    stage: GateStage::Sequence,
                    reason: RejectionReason::SequenceNotNewer {
                        floor: 9,
                        sequence: 1,
                    },
                }));
            }
            Ok(AdoptOutcome {
                adopted: crate::gate::Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: PreservedFields::new(),
                    },
                    sequence: 1,
                    epoch: 1,
                },
                write_scope_seed: None,
                node_id: [0u8; 16],
                read_scope_seed: None,
            })
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

    /// Run the production probe over `device`.
    fn probe(device: &FakeDevice, profile: &SyncTimingProfile) -> Result<(), VaultPointerProbe> {
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let net = VaultProvisionNet {
            transport: &device.record_store,
            adopter: &StubAdopter { admits: true },
            api: &api,
            floors: &device.floor_store,
            scheduler: &device.scheduler,
            profile,
        };
        block_on(net.require_vacant_vault_pointer(&pointer_name()))
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

    /// The root step the production arm reports, over an adopter that admits or
    /// rejects whatever it is handed.
    fn root_step(device: &FakeDevice, admits: bool) -> RootStep {
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let net = VaultProvisionNet {
            transport: &device.record_store,
            adopter: &StubAdopter { admits },
            api: &api,
            floors: &device.floor_store,
            scheduler: &device.scheduler,
            profile: &SyncTimingProfile::CI,
        };
        block_on(net.genesis_root_step(&pointer_name()))
    }

    /// What the production arm serves as the vault pointer's value.
    fn pointer_value(device: &FakeDevice) -> Option<Vec<u8>> {
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let net = VaultProvisionNet {
            transport: &device.record_store,
            adopter: &StubAdopter { admits: true },
            api: &api,
            floors: &device.floor_store,
            scheduler: &device.scheduler,
            profile: &SyncTimingProfile::CI,
        };
        block_on(net.fetch_vault_pointer(&pointer_name()))
    }

    /// The root step is the gate's verdict, not the transport's: a record the
    /// gate admits completes it, so a retry publishes nothing.
    #[test]
    fn a_gate_passing_record_completes_the_root_step() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        seed_record(&device);
        assert_eq!(root_step(&device, true), RootStep::AlreadyAdopted);
    }

    /// A record the gate refuses is not this run's root, and neither is an
    /// unreachable record plane: both must publish and let CAS settle the name.
    #[test]
    fn nothing_adoptable_leaves_the_root_step_to_publish() {
        let world = FakeWorld::new();
        let rejected = world.device(b"alice");
        seed_record(&rejected);
        assert_eq!(root_step(&rejected, false), RootStep::MustPublish);

        // A separate world: `FakeWorld` shares one record plane across devices.
        let empty = FakeWorld::new();
        let unresolvable = empty.device(b"bob");
        assert_eq!(root_step(&unresolvable, true), RootStep::MustPublish);
    }

    /// The mint's success condition reads the pointer through the same fan-out
    /// verify as any boot: an authenticated value, or nothing.
    #[test]
    fn the_pointer_fetch_yields_the_authenticated_value_or_nothing() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        assert_eq!(
            pointer_value(&device),
            None,
            "an unresolvable pointer name answers nothing",
        );

        seed_record(&device);
        assert_eq!(
            pointer_value(&device),
            Some(b"sealed-repoint-block".to_vec()),
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
            adopter: &StubAdopter { admits: true },
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
