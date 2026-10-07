//! The vault pointer's read-epoch vouch: a read cut of the vault root publishes
//! the root, then vouches its epoch here, then raises the floor
//! (blueprint/engine.md "Pointer planes"; [`floor::repoint_regression`]).

use core::cell::RefCell;

use cipherbox_core::payload::RepointObject;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;

use cipherbox_core::ipns::VerifiedRecord;
use cipherbox_core::kdf;
use cipherbox_core::suite::ecdsa::EcdsaVerifier;

use super::fanout::{FanoutRecord, TiedFetch, fanout_get_classified, fanout_get_tied_classified};
use super::publish::{BarFloor, Observed, PublishError};
use super::renewal_walk::RenewalSeams;
use super::resolve::unavailable_below_floor;
use super::revival::{
    Admitted, PlaneRead, PlaneRefusal, RecoveryPace, ReviveError, ReviveRequest, Revived, revive,
};
use super::rotation::{PointerPipeline, publish_pointer_over};
use crate::api::{ApiClient, ApiError};
use crate::entropy::Entropy;
use crate::gate::GateError;
use crate::gate::floor::{self, FloorRegression, PointerPlane, Strictness};
use crate::profile::SyncTimingProfile;
use crate::rotation::{ResealedScopeRoot, RotationPublishError, ScopeRootPublisher};
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SeamResult};
use crate::sync::pointer::{
    MAX_VAULT_POINTER_PROBE, PointerError, SessionRole, open_repoint, seal_repoint,
    vault_pointer_name,
};
use cipherbox_core::ipns::IpnsName;

/// The vault pointer at the index this session adopted, and the owner material
/// that re-seals it. Owner sessions only.
pub(crate) struct VaultPointerVoucher<'a, T, H: Http, C: CredentialStore, F, Sch, E> {
    pub transport: &'a T,
    pub api: &'a ApiClient<H, C>,
    pub floors: &'a F,
    pub scheduler: &'a Sch,
    pub profile: &'a SyncTimingProfile,
    pub entropy: &'a RefCell<E>,
    /// Signs the re-point payload; every reader verifies it against the
    /// contact-anchored owner identity.
    pub owner: &'a EcdsaSigner,
    /// The root scope's stable `pointerReadKey`.
    pub pointer_read_key: SecretBytes,
    /// The record signer of the adopted vault-pointer index.
    pub signer: Ed25519Signer,
    /// The session's root scope — the scope the vault pointer names.
    pub scope_id: [u8; 16],
    pub payload_version: u64,
}

/// The re-point the vault pointer carries now, and the sequence it sits at.
pub(crate) struct StandingVouch {
    sequence: u64,
    repoint: RepointObject,
}

impl StandingVouch {
    /// The read epoch the vault pointer vouches.
    pub(crate) fn min_read_epoch(&self) -> u64 {
        self.repoint.min_read_epoch
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> VaultPointerVoucher<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    /// The vault-pointer name this voucher publishes at.
    pub(crate) fn name(&self) -> IpnsName {
        IpnsName::from_public_key(&self.signer.verifying_key())
    }

    /// Raise the vault pointer's `minReadEpoch` to `read_epoch` for the root at
    /// `root_name`, carrying every other field of the standing re-point.
    pub(crate) async fn vouch_read_epoch(
        &self,
        root_name: &[u8],
        read_epoch: u64,
    ) -> Result<(), RotationPublishError> {
        let standing = self.standing(root_name).await?;
        self.vouch_over(standing, read_epoch).await
    }

    /// The standing re-point, refused when it names a root other than
    /// `root_name`, or sits below the vouched floor or the sequence this device
    /// published: a vouch signs every other field of it again.
    pub(crate) async fn standing(
        &self,
        root_name: &[u8],
    ) -> Result<StandingVouch, RotationPublishError> {
        let name = self.name();
        let TiedFetch {
            pick,
            absent,
            endpoint_failed,
        } = fanout_get_tied_classified(self.transport, &name).await;
        let standing = match pick {
            Some((record, _, _)) => record,
            None if absent => return Err(RotationPublishError::Rejected),
            None => return Err(RotationPublishError::NotPublished),
        };
        let vouched = open_repoint(
            self.pointer_read_key.as_bytes(),
            self.payload_version,
            &self.scope_id,
            &self.owner.verifying_key(),
            &standing.value,
        )
        .map_err(|_| RotationPublishError::Rejected)?;
        if vouched.current_root.as_str().as_bytes() != root_name {
            return Err(RotationPublishError::Rejected);
        }
        let vouched_floor = floor::vouched_floor(self.floors, &self.scope_id)
            .await
            .map_err(|_| RotationPublishError::NotPublished)?;
        if vouched_floor.is_some_and(|floor| vouched.min_read_epoch < floor) {
            return Err(RotationPublishError::Rejected);
        }
        floor::check_sequence(
            self.floors,
            name.as_str().as_bytes(),
            standing.sequence,
            Strictness::AtOrAboveFloor,
        )
        .await
        .map_err(|error| standing_verdict(error, endpoint_failed))?;
        Ok(StandingVouch {
            sequence: standing.sequence,
            repoint: vouched,
        })
    }

    /// Raise `standing`'s `minReadEpoch` to `read_epoch` under a CAS over its
    /// sequence. A standing re-point already at or past it is left alone. Once
    /// the vault pointer vouches `read_epoch`, the vouched floor records it.
    pub(crate) async fn vouch_over(
        &self,
        standing: StandingVouch,
        read_epoch: u64,
    ) -> Result<(), RotationPublishError> {
        if standing.repoint.min_read_epoch < read_epoch {
            self.publish_vouch(standing, read_epoch).await?;
        }
        floor::raise_vouched_floor(self.floors, &self.scope_id, read_epoch)
            .await
            .map_err(|_| RotationPublishError::FloorUnrecorded)
    }

    async fn publish_vouch(
        &self,
        standing: StandingVouch,
        read_epoch: u64,
    ) -> Result<(), RotationPublishError> {
        let repoint = RepointObject {
            min_read_epoch: read_epoch,
            ..standing.repoint
        };
        // The produce bar (ADR 0067 D4).
        if floor::repoint_regression(
            self.floors,
            &repoint,
            &self.scope_id,
            PointerPlane::VaultPointer,
        )
        .await
        .map_err(|_| RotationPublishError::NotPublished)?
        .is_some()
        {
            return Err(RotationPublishError::Rejected);
        }
        let block = seal_repoint(
            SessionRole::Owner,
            &mut *self.entropy.borrow_mut(),
            self.pointer_read_key.as_bytes(),
            self.payload_version,
            self.owner,
            &repoint,
        )
        .map_err(|error| match error {
            PointerError::Entropy(_) => RotationPublishError::NotPublished,
            _ => RotationPublishError::Rejected,
        })?;
        publish_pointer_over(
            PointerPipeline {
                transport: self.transport,
                api: self.api,
                floors: self.floors,
                scheduler: self.scheduler,
                profile: self.profile,
            },
            &Observed::record(&self.name(), standing.sequence),
            &self.signer,
            &block,
        )
        .await
        .map(drop)
        .map_err(RotationPublishError::from)
    }
}

/// A scope-root publisher whose publish of the vault root also vouches the
/// published read epoch at the anchor, so the cut's floor raise follows both.
pub(crate) struct VouchedRoot<'a, P, A> {
    pub root: &'a P,
    pub anchor: Option<&'a A>,
}

impl<P, T, H: Http, C: CredentialStore, F, Sch, E> ScopeRootPublisher
    for VouchedRoot<'_, P, VaultPointerVoucher<'_, T, H, C, F, Sch, E>>
where
    P: ScopeRootPublisher,
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    async fn publish_scope_root(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        self.root.publish_scope_root(record).await?;
        let Some(anchor) = self.anchor else {
            return Ok(());
        };
        // A fresh read, not the cut's refusal check: the CAS bar must follow
        // the root publish, or another device's re-point in between is lost.
        anchor
            .vouch_read_epoch(&record.ipns_name, record.read_epoch)
            .await
    }
}

/// `open_repoint` and the vault-pointer bar of one index of the chain (ADR
/// 0062 D1 step 3).
pub(crate) struct VaultPointerRead<'a, F> {
    pub(crate) floors: &'a F,
    pub(crate) pointer_read_key: &'a [u8; 32],
    pub(crate) owner_identity: &'a EcdsaVerifier,
    /// The session's root scope, the scope the vault pointer names.
    pub(crate) scope_id: [u8; 16],
    pub(crate) payload_version: u64,
}

impl<F> Clone for VaultPointerRead<'_, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F> Copy for VaultPointerRead<'_, F> {}

impl<F: FloorStore> PlaneRead for VaultPointerRead<'_, F> {
    async fn admit<T: RecordTransport>(
        &self,
        _: &T,
        name: &IpnsName,
        recovered: &VerifiedRecord,
        bytes: &[u8],
    ) -> Result<Admitted, PlaneRefusal> {
        let repoint = open_repoint(
            self.pointer_read_key,
            self.payload_version,
            &self.scope_id,
            self.owner_identity,
            &recovered.value,
        )
        .map_err(|_| PlaneRefusal::Rejected)?;
        match floor::repoint_regression(
            self.floors,
            &repoint,
            &self.scope_id,
            PointerPlane::VaultPointer,
        )
        .await
        {
            Ok(None) => Ok(Admitted::unbarred(name, recovered.sequence, bytes)),
            // The produce bar can sit above the vouched floor the cold start
            // reads (ADR 0067 D4): a pointer only that bar refuses passes the
            // gate, so the refusal is of the signature, not of the record.
            Ok(Some(produce)) => {
                match floor::vouched_regression(self.floors, &repoint, &self.scope_id).await {
                    Ok(Some(_)) => Err(PlaneRefusal::Rejected),
                    Ok(None) => Err(PlaneRefusal::Unsignable(below_bar(produce))),
                    Err(_) => Err(PlaneRefusal::Unavailable),
                }
            }
            Err(_) => Err(PlaneRefusal::Unavailable),
        }
    }

    /// A device that never walked the chain holds no index floor.
    async fn floorless<G: FloorStore>(&self, floors: &G, _: &IpnsName) -> SeamResult<bool> {
        Ok(floor::vault_pointer_index_floor(floors, &self.scope_id)
            .await?
            .is_none())
    }
}

fn below_bar(regression: FloorRegression) -> PublishError {
    let (floor, at, epoch) = match regression {
        FloorRegression::ReadEpoch { floor, vouched } => (BarFloor::Read, floor, vouched),
        FloorRegression::WriteEpoch { floor, vouched } => (BarFloor::Write, floor, vouched),
    };
    PublishError::BelowBar { floor, at, epoch }
}

/// What the session-start pass over the vault pointer chain found.
pub(crate) struct ChainRevival {
    /// Each revival the pass ran, by routing key.
    pub(crate) revivals: Vec<(String, Result<Revived, ReviveError>)>,
    /// `None` when the pass reached a chain end the cold start may read: the
    /// recovery endpoint holds no record one index past the last, or the
    /// fan-out did not answer, which the cold start reports itself. Else
    /// whether a later pass can still reach that end; the cold start must not
    /// adopt the prefix of a chain whose next index may only be lapsed.
    pub(crate) unconfirmed: Option<bool>,
}

/// Revive each lapsed index of the vault pointer chain, from the durable index
/// floor up, before `resolve_vault_pointer` reads it (ADR 0062 D3). An index
/// that the fan-out reads `Absent` revives from the recovery endpoint. The
/// first index the recovery endpoint holds no record for ends the chain, as
/// the probe one index past the last does.
pub(crate) async fn revive_vault_pointer_chain<T, H, C, F, Sch>(
    api: &ApiClient<H, C>,
    seams: &RenewalSeams<'_, T, F, Sch>,
    pace: &RecoveryPace,
    login_secret: &[u8],
    read: VaultPointerRead<'_, F>,
) -> ChainRevival
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    let mut pass = ChainRevival {
        revivals: Vec::new(),
        unconfirmed: None,
    };
    // An index below the floor is abandoned, so its revival would re-sign a
    // superseded pointer.
    let Ok(floor) = floor::vault_pointer_index_floor(seams.floors, &read.scope_id).await else {
        pass.unconfirmed = Some(true);
        return pass;
    };
    let mut revived = None;
    let mut index = floor.unwrap_or(0);
    while index < MAX_VAULT_POINTER_PROBE {
        let name = vault_pointer_name(login_secret, index);
        match fanout_get_classified(seams.transport, &name).await {
            FanoutRecord::Found(..) => index += 1,
            FanoutRecord::Absent if revived != Some(index) => {
                let signer = kdf::vault_pointer_index(login_secret, index);
                let request = ReviveRequest {
                    name: &name,
                    signer: Some(&signer),
                    plane: read,
                };
                let result = revive(api, seams, pace, &[request]).await.remove(0);
                pass.unconfirmed = match &result {
                    Ok(_) => None,
                    Err(ReviveError::Recovery(ApiError::Status { status: 404, .. })) => {
                        pass.revivals.push((name.as_str().to_owned(), result));
                        return pass;
                    }
                    Err(error) => Some(error.is_transient()),
                };
                pass.revivals.push((name.as_str().to_owned(), result));
                if pass.unconfirmed.is_some() {
                    return pass;
                }
                // The next read finds the record the endpoints now serve.
                revived = Some(index);
            }
            // The endpoints still read the revived index `Absent`.
            FanoutRecord::Absent => {
                pass.unconfirmed = Some(true);
                return pass;
            }
            FanoutRecord::Unavailable(_) => return pass,
        }
    }
    pass
}

/// The standing re-point's sequence check on rule 6's axis: a record below the
/// floor while an endpoint failed is unavailable (ADR 0071 D1).
fn standing_verdict(error: GateError, endpoint_failed: bool) -> RotationPublishError {
    match error {
        GateError::Rejected(rejection)
            if !unavailable_below_floor(&rejection.reason, endpoint_failed) =>
        {
            RotationPublishError::Rejected
        }
        _ => RotationPublishError::NotPublished,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::time::Duration;

    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::api::ApiError;
    use crate::gate::{GateRejection, GateStage, RejectionReason};
    use crate::net::eol::eol_from;
    use crate::seams::{HttpResponse, UnixMillis};
    use crate::sync::pointer::POINTER_PAYLOAD_VERSION;
    use crate::testkit::{FakeDevice, FakeWorld, SeededEntropy, block_on};

    fn sequence(floor: u64, sequence: u64) -> GateError {
        GateError::Rejected(GateRejection {
            stage: GateStage::Sequence,
            reason: RejectionReason::SequenceNotNewer { floor, sequence },
        })
    }

    #[test]
    fn a_below_floor_standing_pointer_is_unavailable_only_while_an_endpoint_fails() {
        assert_eq!(
            standing_verdict(sequence(3, 2), true),
            RotationPublishError::NotPublished
        );
        assert_eq!(
            standing_verdict(sequence(3, 2), false),
            RotationPublishError::Rejected
        );
    }

    const SECRET: [u8; 32] = [7; 32];
    const SCOPE: [u8; 16] = [0x44; 16];
    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    fn owner() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[3u8; 32]).expect("a valid scalar")
    }

    fn read_key() -> SecretBytes {
        kdf::pointer_read_key(kdf::owner_pointer_seed(&SECRET).as_bytes(), &SCOPE)
    }

    /// The record at `index` of the chain, signed on day 0 with a 90-day EOL.
    fn pointer_record(index: u64, sequence: u64) -> Vec<u8> {
        let block = seal_repoint(
            SessionRole::Owner,
            &mut SeededEntropy::new(index),
            read_key().as_bytes(),
            POINTER_PAYLOAD_VERSION,
            &owner(),
            &RepointObject {
                scope_id: SCOPE,
                current_root: vault_pointer_name(&SECRET, 99),
                write_epoch: 1,
                min_read_epoch: 1,
                prev_root: None,
            },
        )
        .expect("the owner seals the re-point");
        IpnsRecord::create_v2(
            &kdf::vault_pointer_index(&SECRET, index),
            &block,
            sequence,
            2_000_000_000,
            &eol_from(UnixMillis(0)),
        )
        .marshal()
    }

    fn answer(status: u16, body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Recovery serves `record`, and the registration succeeds.
    fn recover(device: &FakeDevice, record: Vec<u8>) {
        device.http.enqueue_response(answer(200, record));
        device.http.enqueue_response(answer(200, Vec::new()));
    }

    fn after_100_days() -> (FakeWorld, FakeDevice) {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        world.scheduler.advance(100 * DAY);
        (world, device)
    }

    fn revive_chain(world: &FakeWorld, device: &FakeDevice) -> ChainRevival {
        let publishing = RefCell::default();
        let seams = RenewalSeams {
            transport: &device.record_store,
            floors: &device.floor_store,
            scheduler: &world.scheduler,
            profile: &SyncTimingProfile::CI,
            publishing: &publishing,
        };
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let (owner, key) = (owner().verifying_key(), read_key());
        block_on(revive_vault_pointer_chain(
            &api,
            &seams,
            &RecoveryPace::default(),
            &SECRET,
            VaultPointerRead {
                floors: &device.floor_store,
                pointer_read_key: key.as_bytes(),
                owner_identity: &owner,
                scope_id: SCOPE,
                payload_version: POINTER_PAYLOAD_VERSION,
            },
        ))
    }

    fn recovered_names(device: &FakeDevice) -> Vec<String> {
        device
            .http
            .requests()
            .into_iter()
            .filter_map(|request| {
                request
                    .url
                    .split_once("/recovery/")
                    .map(|(_, name)| name.to_owned())
            })
            .collect()
    }

    fn served(device: &FakeDevice, index: u64) -> Option<IpnsRecord> {
        let name = vault_pointer_name(&SECRET, index);
        let endpoint = device.record_store.endpoints()[0].clone();
        let bytes = device.record_store.record_at(&endpoint, name.as_str())?;
        Some(IpnsRecord::unmarshal(&bytes).expect("a record"))
    }

    #[test]
    fn each_lapsed_index_revives_up_to_the_probe_one_past_the_last() {
        let (world, device) = after_100_days();
        for index in 0..2 {
            recover(&device, pointer_record(index, 3));
        }
        device.http.enqueue_response(answer(404, Vec::new()));

        let ChainRevival {
            revivals,
            unconfirmed,
        } = revive_chain(&world, &device);
        assert_eq!(
            unconfirmed, None,
            "the probe one past the last index ends the chain"
        );

        let names: Vec<String> = (0..3)
            .map(|index| vault_pointer_name(&SECRET, index).as_str().to_owned())
            .collect();
        assert_eq!(recovered_names(&device), names, "one past the last index");
        assert!(revivals[..2].iter().all(|(_, result)| result.is_ok()));
        assert!(matches!(
            revivals[2].1,
            Err(ReviveError::Recovery(ApiError::Status { status: 404, .. }))
        ));
        for index in 0..2 {
            let name = vault_pointer_name(&SECRET, index);
            let recovered = IpnsRecord::unmarshal(&pointer_record(index, 3))
                .and_then(|record| record.verify(&name))
                .unwrap();
            let revived = served(&device, index)
                .expect("the index revived")
                .verify(&name)
                .unwrap();
            assert_eq!(revived.sequence, 4);
            assert_eq!(revived.value, recovered.value, "the sealed block unchanged");
        }
        assert!(served(&device, 2).is_none());
    }

    /// A 429 after a revived index leaves the chain end unconfirmed, so the
    /// cold start adopts no prefix and a later pass tries again.
    #[test]
    fn a_429_inside_the_chain_leaves_its_end_unconfirmed() {
        let (world, device) = after_100_days();
        recover(&device, pointer_record(0, 3));
        device.http.enqueue_response(answer(429, Vec::new()));

        let pass = revive_chain(&world, &device);

        assert_eq!(pass.unconfirmed, Some(true), "a retryable verdict");
        assert!(matches!(pass.revivals[1].1, Err(ReviveError::Throttled)));
        assert!(served(&device, 0).is_some(), "index 0 revived");
    }

    #[test]
    fn the_chain_revives_from_the_index_floor_and_reads_a_live_index() {
        let (world, device) = after_100_days();
        block_on(floor::advance_vault_pointer_index(
            &device.floor_store,
            &SCOPE,
            1,
        ))
        .unwrap();
        for endpoint in device.record_store.endpoints() {
            device.record_store.seed_record(
                &endpoint,
                vault_pointer_name(&SECRET, 1).as_str(),
                pointer_record(1, 3),
            );
        }
        device.http.enqueue_response(answer(404, Vec::new()));

        let revivals = revive_chain(&world, &device).revivals;

        assert_eq!(
            recovered_names(&device),
            [vault_pointer_name(&SECRET, 2).as_str().to_owned()],
            "no fetch below the floor, and none for the live index"
        );
        assert_eq!(revivals.len(), 1);
        assert!(
            served(&device, 0).is_none(),
            "an abandoned index stays lapsed"
        );
    }
}
