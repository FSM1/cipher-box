//! The child-record [`Adopter`]: verified content-plane reads one level below
//! the scope root (blueprint/engine.md "Content plane").
//!
//! A non-scope-root record carries no grant section, so the six-stage root gate
//! cannot apply. The child pipeline instead composes: record verify → head
//! fetch fail-closed on a CID mismatch → envelope binding (id + scope; a
//! transplant rejects) → the per-name sequence and scope read-epoch floors →
//! the AAD-bound read-body unseal under `read-key(node-seed(scopeReadSeed,
//! id))` — the same KDF edges the root walks, one level down. The sequence
//! floor advances only after a successful unseal (the floor law) and only once
//! the accepted record is durable ([`floor::PendingSequenceRaise`]); the scope
//! epoch floor never moves from a child. No new crypto: pure composition of
//! core verify/unseal plus the frozen KDF catalog.

use core::cell::RefCell;

use cipherbox_core::error::{Malformed, TrustViolation};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{Envelope, ReadBody, has_grant_section, open_read_body};
use zeroize::Zeroizing;

use super::adopter::{LocalHead, assemble_head_envelope, reject};
use super::resolve::{AdoptOutcome, Adopter, GatePass, ResolveOutcome, resolve};
use crate::content::Gateway;
use crate::gate::{Adopted, GateError, GateStage, floor};
use crate::seams::{FloorStore, Http, RecordTransport, SeamError, SnapshotCache};
use crate::sync::tick::ResolveMode;

/// The child-record [`Adopter`] for one non-root node of an owned scope.
/// Borrows the content seams from the live session; terminally owns a
/// zeroizing clone of the scope read seed (zeroized when the adopter drops).
pub struct ChildAdopter<'a, H, F> {
    /// Content read sources (accelerator + public fallbacks).
    gateway: &'a Gateway,
    /// The HTTP seam the head-block fetch rides.
    http: &'a H,
    /// The durable floor store the child floors read and advance. A scope held
    /// by grant must arrive filed under its granting identity, as
    /// [`RootAdopter::for_grantee`](super::RootAdopter::for_grantee) takes it.
    floors: &'a F,
    /// The scope the child must be sealed under (the AAD scope binding and the
    /// read-epoch floor key). A foreign scope is a transplant, fail-closed.
    scope_id: [u8; 16],
    /// The scope read seed the per-node read key derives from.
    scope_read_seed: Zeroizing<[u8; 32]>,
    /// The node id the resolved envelope must carry — the rendered-view child
    /// this read was issued for. A different id is a transplant, fail-closed.
    expected_node: [u8; 16],
    /// The envelope a floor-rejected [`Adopter::adopt`] assembled, kept so every
    /// re-open of those same bytes reuses it instead of re-fetching the same
    /// head block (mirrors [`RootAdopter`](super::RootAdopter)).
    assembled: RefCell<Option<AssembledChild>>,
    /// A head block the caller already holds ([`Self::hold_local_head`]).
    local_head: RefCell<Option<LocalHead>>,
}

/// One assembled child head, keyed by the record it came from.
struct AssembledChild {
    name: IpnsName,
    record_bytes: Vec<u8>,
    sequence: u64,
    envelope: Envelope,
}

impl<'a, H, F> ChildAdopter<'a, H, F> {
    /// Assemble a child adopter over the borrowed seams and the scope's read
    /// material.
    pub fn new(
        gateway: &'a Gateway,
        http: &'a H,
        floors: &'a F,
        scope_id: [u8; 16],
        scope_read_seed: Zeroizing<[u8; 32]>,
        expected_node: [u8; 16],
    ) -> Self {
        Self {
            gateway,
            http,
            floors,
            scope_id,
            scope_read_seed,
            expected_node,
            assembled: RefCell::new(None),
            local_head: RefCell::new(None),
        }
    }

    /// Supply a head block the caller already holds, so a self-adopt of our own
    /// just-published record skips the fetch. The CID the signed record anchors
    /// still decides: a block that does not match it is ignored.
    pub fn hold_local_head(&self, head: LocalHead) {
        *self.local_head.borrow_mut() = Some(head);
    }
}

impl<H: Http, F: FloorStore> ChildAdopter<'_, H, F> {
    /// The shared head-envelope assembly ([`assemble_head_envelope`]) plus the
    /// child bindings — every step fail-closed as a trust violation; a missing
    /// source stays availability.
    async fn assemble_envelope(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<(u64, Envelope), GateError> {
        let local = self.local_head.borrow().clone();
        let (sequence, envelope, _) =
            assemble_head_envelope(self.gateway, self.http, name, record_bytes, local.as_ref())
                .await?;
        // A grant section marks a scope root; granted-subscope reads are a
        // later slice — fail closed, no partial support.
        if has_grant_section(&envelope) {
            return Err(reject(
                GateStage::GrantSection,
                Malformed::UnexpectedType {
                    expected: "child envelope",
                    found: "grantSection",
                }
                .into(),
            ));
        }
        // Transplant binding: the envelope must be exactly the expected node in
        // this scope (the read-key KDF does not bind the scope UUID, so the
        // scope check joins the same equivalence class as the root gate's).
        if envelope.id != self.expected_node || envelope.scope != self.scope_id {
            return Err(reject(
                GateStage::Unseal,
                TrustViolation::SealOpenFailed.into(),
            ));
        }
        Ok((sequence, envelope))
    }

    /// Unseal the read-body under the per-node read key derived from the scope
    /// read seed (`node-seed` → `read-key`, the frozen KDF edges).
    ///
    /// A failure above `epoch_floor` is availability: this device holds no seed
    /// for that epoch, so the record accuses nobody by failing to open, and the
    /// root leg that recovers the seed repaints it. At or below the floor this
    /// seed is the one the record must open under, so the failure stays the
    /// fail-closed trust verdict. An absent floor proves nothing above it and
    /// keeps the verdict.
    ///
    /// Accepted: the epoch tag attests nothing (ADR 0017), so a party that can
    /// sign at this name buys unreachability instead of an accusation. It can
    /// already withhold the body outright, and neither arm adopts a record or
    /// moves a floor.
    fn unseal(&self, envelope: &Envelope, epoch_floor: Option<u64>) -> Result<ReadBody, GateError> {
        let node_seed = kdf::node_seed(&self.scope_read_seed, &envelope.id);
        let read_key = kdf::read_key(node_seed.as_bytes());
        match open_read_body(envelope, read_key.as_bytes()) {
            Ok(read_body) => Ok(read_body),
            Err(_) if epoch_floor.is_some_and(|floor| envelope.epoch > floor) => {
                Err(GateError::Seam(SeamError::new(format!(
                    "record at epoch {} is above this scope's read-epoch floor",
                    envelope.epoch
                ))))
            }
            Err(e) => Err(reject(GateStage::Unseal, e)),
        }
    }

    /// Re-open a record already at the durable floor — our own current record
    /// or the cached last-known-good. The full child pipeline minus the
    /// strictly-newer requirement, with **no** floor advance (only a
    /// gate-passing adopt moves floors).
    pub(crate) async fn open_at_floor(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<Adopted, GateError> {
        self.open_carried_at_floor(name, record_bytes)
            .await
            .map(|(adopted, _)| adopted)
    }

    /// The decoded head for these exact bytes: the one an earlier assembly for
    /// the same record left behind, or a fresh assembly. Assembling again
    /// re-fetches the head block, so every re-open path comes through here.
    async fn assembled_head(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<(u64, Envelope), GateError> {
        let cached = self
            .assembled
            .borrow()
            .as_ref()
            .filter(|c| c.name == *name && c.record_bytes == record_bytes)
            .map(|c| (c.sequence, c.envelope.clone()));
        match cached {
            Some(head) => Ok(head),
            None => self.assemble_envelope(name, record_bytes).await,
        }
    }

    /// [`open_at_floor`](Self::open_at_floor) keeping the decoded envelope, so a
    /// re-author can carry its unknown fields forward byte-stable (#27 D10).
    pub(crate) async fn open_carried_at_floor(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<(Adopted, Envelope), GateError> {
        let (sequence, envelope) = self.assembled_head(name, record_bytes).await?;
        let epoch_floor = floor::check(
            self.floors,
            name.as_str().as_bytes(),
            &self.scope_id,
            sequence,
            envelope.epoch,
            floor::Strictness::AtFloor,
        )
        .await?;
        let read_body = self.unseal(&envelope, epoch_floor)?;
        Ok((
            Adopted {
                read_body,
                sequence,
                epoch: envelope.epoch,
            },
            envelope,
        ))
    }

    /// The record bytes an earlier [`Adopter::adopt`] assembled under `name`. A
    /// resolve that ends in a rejection drops the bytes it verified, so a caller
    /// that must re-read that same record reads them back here.
    pub(crate) fn assembled_record_bytes(&self, name: &IpnsName) -> Option<Vec<u8>> {
        self.assembled
            .borrow()
            .as_ref()
            .filter(|c| c.name == *name)
            .map(|c| c.record_bytes.clone())
    }

    /// Open an **interior** node's record under `epoch_seed`, the scope read
    /// seed of the epoch the record's own envelope is tagged with, so a caller
    /// carrying the lazy wave can re-seal the body forward at the scope's
    /// current epoch (CONTEXT.md "Lazy wave").
    ///
    /// Skips the scope's read-epoch floor, on the argument the sweep's own
    /// interior read is documented under
    /// ([`OwnerRotationNet::interior_node`](crate::net::OwnerRotationNet)).
    /// Two conditions of that argument are this path's to hold:
    /// [`assemble_envelope`](Self::assemble_envelope) refuses a record carrying
    /// a grant section, so nothing gated as a scope root arrives here, and this
    /// path moves no floor, like the other re-open paths.
    pub(crate) async fn open_interior_under(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
        epoch_seed: &[u8; 32],
    ) -> Result<(Adopted, Envelope), GateError> {
        let (sequence, envelope) = self.assembled_head(name, record_bytes).await?;
        // The replay bar alone, relaxed with the epoch stage: the lazy wave is
        // exactly what puts a good record below both.
        floor::check_sequence(
            self.floors,
            name.as_str().as_bytes(),
            sequence,
            floor::Strictness::AtOrAboveFloor,
        )
        .await?;
        // The AAD binds the envelope's own epoch, so a relabelled record does
        // not open under the seed the caller ratcheted to.
        let node_seed = kdf::node_seed(epoch_seed, &envelope.id);
        let read_key = kdf::read_key(node_seed.as_bytes());
        let read_body = open_read_body(&envelope, read_key.as_bytes())
            .map_err(|e| reject(GateStage::Unseal, e))?;
        Ok((
            Adopted {
                read_body,
                sequence,
                epoch: envelope.epoch,
            },
            envelope,
        ))
    }
}

/// Why a child-record resolve produced no adopted body.
pub(crate) enum ChildResolveError {
    /// No reachable source and no cached record — availability staleness.
    Unavailable(String),
    /// The record failed the gate — fail-closed.
    Gate(GateError),
}

/// One child record's cache-first gated resolve: the child gate on a strictly
/// newer record, then an at-floor re-open of the current or cached bytes so a
/// process starting over durable floors still renders.
///
/// Both read paths that descend below the scope root — a file's content read
/// and the focus-window folder refresh — walk this one function, so neither can
/// drift on which outcome is staleness and which is a fail-closed violation.
pub(crate) async fn resolve_child<T, S, H, F>(
    transport: &T,
    snapshot_cache: &S,
    adopter: &ChildAdopter<'_, H, F>,
    name: &IpnsName,
    mode: ResolveMode,
) -> Result<Adopted, ChildResolveError>
where
    T: RecordTransport,
    S: SnapshotCache,
    H: Http,
    F: FloorStore,
{
    let resolved = resolve(transport, snapshot_cache, adopter, name, mode)
        .await
        .map_err(|e| ChildResolveError::Unavailable(e.message().to_owned()))?;
    let record_bytes = match resolved.outcome {
        ResolveOutcome::Adopted(adopted) => return Ok(adopted),
        ResolveOutcome::TrustViolation(rejection) => {
            return Err(ChildResolveError::Gate(GateError::Rejected(rejection)));
        }
        ResolveOutcome::Current { record_bytes } => record_bytes,
        ResolveOutcome::NoUpdate => resolved.last_known_good.ok_or_else(|| {
            ChildResolveError::Unavailable(
                "no record source reachable and no cached record".to_owned(),
            )
        })?,
    };
    adopter
        .open_at_floor(name, &record_bytes)
        .await
        .map_err(ChildResolveError::Gate)
}

impl<H: Http, F: FloorStore> Adopter for ChildAdopter<'_, H, F> {
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<AdoptOutcome, GateError> {
        let (sequence, envelope) = self.assemble_envelope(name, record_bytes).await?;
        // Keep the assembled head whatever the floor says: both the equal-floor
        // re-open and the write path's carried-field read go back through
        // [`open_carried_at_floor`], which re-fetches the same head block
        // otherwise.
        *self.assembled.borrow_mut() = Some(AssembledChild {
            name: name.clone(),
            record_bytes: record_bytes.to_vec(),
            sequence,
            envelope: envelope.clone(),
        });
        let epoch_floor = floor::check(
            self.floors,
            name.as_str().as_bytes(),
            &self.scope_id,
            sequence,
            envelope.epoch,
            floor::Strictness::StrictlyNewer,
        )
        .await?;
        let read_body = self.unseal(&envelope, epoch_floor)?;
        // Sequence floor only, after the AAD-confirmed unseal (the floor law),
        // and deferred until the accepted record is durable.
        let pending = floor::PendingSequenceRaise::new(
            name.as_str().as_bytes(),
            Adopted {
                read_body,
                sequence,
                epoch: envelope.epoch,
            },
        );
        Ok(AdoptOutcome {
            pass: GatePass::DeferredSequence(pending),
            write_scope_seed: None,
            node_id: envelope.id,
            read_scope_seed: None,
        })
    }

    async fn commit_sequence_adoption(
        &self,
        pending: floor::PendingSequenceRaise,
    ) -> Result<Adopted, SeamError> {
        pending.commit(self.floors).await
    }

    /// A child record carries no owner blob, so no arm of this adopter ever
    /// recovers a scope seed.
    async fn probe_read_scope_seed(
        &self,
        _name: &IpnsName,
        _record_bytes: &[u8],
    ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::content::{compute_cid, encode_content_cid_str};
    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::seal::{
        PreservedFields, encode_envelope, seal_read_body, set_grant_section,
    };

    use crate::content::{DAG_ROOT_CODEC, GatewaySource};
    use crate::gate::{GateRejection, RejectionReason};
    use crate::net::resolve::resolve_gated;
    use crate::seams::EndpointId;
    use crate::testkit::block_on;
    use crate::testkit::fakes::{
        InMemoryFloorStore, InMemoryRecordStore, InMemorySnapshotCache, ScriptedHttp,
    };

    const SCOPE: [u8; 16] = [0x44; 16];
    const NODE: [u8; 16] = [0x55; 16];
    const WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
    const V: u64 = 1;
    const TTL_NANOS: u64 = 2_000_000_000;
    const EOL: &str = "2099-01-01T00:00:00Z";
    /// The epoch a cut moved the scope to, and the older one the interior node
    /// this session reads is still sealed at.
    const CURRENT_EPOCH: u64 = 4;
    const LAGGING_EPOCH: u64 = 1;
    /// The epoch a rotation on another device moved the scope to, which this
    /// device has not observed: above its own read-epoch floor.
    const UNOBSERVED_EPOCH: u64 = CURRENT_EPOCH + 1;
    const SEQUENCE: u64 = 3;

    /// One scope read seed per epoch — a cut leaves a distinct seed behind, so
    /// no test can pass by opening the wrong epoch under the right key.
    fn scope_seed(epoch: u64) -> [u8; 32] {
        let mut seed = [0xA0; 32];
        for (slot, byte) in seed.iter_mut().zip(epoch.to_be_bytes()) {
            *slot ^= byte;
        }
        seed
    }

    /// One interior node's published record, and the head block it anchors.
    struct Published {
        name: IpnsName,
        record_bytes: Vec<u8>,
        head: LocalHead,
    }

    struct Spec {
        node_id: [u8; 16],
        scope_id: [u8; 16],
        sequence: u64,
        /// The epoch the record is labelled with, and whose seed seals it.
        epoch: u64,
        /// Attach a grant section, the marker that makes a record a scope root.
        scope_root: bool,
    }

    impl Default for Spec {
        fn default() -> Self {
            Self {
                node_id: NODE,
                scope_id: SCOPE,
                sequence: SEQUENCE,
                epoch: LAGGING_EPOCH,
                scope_root: false,
            }
        }
    }

    /// A nonce derived from the whole spec. The scope UUID is no KDF input, so
    /// two specs differing only in scope seal under one read key: a fixed nonce
    /// would put two AAD/ciphertext pairs under one one-time Poly1305 key, the
    /// reuse blueprint/core.md forbids the corpus to model.
    fn fixture_nonce(spec: &Spec) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&spec.sequence.to_be_bytes());
        nonce[8] = u8::from(spec.scope_root);
        for (i, byte) in spec.node_id.iter().chain(&spec.scope_id).enumerate() {
            nonce[9 + i % 15] ^= byte.rotate_left(u32::try_from(i % 8).expect("under 8"));
        }
        nonce
    }

    /// Publish `spec` at its own epoch, under that epoch's scope read seed.
    fn publish(spec: Spec) -> Published {
        let nonce = fixture_nonce(&spec);
        let seed = scope_seed(spec.epoch);
        let node_seed = kdf::node_seed(&seed, &spec.node_id);
        let read_key = kdf::read_key(node_seed.as_bytes());
        let body = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let mut envelope = seal_read_body(
            read_key.as_bytes(),
            &nonce,
            V,
            spec.node_id,
            spec.scope_id,
            spec.epoch,
            &body,
        )
        .expect("the fixture body seals");
        if spec.scope_root {
            set_grant_section(&mut envelope, vec![0xEE; 8]);
        }
        let block = encode_envelope(&envelope).expect("the fixture envelope encodes");
        let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));

        let write_seed = kdf::write_seed(&WRITE_SCOPE_SEED, &spec.node_id);
        let signer = kdf::ipns_keypair(write_seed.as_bytes());
        let record_bytes = IpnsRecord::create_v2(
            &signer,
            format!("/ipfs/{cid}").as_bytes(),
            spec.sequence,
            TTL_NANOS,
            EOL,
        )
        .marshal();
        Published {
            name: IpnsName::from_public_key(&signer.verifying_key()),
            record_bytes,
            head: LocalHead { cid, block },
        }
    }

    fn gateway() -> Gateway {
        Gateway {
            accelerator: Some(GatewaySource::public("https://gw.test")),
            public_fallbacks: Vec::new(),
        }
    }

    /// The floors a cut leaves: the scope's read-epoch floor at the new epoch.
    fn floors_after_a_cut() -> InMemoryFloorStore {
        let floors = InMemoryFloorStore::default();
        block_on(floors.raise_epoch_floor(&SCOPE, CURRENT_EPOCH)).expect("the cut raises");
        floors
    }

    /// The session's adopter: it holds the seed of the epoch the cut moved to,
    /// which is exactly why the lagging record does not open under it. The head
    /// block is held locally, so no test needs a scripted fetch.
    fn adopter<'a>(
        gateway: &'a Gateway,
        http: &'a ScriptedHttp,
        floors: &'a InMemoryFloorStore,
        published: &Published,
        node_id: [u8; 16],
    ) -> ChildAdopter<'a, ScriptedHttp, InMemoryFloorStore> {
        seeded_adopter(gateway, http, floors, published, node_id, CURRENT_EPOCH)
    }

    /// The same adopter under the seed of `seed_epoch` — a read reaches a gate
    /// pass only under the seed of the epoch its record was sealed at.
    fn seeded_adopter<'a>(
        gateway: &'a Gateway,
        http: &'a ScriptedHttp,
        floors: &'a InMemoryFloorStore,
        published: &Published,
        node_id: [u8; 16],
        seed_epoch: u64,
    ) -> ChildAdopter<'a, ScriptedHttp, InMemoryFloorStore> {
        let adopter = ChildAdopter::new(
            gateway,
            http,
            floors,
            SCOPE,
            Zeroizing::new(scope_seed(seed_epoch)),
            node_id,
        );
        adopter.hold_local_head(published.head.clone());
        adopter
    }

    /// The fail-closed rejection `result` carries. `context` names what a read
    /// that succeeded would have admitted.
    fn refusal<T>(result: Result<T, GateError>, context: &str) -> GateRejection {
        match result {
            Ok(_) => panic!("{context}"),
            Err(GateError::Rejected(rejection)) => rejection,
            Err(GateError::Seam(e)) => panic!("expected a fail-closed rejection, got seam {e}"),
        }
    }

    /// The lazy wave's read: a cut raises the read-epoch floor at once, so an
    /// interior node the wave has not re-sealed is below that floor by
    /// construction. The adopt path refuses it, and this read opens it under the
    /// seed of the epoch it was actually sealed at.
    #[test]
    fn a_node_the_wave_has_not_reached_opens_under_the_seed_of_its_own_epoch() {
        let published = publish(Spec::default());
        let http = ScriptedHttp::default();
        let floors = floors_after_a_cut();
        let gw = gateway();
        let adopter = adopter(&gw, &http, &floors, &published, NODE);

        let refused = refusal(
            block_on(adopter.adopt(&published.name, &published.record_bytes)),
            "the adopt path must refuse a record below the scope's epoch floor",
        );
        assert_eq!(
            refused.reason,
            RejectionReason::EpochBelowFloor {
                floor: CURRENT_EPOCH,
                epoch: LAGGING_EPOCH,
            },
        );

        let (adopted, envelope) = block_on(adopter.open_interior_under(
            &published.name,
            &published.record_bytes,
            &scope_seed(LAGGING_EPOCH),
        ))
        .expect("the wave's read opens the node at its own epoch");
        assert_eq!(adopted.epoch, LAGGING_EPOCH, "opened where it was sealed");
        assert_eq!(adopted.sequence, SEQUENCE);
        assert_eq!(
            envelope.id, NODE,
            "and the caller can re-author these bytes"
        );
        assert!(matches!(adopted.read_body, ReadBody::Folder { .. }));
        assert_eq!(
            block_on(floors.sequence_floor(published.name.as_str().as_bytes()))
                .expect("the floor store answers"),
            None,
            "a re-open moves no floor: only a gate-passing adopt does",
        );
    }

    /// The relaxation is the epoch stage alone. A seed from any other epoch
    /// derives another read key, and the AAD binds the record's own epoch — so a
    /// caller that ratchets to the wrong epoch opens nothing.
    #[test]
    fn a_seed_from_another_epoch_opens_no_lagging_record() {
        let published = publish(Spec::default());
        let http = ScriptedHttp::default();
        let floors = floors_after_a_cut();
        let gw = gateway();
        let adopter = adopter(&gw, &http, &floors, &published, NODE);

        for wrong in [CURRENT_EPOCH, LAGGING_EPOCH + 1] {
            let refused = refusal(
                block_on(adopter.open_interior_under(
                    &published.name,
                    &published.record_bytes,
                    &scope_seed(wrong),
                )),
                "a seed the record was not sealed under must open nothing",
            );
            assert_eq!(refused.stage, GateStage::Unseal, "epoch {wrong}");
        }
    }

    /// Adopt `epoch`'s record under a seed it was never sealed under, over a
    /// device whose read-epoch floor stands at [`CURRENT_EPOCH`]. The unseal
    /// fails whatever the epoch, so the label is the only input the two arms
    /// below differ on. Answers the error, and asserts no arm moved a floor.
    fn failed_unseal_at(epoch: u64) -> GateError {
        let published = publish(Spec {
            epoch,
            ..Spec::default()
        });
        let gw = gateway();
        let http = ScriptedHttp::default();
        let floors = floors_after_a_cut();
        let adopter = seeded_adopter(&gw, &http, &floors, &published, NODE, LAGGING_EPOCH);

        let error = block_on(adopter.adopt(&published.name, &published.record_bytes))
            .err()
            .expect("a seed the record was not sealed under must open nothing");
        assert_eq!(
            sequence_floor(&floors, &published.name),
            0,
            "a failed unseal moves no replay bar",
        );
        assert_eq!(
            read_epoch_floor(&floors),
            Some(CURRENT_EPOCH),
            "and no revocation boundary",
        );
        error
    }

    /// A record above the floor needs a seed a rotation minted on another
    /// device, which this one recovers on its next root leg. Availability.
    #[test]
    fn a_failed_unseal_above_the_read_epoch_floor_is_availability() {
        let error = failed_unseal_at(UNOBSERVED_EPOCH);
        assert!(
            matches!(error, GateError::Seam(_)),
            "epoch {UNOBSERVED_EPOCH} over floor {CURRENT_EPOCH} earned [{error}]"
        );
    }

    /// At the floor this device holds the seed the record must open under, so a
    /// body that does not open is tampering.
    #[test]
    fn a_failed_unseal_at_the_read_epoch_floor_stays_a_trust_verdict() {
        let refused = refusal(
            Err::<(), _>(failed_unseal_at(CURRENT_EPOCH)),
            "unreachable: the input is already an error",
        );
        assert_eq!(refused.stage, GateStage::Unseal);
        assert_eq!(refused.check(), "seal-open-failed");
    }

    /// The accepted cost of reading an unauthenticated label (ADR 0017): a
    /// party that can sign at this name escapes the accusation by claiming any
    /// epoch above the floor. It buys an unrenderable row, which withholding
    /// the record already bought it, and no floor moves either way.
    #[test]
    fn a_far_future_epoch_label_also_escapes_the_accusation() {
        let error = failed_unseal_at(u64::MAX);
        assert!(matches!(error, GateError::Seam(_)), "earned [{error}]");
    }

    /// A scope root below its own read-epoch floor is never a wave target: it
    /// carries seeds, a grant blob and a commitment, so admitting one hands a
    /// revoked reader material the cut took away. The grant section marks it,
    /// and this read refuses on that marker alone.
    #[test]
    fn a_record_carrying_a_grant_section_is_refused_however_it_is_opened() {
        let published = publish(Spec {
            scope_root: true,
            ..Spec::default()
        });
        let http = ScriptedHttp::default();
        let floors = floors_after_a_cut();
        let gw = gateway();
        let adopter = adopter(&gw, &http, &floors, &published, NODE);

        let refused = refusal(
            block_on(adopter.open_interior_under(
                &published.name,
                &published.record_bytes,
                &scope_seed(LAGGING_EPOCH),
            )),
            "a scope root must be refused even under the seed of its own epoch",
        );
        assert_eq!(refused.stage, GateStage::GrantSection);
    }

    /// The per-name replay bar is untouched by the wave: a record below the
    /// durable sequence floor is a rollback whatever epoch it claims.
    #[test]
    fn a_rolled_back_record_stays_refused_below_the_sequence_floor() {
        let published = publish(Spec::default());
        let http = ScriptedHttp::default();
        let floors = floors_after_a_cut();
        let raised = SEQUENCE + 1;
        block_on(floors.raise_sequence_floor(published.name.as_str().as_bytes(), raised))
            .expect("the floor raises");
        let gw = gateway();
        let adopter = adopter(&gw, &http, &floors, &published, NODE);

        let refused = refusal(
            block_on(adopter.open_interior_under(
                &published.name,
                &published.record_bytes,
                &scope_seed(LAGGING_EPOCH),
            )),
            "a record below the sequence floor is a replay",
        );
        assert_eq!(
            refused.reason,
            RejectionReason::SequenceNotNewer {
                floor: raised,
                sequence: SEQUENCE,
            },
        );
    }

    /// The transplant bindings hold on this read too: the envelope must be the
    /// node the read was issued for, in the scope the caller already gated.
    #[test]
    fn a_transplanted_envelope_is_refused_however_it_is_opened() {
        let foreign_scope = publish(Spec {
            scope_id: [0x99; 16],
            ..Spec::default()
        });
        let other_node = publish(Spec {
            node_id: [0x66; 16],
            ..Spec::default()
        });
        let gw = gateway();
        let floors = floors_after_a_cut();

        for published in [&foreign_scope, &other_node] {
            let http = ScriptedHttp::default();
            let adopter = adopter(&gw, &http, &floors, published, NODE);
            let refused = refusal(
                block_on(adopter.open_interior_under(
                    &published.name,
                    &published.record_bytes,
                    &scope_seed(LAGGING_EPOCH),
                )),
                "a transplant must be refused",
            );
            assert_eq!(refused.stage, GateStage::Unseal);
        }
    }

    /// The child arm's durability rule: the sequence floor moves only with the
    /// snapshot write that makes those bytes last-known-good. A put that fails
    /// must leave the floor unspent, or this device holds a replay bar for a
    /// record it never cached — every later pass is then an equal-floor re-open
    /// that caches nothing, and an offline read finds no last-known-good.
    ///
    /// Mirrors the root arm's
    /// `a_failed_snapshot_write_leaves_the_sequence_floor_unspent_and_the_retry_caches`.
    #[test]
    fn a_failed_snapshot_write_leaves_the_sequence_floor_unspent_and_the_retry_caches() {
        let published = publish(Spec::default());
        let floors = InMemoryFloorStore::default();
        let endpoint = EndpointId::new("e0");
        let transport = InMemoryRecordStore::new(vec![endpoint.clone()]);
        transport.seed_record(
            &endpoint,
            published.name.as_str(),
            published.record_bytes.clone(),
        );
        let cache = InMemorySnapshotCache::default();
        cache.fail_puts();
        let gw = gateway();
        let http = ScriptedHttp::default();
        let cache_key = published.name.as_str().as_bytes().to_vec();
        let resolve = || {
            block_on(resolve_gated(
                &transport,
                &cache,
                &seeded_adopter(&gw, &http, &floors, &published, NODE, LAGGING_EPOCH),
                &published.name,
                ResolveMode::CacheFirst,
            ))
        };

        assert!(
            resolve().is_err(),
            "an unwritable snapshot cache aborts the resolve"
        );
        assert_eq!(
            sequence_floor(&floors, &published.name),
            0,
            "and leaves the floor where the pass found it"
        );
        assert_eq!(read_epoch_floor(&floors), None, "no child raises an epoch");

        cache.heal_puts();
        let resolved = resolve().expect("the retry resolves");
        assert!(
            matches!(resolved.resolved.outcome, ResolveOutcome::Adopted(_)),
            "the retry is a fresh adopt, not an equal-floor Current"
        );
        assert_eq!(
            cache.peek(&cache_key).as_deref(),
            Some(&published.record_bytes[..])
        );
        assert_eq!(sequence_floor(&floors, &published.name), SEQUENCE);
        assert_eq!(
            read_epoch_floor(&floors),
            None,
            "and the committed raise is the sequence floor alone",
        );
    }

    /// The durable per-name sequence floor, zero where none was raised.
    fn sequence_floor(floors: &InMemoryFloorStore, name: &IpnsName) -> u64 {
        block_on(floor::sequence_floor(floors, name.as_str().as_bytes()))
            .expect("the floor store answers")
            .unwrap_or(0)
    }

    /// The scope's read-epoch floor, which no child record may move.
    fn read_epoch_floor(floors: &InMemoryFloorStore) -> Option<u64> {
        block_on(floor::read_epoch_floor(floors, &SCOPE)).expect("the floor store answers")
    }
}
