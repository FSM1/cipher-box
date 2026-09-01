//! The child-record [`Adopter`]: verified content-plane reads one level below
//! the scope root (blueprint/engine.md "Content plane").
//!
//! A non-scope-root record carries no grant section, so the six-stage root gate
//! cannot apply. The child pipeline instead composes: record verify → head
//! fetch fail-closed on a CID mismatch → envelope binding (id + scope; a
//! transplant rejects) → the per-name sequence and scope read-epoch floors →
//! the AAD-bound read-body unseal under `read-key(node-seed(scopeReadSeed,
//! id))` — the same KDF edges the root walks, one level down. The sequence
//! floor advances only after a successful unseal (the floor law); the scope
//! epoch floor never moves from a child
//! ([`floor::advance_sequence_on_unseal`]). No new crypto: pure composition of
//! core verify/unseal plus the frozen KDF catalog.

use core::cell::RefCell;

use cipherbox_core::error::{Malformed, TrustViolation};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{Envelope, ReadBody, has_grant_section, open_read_body};
use zeroize::Zeroizing;

use super::adopter::{LocalHead, assemble_head_envelope, reject};
use super::resolve::{AdoptOutcome, Adopter, ResolveOutcome, resolve};
use crate::content::Gateway;
use crate::gate::{Adopted, GateError, GateStage, floor};
use crate::seams::{FloorStore, Http, RecordTransport, SnapshotCache};
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
    fn unseal(&self, envelope: &Envelope) -> Result<ReadBody, GateError> {
        let node_seed = kdf::node_seed(&self.scope_read_seed, &envelope.id);
        let read_key = kdf::read_key(node_seed.as_bytes());
        open_read_body(envelope, read_key.as_bytes()).map_err(|e| reject(GateStage::Unseal, e))
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
        floor::check(
            self.floors,
            name.as_str().as_bytes(),
            &self.scope_id,
            sequence,
            envelope.epoch,
            floor::Strictness::AtFloor,
        )
        .await?;
        let read_body = self.unseal(&envelope)?;
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
    /// This is the one child read that does **not** run the scope's read-epoch
    /// floor: a node the lazy wave has not reached is below that floor by
    /// construction. It is safe for an interior record where it would not be
    /// for a scope root, because an interior record carries no seed, no grant
    /// blob and no commitment — every key comes from the scope root the caller
    /// already gated, so nothing the record claims hands a revoked reader
    /// anything, and [`assemble_envelope`](Self::assemble_envelope) still
    /// refuses a record that carries a grant section. What the skipped stage
    /// carried is authorship: the body is authenticated only by the AEAD under
    /// that epoch's read key, which is the write plane's residual forgery
    /// window (CONTEXT.md "Forgery window"), closed by a write rotation and not
    /// by this read. The per-name replay bar still refuses a rolled-back
    /// record. Moves no floor, like the other re-open paths.
    pub(crate) async fn open_interior_under(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
        epoch_seed: &[u8; 32],
    ) -> Result<(Adopted, Envelope), GateError> {
        let (sequence, envelope) = self.assembled_head(name, record_bytes).await?;
        self.check_replay_bar(name, sequence).await?;
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

    /// The per-name sequence floor alone, at the bar a below-floor interior read
    /// takes ([`floor::Strictness::AtOrAboveFloor`]): the epoch stage is what
    /// the lazy wave relaxes, never this one.
    async fn check_replay_bar(&self, name: &IpnsName, sequence: u64) -> Result<(), GateError> {
        floor::check_sequence(
            self.floors,
            name.as_str().as_bytes(),
            sequence,
            floor::Strictness::AtOrAboveFloor,
        )
        .await
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
        floor::check(
            self.floors,
            name.as_str().as_bytes(),
            &self.scope_id,
            sequence,
            envelope.epoch,
            floor::Strictness::StrictlyNewer,
        )
        .await?;
        let read_body = self.unseal(&envelope)?;
        // Sequence floor only, after the AAD-confirmed unseal (the floor law).
        floor::advance_sequence_on_unseal(self.floors, name.as_str().as_bytes(), sequence)
            .await
            .map_err(GateError::Seam)?;
        Ok(AdoptOutcome {
            adopted: Adopted {
                read_body,
                sequence,
                epoch: envelope.epoch,
            },
            write_scope_seed: None,
            node_id: envelope.id,
            read_scope_seed: None,
        })
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
    use crate::testkit::block_on;
    use crate::testkit::fakes::{InMemoryFloorStore, ScriptedHttp};

    const SCOPE: [u8; 16] = [0x44; 16];
    const NODE: [u8; 16] = [0x55; 16];
    const WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
    const V: u64 = 1;
    const NONCE: [u8; 24] = [0x31; 24];
    const TTL_NANOS: u64 = 2_000_000_000;
    const EOL: &str = "2099-01-01T00:00:00Z";
    /// The epoch a cut moved the scope to, and the older one the interior node
    /// this session reads is still sealed at.
    const CURRENT_EPOCH: u64 = 4;
    const LAGGING_EPOCH: u64 = 1;
    const SEQUENCE: u64 = 3;

    /// One scope read seed per epoch — a cut leaves a distinct seed behind, so
    /// no test can pass by opening the wrong epoch under the right key.
    fn scope_seed(epoch: u64) -> [u8; 32] {
        [0xA0 ^ u8::try_from(epoch).expect("a small test epoch"); 32]
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
        /// Attach a grant section, the marker that makes a record a scope root.
        scope_root: bool,
    }

    impl Default for Spec {
        fn default() -> Self {
            Self {
                node_id: NODE,
                scope_id: SCOPE,
                sequence: SEQUENCE,
                scope_root: false,
            }
        }
    }

    /// Publish `spec` at [`LAGGING_EPOCH`], under that epoch's scope read seed.
    fn publish(spec: Spec) -> Published {
        let seed = scope_seed(LAGGING_EPOCH);
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
            &NONCE,
            V,
            spec.node_id,
            spec.scope_id,
            LAGGING_EPOCH,
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
        let adopter = ChildAdopter::new(
            gateway,
            http,
            floors,
            SCOPE,
            Zeroizing::new(scope_seed(CURRENT_EPOCH)),
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
}
