//! The child-record [`Adopter`]: verified content-plane reads one level below
//! the scope root (blueprint/engine.md "Content plane").
//!
//! A non-scope-root record carries no grant section, so the six-stage root gate
//! cannot apply. The child pipeline instead composes: record verify → head
//! fetch fail-closed on a CID mismatch → envelope binding (id + scope; a
//! transplant rejects) → the per-name sequence and scope read-epoch floors →
//! the AAD-bound read-body unseal under `read-key(node-seed(scopeReadSeed,
//! id))` — the same KDF edges the root walks, one level down. Floors advance
//! only after a successful unseal (the floor law). No new crypto: pure
//! composition of core verify/unseal plus the frozen KDF catalog.

use core::cell::RefCell;

use cipherbox_core::content::decode_content_cid_str;
use cipherbox_core::error::{Malformed, TrustViolation};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{Envelope, ReadBody, decode_envelope, open_read_body};
use zeroize::Zeroizing;

use super::adopter::{assembly_reject, map_read_error, reject};
use super::publish::head_cid_from_value;
use super::resolve::{AdoptOutcome, Adopter};
use crate::content::{ContentPlane, Gateway, read_block};
use crate::gate::{Adopted, GateError, GateRejection, GateStage, RejectionReason, floor};
use crate::seams::{FloorStore, Http};

/// The child-record [`Adopter`] for one non-root node of an owned scope.
/// Borrows the content seams from the live session; terminally owns a
/// zeroizing clone of the scope read seed (zeroized when the adopter drops).
pub struct ChildAdopter<'a, H, F> {
    /// Content read sources (accelerator + public fallbacks).
    gateway: &'a Gateway,
    /// The HTTP seam the head-block fetch rides.
    http: &'a H,
    /// The durable floor store the child floors read and advance.
    floors: &'a F,
    /// The scope the child must be sealed under (the AAD scope binding and the
    /// read-epoch floor key). A foreign scope is a transplant, fail-closed.
    scope_id: [u8; 16],
    /// The scope read seed the per-node read key derives from.
    scope_read_seed: Zeroizing<[u8; 32]>,
    /// The node id the resolved envelope must carry — the rendered-view child
    /// this read was issued for. A different id is a transplant, fail-closed.
    expected_node: [u8; 16],
    /// The envelope a floor-rejected [`Adopter::adopt`] assembled, kept so the
    /// equal-floor re-open ([`Self::open_at_floor`]) reuses it instead of
    /// re-fetching the same head block (mirrors
    /// [`RootAdopter`](super::RootAdopter)).
    assembled: RefCell<Option<AssembledChild>>,
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
        }
    }
}

impl<H: Http, F: FloorStore> ChildAdopter<'_, H, F> {
    /// Record verify, CID-verified head fetch, envelope decode, and the child
    /// bindings — every step fail-closed as a trust violation; a missing source
    /// stays availability ([`map_read_error`]).
    async fn assemble_envelope(
        &self,
        name: &IpnsName,
        record_bytes: &[u8],
    ) -> Result<(u64, Envelope), GateError> {
        let verified = IpnsRecord::unmarshal(record_bytes)
            .and_then(|record| record.verify(name))
            .map_err(assembly_reject)?;

        let cid_str = head_cid_from_value(&verified.value)
            .ok_or_else(|| assembly_reject(Malformed::ContentCidStrMalformed.into()))?;
        let expected_cid = decode_content_cid_str(&cid_str).map_err(assembly_reject)?;
        let block = read_block(
            self.gateway,
            self.http,
            &cid_str,
            &expected_cid,
            ContentPlane::Root,
        )
        .await
        .map_err(map_read_error)?;

        let envelope = decode_envelope(&block).map_err(assembly_reject)?;
        // A grant section marks a scope root; granted-subscope reads are a
        // later slice — fail closed, no partial support.
        if envelope
            .unknown
            .iter()
            .any(|(key, _)| key == "grantSection")
        {
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
        Ok((verified.sequence, envelope))
    }

    /// The child floor checks (root-gate stages 4/5). `strict` requires a
    /// strictly newer sequence (the adopt path); the at-floor path admits
    /// equality (our own current record) while a strictly lower sequence stays
    /// a fail-closed replay.
    async fn check_floors(
        &self,
        name: &IpnsName,
        sequence: u64,
        epoch: u64,
        strict: bool,
    ) -> Result<(), GateError> {
        let sequence_floor = floor::sequence_floor(self.floors, name.as_str().as_bytes())
            .await
            .map_err(GateError::Seam)?
            .unwrap_or(0);
        let replayed = if strict {
            sequence <= sequence_floor
        } else {
            sequence < sequence_floor
        };
        if replayed {
            return Err(GateError::Rejected(GateRejection {
                stage: GateStage::Sequence,
                reason: RejectionReason::SequenceNotNewer {
                    floor: sequence_floor,
                    sequence,
                },
            }));
        }
        let epoch_floor = floor::read_epoch_floor(self.floors, &self.scope_id)
            .await
            .map_err(GateError::Seam)?
            .unwrap_or(0);
        if epoch < epoch_floor {
            return Err(GateError::Rejected(GateRejection {
                stage: GateStage::Epoch,
                reason: RejectionReason::EpochBelowFloor {
                    floor: epoch_floor,
                    epoch,
                },
            }));
        }
        Ok(())
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
        // Reuse the envelope the floor-rejected adopt assembled for these same
        // bytes; assembling again re-fetches the head block.
        let cached = self
            .assembled
            .borrow_mut()
            .take()
            .filter(|c| c.name == *name && c.record_bytes == record_bytes);
        let (sequence, envelope) = match cached {
            Some(cached) => (cached.sequence, cached.envelope),
            None => self.assemble_envelope(name, record_bytes).await?,
        };
        self.check_floors(name, sequence, envelope.epoch, false)
            .await?;
        let read_body = self.unseal(&envelope)?;
        Ok(Adopted {
            read_body,
            sequence,
            epoch: envelope.epoch,
        })
    }
}

impl<H: Http, F: FloorStore> Adopter for ChildAdopter<'_, H, F> {
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<AdoptOutcome, GateError> {
        let (sequence, envelope) = self.assemble_envelope(name, record_bytes).await?;
        if let Err(err) = self
            .check_floors(name, sequence, envelope.epoch, true)
            .await
        {
            // Keep the assembled head for the equal-floor re-open path — it
            // re-fetches the same head block otherwise.
            *self.assembled.borrow_mut() = Some(AssembledChild {
                name: name.clone(),
                record_bytes: record_bytes.to_vec(),
                sequence,
                envelope,
            });
            return Err(err);
        }
        let read_body = self.unseal(&envelope)?;
        // Floors advance only after the AAD-confirmed unseal (the floor law).
        floor::advance_on_unseal(
            self.floors,
            &self.scope_id,
            name.as_str().as_bytes(),
            sequence,
            envelope.epoch,
        )
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
