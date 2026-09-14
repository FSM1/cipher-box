//! A scripted [`Adopter`] that fronts the adoption gate for the resolve
//! pipeline.

use std::sync::{Arc, Mutex};

use cipherbox_core::error::TrustViolation;
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::seal::{PreservedFields, ReadBody};
use zeroize::Zeroizing;

use crate::gate::{Adopted, GateError, GateRejection, GateStage, RejectionReason};
use crate::net::{AdoptOutcome, Adopter, GatePass};

/// The verdict a [`ScriptedAdopter`] returns for every record it is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdoptVerdict {
    /// The record passes the gate.
    Accept,
    /// A non-floor trust violation (fail-closed, pins last-known-good).
    TrustViolation,
    /// Our own current record re-fetched: `sequence == floor` (a no-update,
    /// never a violation).
    EqualSequence,
}

/// An [`Adopter`] that returns a scripted verdict and records every sequence it
/// is handed, so a suite can prove the pipeline gated the freshest fetched
/// record without re-deriving the adoption-gate crypto fixture.
#[derive(Clone)]
pub struct ScriptedAdopter {
    verdict: AdoptVerdict,
    seen: Arc<Mutex<Vec<u64>>>,
}

impl ScriptedAdopter {
    /// An adopter answering `verdict` to every record.
    #[must_use]
    pub fn new(verdict: AdoptVerdict) -> Self {
        Self {
            verdict,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Every sequence this adopter was handed, in call order.
    #[must_use]
    pub fn seen(&self) -> Vec<u64> {
        self.seen.lock().expect("lock").clone()
    }
}

impl Adopter for ScriptedAdopter {
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<AdoptOutcome, GateError> {
        let sequence = IpnsRecord::unmarshal(record_bytes)
            .expect("record parses")
            .verify(name)
            .expect("record verifies")
            .sequence;
        self.seen.lock().expect("lock").push(sequence);
        match self.verdict {
            AdoptVerdict::Accept => Ok(AdoptOutcome {
                pass: GatePass::Advanced(Adopted {
                    read_body: ReadBody::Folder {
                        created_at: 0,
                        modified_at: 0,
                        children: Vec::new(),
                        unknown: PreservedFields::new(),
                    },
                    sequence,
                    epoch: 1,
                }),
                write_scope_seed: None,
                node_id: [0u8; 16],
                read_scope_seed: None,
            }),
            AdoptVerdict::TrustViolation => Err(GateError::Rejected(GateRejection {
                stage: GateStage::RecordVerify,
                reason: RejectionReason::Trust(TrustViolation::IpnsSignatureInvalid.into()),
            })),
            AdoptVerdict::EqualSequence => Err(GateError::Rejected(GateRejection {
                stage: GateStage::Sequence,
                reason: RejectionReason::SequenceNotNewer {
                    floor: sequence,
                    sequence,
                },
            })),
        }
    }

    async fn probe_read_scope_seed(
        &self,
        _name: &IpnsName,
        _record_bytes: &[u8],
    ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError> {
        Ok(None)
    }
}
